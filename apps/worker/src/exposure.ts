/**
 * Website monitoring (ADR 0023, a module since ADR 0033): checking the proof of control, stage 1 (passive) and stage 2 (light active), and the schedule.
 *
 * - **Proof of control** (`runVerify`): a DNS TXT record or a file on the asset. Checked daily and again at the start of every stage 2
 *   run. A proof that is definitely gone (record absent or different, file absent or different) turns a verified asset into a lost
 *   one, stops stage 2 for it and tells owners and admins; an inconclusive check (a time-out, a resolver failure) changes nothing, but
 *   stage 2 needs a proof confirmed within the last 48 hours and fails closed otherwise.
 * - **Stage 1** (`runPassive`): DNS, TLS, one GET of `/`, optionally Certificate Transparency.
 * - **Stage 2** (`runActive`): a TCP connection to each port of a fixed list. Only for verified, acknowledged assets, at most once a
 *   day per asset, at most four attempts at a time with 200 ms between starts. Nothing is sent to a port.
 *
 * Nothing runs for an organisation that has not switched the module on (ADR 0033). Everything remote is hostile text (see
 * exposure-net.ts); every state change that matters is in the audit log.
 */
import { newId } from "@garnetops/core";
import {
  ACTIVE_LIMITS,
  type ActiveSnapshot,
  CT_LIMITS,
  challengeName,
  countBySeverity,
  type DnsSnapshot,
  daysToExpiry,
  EXPOSURE_PORTS,
  type ExposureErrorCode,
  effectiveVerification,
  evaluateActive,
  evaluatePassive,
  expiryLevel,
  expiryWarningDue,
  type FindingDraft,
  fileMatchesToken,
  isRiskyService,
  MAX_ADDRESSES_PER_ASSET,
  mayFollowRedirect,
  newOpenPorts,
  PASSIVE_INTERVAL_HOURS,
  type PassiveSnapshot,
  type PortResult,
  type PortSpec,
  RUNS_KEPT,
  registrableDomain,
  SCHEDULE_HOURS,
  SEVERITY_RANK,
  type TlsSnapshot,
  txtMatchesToken,
  unjudgedRules,
  VERIFY_FILE_PATH,
  VERIFY_FRESH_HOURS,
  VERIFY_INTERVAL_HOURS,
  type VerifiableAsset,
  type VerifyMethod,
} from "@garnetops/core/exposure";
import { checkAsset } from "@garnetops/core/exposure-assets";
import { schema } from "@garnetops/db";
import { and, asc, eq, inArray, isNull, lt, or, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { readDnssec } from "./dnssec.ts";
import { CtError, type CtFetch, crtShFetch } from "./exposure-ct.ts";
import {
  fetchHomepage,
  fetchPlain,
  fetchProofFile,
  type NetEnv,
  pacedRun,
  portResult,
  probePort,
  readDns,
  readPtr,
  readTxt,
  resolveAssetAddresses,
  tlsFull,
} from "./exposure-net.ts";
import { lookupFor, publicDnsOf, resolverFor } from "./public-dns.ts";
import { tellUsers } from "./user-notify.ts";

/** New names: the `exposure.*` queues of 0.0.3 are removed on every start (retired-queues.ts). */
export const EXPOSURE_VERIFY_QUEUE = "websites.verify";
export const EXPOSURE_RUN_QUEUE = "websites.run";
export const EXPOSURE_TICK_QUEUE = "websites.tick";
export const EXPOSURE_TICK_MINUTES = 15;
/** Same job options as runs queued by the API (apps/api/src/routes/exposure.ts). One try: the next tick is the retry. */
export const EXPOSURE_JOB = { retryLimit: 0, expireInSeconds: 25 * 60 };

type AssetRow = typeof schema.exposureAsset.$inferSelect;
type RunRow = typeof schema.exposureRun.$inferSelect;
type SettingsRow = typeof schema.exposureSettings.$inferSelect;

/** What a test can replace. Production passes nothing. */
export interface ExposureDeps {
  net?: NetEnv;
  now?: () => Date;
  ct?: CtFetch;
  /** Tests only: another port list (a fake server listens on an ephemeral port). */
  ports?: readonly PortSpec[];
  /** Tests only: no pause between two Certificate Transparency queries. */
  ctPauseMs?: number;
}

/** The network of one organisation's checks: the local resolver, and its public DNS next to it if it chose one. */
const netOf = async (deps: ExposureDeps, organizationId: string): Promise<NetEnv> =>
  deps.net ?? { dns: resolverFor(await publicDnsOf(organizationId)) };
const nowOf = (deps: ExposureDeps): Date => (deps.now ? deps.now() : new Date());
const HOUR = 3_600_000;
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The error a run stored, as a code; unknown errors are "unexpected" and the worker log has the error's name only. */
class RunError extends Error {
  readonly code: ExposureErrorCode;
  constructor(code: ExposureErrorCode) {
    super(code);
    this.name = "RunError";
    this.code = code;
  }
}

/* -------------------------------------------------------------------------- */
/* Assets                                                                      */
/* -------------------------------------------------------------------------- */

/** The organisations that switched the module on (ADR 0033), as a subquery. */
const enabledOrganizations = () =>
  db
    .select({ id: schema.exposureSettings.organizationId })
    .from(schema.exposureSettings)
    .where(eq(schema.exposureSettings.enabled, true));

/** Whether an organisation switched the module on. */
export async function moduleEnabled(organizationId: string): Promise<boolean> {
  const [row] = await db
    .select({ enabled: schema.exposureSettings.enabled })
    .from(schema.exposureSettings)
    .where(eq(schema.exposureSettings.organizationId, organizationId))
    .limit(1);
  return row?.enabled === true;
}

async function orgAssets(organizationId: string): Promise<AssetRow[]> {
  return db
    .select()
    .from(schema.exposureAsset)
    .where(eq(schema.exposureAsset.organizationId, organizationId));
}

const verifiable = (a: AssetRow): VerifiableAsset => ({
  id: a.id,
  kind: a.kind,
  value: a.value,
  verifyState: a.verifyState,
  includeSubdomains: a.includeSubdomains,
});

/** Hosts a redirect may lead to besides the asset's own site: the organisation's verified assets. */
function verifiedHosts(all: AssetRow[]): Set<string> {
  const list = all.map(verifiable);
  return new Set(all.filter((a) => effectiveVerification(verifiable(a), list).verified).map((a) => a.value));
}

/**
 * Why stage 2 may not run for this asset right now, or null if it may: switched on, acknowledged, verified (on its own or through a
 * parent domain that includes subdomains) and the proof confirmed within the last 48 hours.
 */
export function stage2Refusal(
  asset: AssetRow,
  all: AssetRow[],
  now: Date,
  options: { requireFresh?: boolean } = {},
): ExposureErrorCode | null {
  if (!asset.stage2Enabled) return "stageOff";
  if (!asset.stage2AcknowledgedAt || !asset.stage2AcknowledgedBy) return "notAcknowledged";
  const effective = effectiveVerification(verifiable(asset), all.map(verifiable));
  if (!effective.verified) return "notVerified";
  if (options.requireFresh === false) return null;
  const holder = effective.via === "parent" ? all.find((a) => a.id === effective.parentId) : asset;
  const confirmed = holder?.verifiedAt?.getTime() ?? 0;
  if (now.getTime() - confirmed > VERIFY_FRESH_HOURS * HOUR) return "notVerified";
  return null;
}

async function audit(
  organizationId: string,
  action: string,
  asset: Pick<AssetRow, "id">,
  data: Record<string, unknown>,
): Promise<void> {
  await db.insert(schema.auditLog).values({
    organizationId,
    action,
    targetType: "exposure_asset",
    targetId: asset.id,
    data,
  });
}

/* -------------------------------------------------------------------------- */
/* Proof of control                                                            */
/* -------------------------------------------------------------------------- */

export type ProofResult =
  | { ok: true; method: VerifyMethod }
  | { ok: false; code: ExposureErrorCode; definitive: boolean };

/** Which code to show when both methods failed: the one that tells an owner most about what to fix. */
const CODE_PRIORITY: ExposureErrorCode[] = [
  "dnsNoMatch",
  "fileNoMatch",
  "fileRedirected",
  "fileTooLarge",
  "dnsRecordMissing",
  "dnsFailed",
  "fileNotFound",
  "tlsFailed",
  "fileUnreachable",
  "timeout",
  "addressRefused",
  "unresolvable",
];

/**
 * Looks for the proof by DNS (domains) and by the file on the asset. `definitive` says the proof is demonstrably not there (the record
 * is absent or different, the file is gone or different) as far as the method the asset was verified with is concerned; a failure to
 * look is never definitive.
 */
export async function checkProof(
  env: NetEnv,
  asset: Pick<AssetRow, "kind" | "value" | "verifyToken" | "verifyMethod">,
): Promise<ProofResult> {
  const found: Partial<Record<VerifyMethod, { code: ExposureErrorCode; definitive: boolean }>> = {};
  if (asset.kind === "domain") {
    const txt = await readTxt(env, challengeName(asset.value));
    if (txt === undefined) found.dns = { code: "dnsFailed", definitive: false };
    else if (txtMatchesToken(txt, asset.verifyToken)) return { ok: true, method: "dns" };
    else found.dns = { code: txt.length === 0 ? "dnsRecordMissing" : "dnsNoMatch", definitive: true };
  }
  const resolved = await resolveAssetAddresses(env, asset.value);
  if (resolved.addresses.length === 0) {
    found.http = {
      code: resolved.nonPublic.length > 0 ? "addressRefused" : "unresolvable",
      definitive: false,
    };
  } else {
    const file = await fetchProofFile(
      env,
      { value: asset.value, isAddress: asset.kind === "ip" },
      resolved.addresses,
      VERIFY_FILE_PATH,
    );
    if (file.ok && fileMatchesToken(file.body, asset.verifyToken)) return { ok: true, method: "http" };
    const code: ExposureErrorCode = file.ok ? "fileNoMatch" : file.error;
    found.http = {
      code,
      definitive:
        code === "fileNoMatch" ||
        code === "fileNotFound" ||
        code === "fileRedirected" ||
        code === "fileTooLarge",
    };
  }
  const codes = Object.values(found).map((f) => f.code);
  const code = CODE_PRIORITY.find((c) => codes.includes(c)) ?? "unexpected";
  const preferred: VerifyMethod = asset.verifyMethod ?? (asset.kind === "domain" ? "dns" : "http");
  return { ok: false, code, definitive: found[preferred]?.definitive ?? false };
}

/**
 * Writes the result of a proof check: a proof found verifies the asset, a proof definitely gone turns a verified asset into a lost one
 * (stage 2 off, acknowledgement void, audit entry, owners and admins told), anything else only records why the check was not conclusive.
 * Returns whether the asset lost its verification.
 */
export async function applyProof(
  asset: AssetRow,
  result: ProofResult,
  now: Date,
): Promise<{ lost: boolean }> {
  const a = schema.exposureAsset;
  if (result.ok) {
    await db
      .update(a)
      .set({
        verifyState: "verified",
        verifyMethod: result.method,
        verifiedAt: now,
        verifyCheckedAt: now,
        verifyError: null,
        updatedAt: now,
      })
      .where(eq(a.id, asset.id));
    if (asset.verifyState !== "verified") {
      await audit(
        asset.organizationId,
        asset.verifyState === "lost" ? "exposure.verification_restored" : "exposure.verified",
        asset,
        { value: asset.value, method: result.method },
      );
    }
    return { lost: false };
  }
  if (result.definitive && asset.verifyState === "verified") {
    await db
      .update(a)
      .set({
        verifyState: "lost",
        verifyCheckedAt: now,
        verifyError: result.code,
        // Stage 2 stops at once and needs a new acknowledgement after a new proof.
        stage2Enabled: false,
        stage2AcknowledgedBy: null,
        stage2AcknowledgedAt: null,
        updatedAt: now,
      })
      .where(eq(a.id, asset.id));
    await audit(asset.organizationId, "exposure.verification_lost", asset, {
      value: asset.value,
      reason: result.code,
      stage2WasOn: asset.stage2Enabled,
    });
    await tellUsers({
      organizationId: asset.organizationId,
      titleKey: "exposureVerificationLost",
      params: { asset: asset.value },
      link: `/websites/${asset.id}`,
    });
    await reconcileCoverage(asset.organizationId, now);
    return { lost: true };
  }
  await db
    .update(a)
    .set({ verifyCheckedAt: now, verifyError: result.code, updatedAt: now })
    .where(eq(a.id, asset.id));
  return { lost: false };
}

/**
 * Switches stage 2 off for every asset that is no longer covered by a verification, for example the subdomains of a domain that lost
 * its proof. Each one is audited and announced like the asset that lost the proof itself.
 */
export async function reconcileCoverage(organizationId: string, now: Date): Promise<void> {
  const all = await orgAssets(organizationId);
  const list = all.map(verifiable);
  for (const asset of all) {
    if (!asset.stage2Enabled) continue;
    if (effectiveVerification(verifiable(asset), list).verified) continue;
    await db
      .update(schema.exposureAsset)
      .set({ stage2Enabled: false, stage2AcknowledgedBy: null, stage2AcknowledgedAt: null, updatedAt: now })
      .where(eq(schema.exposureAsset.id, asset.id));
    await audit(organizationId, "exposure.stage2_stopped", asset, {
      value: asset.value,
      reason: "notVerified",
    });
    await tellUsers({
      organizationId,
      titleKey: "exposureVerificationLost",
      params: { asset: asset.value },
      link: `/websites/${asset.id}`,
    });
  }
}

/** The verification job: checks the proof of one asset and records the result. */
export async function runVerify(assetId: string, deps: ExposureDeps = {}): Promise<void> {
  const [asset] = await db
    .select()
    .from(schema.exposureAsset)
    .where(eq(schema.exposureAsset.id, assetId))
    .limit(1);
  if (!asset || !(await moduleEnabled(asset.organizationId))) return;
  const result = await checkProof(await netOf(deps, asset.organizationId), asset);
  await applyProof(asset, result, nowOf(deps));
}

/* -------------------------------------------------------------------------- */
/* Runs                                                                        */
/* -------------------------------------------------------------------------- */

async function claimRun(runId: string, now: Date): Promise<RunRow | null> {
  const r = schema.exposureRun;
  const [claimed] = await db
    .update(r)
    .set({ state: "running", startedAt: now })
    .where(and(eq(r.id, runId), eq(r.state, "queued")))
    .returning();
  if (!claimed) return null;
  // Switched off after the run was queued: nothing is looked at.
  if (!(await moduleEnabled(claimed.organizationId))) {
    await db
      .update(r)
      .set({ state: "failed", error: "moduleOff", finishedAt: now })
      .where(eq(r.id, claimed.id));
    return null;
  }
  return claimed;
}

async function finishRun(
  run: RunRow,
  result: { error: ExposureErrorCode | null; counts?: Record<string, number>; openPorts?: number },
  now: Date,
): Promise<void> {
  const r = schema.exposureRun;
  await db
    .update(r)
    .set({
      state: result.error ? "failed" : "succeeded",
      error: result.error,
      findingCounts: result.counts ?? null,
      openPorts: result.openPorts ?? null,
      finishedAt: now,
    })
    .where(eq(r.id, run.id));
  // Keep the newest runs of this asset and stage.
  await db.execute(sql`
    delete from exposure_run where asset_id = ${run.assetId} and stage = ${run.stage} and id not in (
      select id from exposure_run where asset_id = ${run.assetId} and stage = ${run.stage}
      order by created_at desc, id desc limit ${RUNS_KEPT})`);
}

const errorCodeOf = (error: unknown): ExposureErrorCode =>
  error instanceof RunError ? error.code : "unexpected";

/* -------------------------------------------------------------------------- */
/* Findings                                                                    */
/* -------------------------------------------------------------------------- */

type FindingRow = typeof schema.exposureFinding.$inferSelect;

/**
 * Brings the findings of one asset and stage in line with what the run saw: new ones are opened, known ones refreshed, reopened ones
 * clear their "resolved" mark, and open ones that no longer fire are resolved. Rules the run could not judge are left as they are.
 */
async function syncFindings(
  asset: AssetRow,
  stage: "passive" | "active",
  drafts: FindingDraft[],
  skip: ReadonlySet<string>,
  now: Date,
): Promise<FindingRow[]> {
  const f = schema.exposureFinding;
  return db.transaction(async (tx) => {
    const existing = await tx
      .select()
      .from(f)
      .where(and(eq(f.assetId, asset.id), eq(f.stage, stage)));
    const byKey = new Map(existing.map((row) => [`${row.rule}|${row.subject}`, row]));
    const seen = new Set<string>();
    for (const draft of drafts) {
      const key = `${draft.rule}|${draft.subject}`;
      seen.add(key);
      const prior = byKey.get(key);
      if (prior) {
        await tx
          .update(f)
          .set({
            severity: draft.severity,
            severityRank: SEVERITY_RANK[draft.severity],
            params: draft.params,
            lastSeenAt: now,
            state: "open",
            resolvedAt: null,
            ...(prior.state === "resolved" ? { firstSeenAt: now, notifiedAt: null } : {}),
          })
          .where(eq(f.id, prior.id));
      } else {
        await tx.insert(f).values({
          id: newId("exf"),
          organizationId: asset.organizationId,
          assetId: asset.id,
          stage,
          rule: draft.rule,
          subject: draft.subject,
          severity: draft.severity,
          severityRank: SEVERITY_RANK[draft.severity],
          state: "open",
          params: draft.params,
          firstSeenAt: now,
          lastSeenAt: now,
        });
      }
    }
    for (const row of existing) {
      const key = `${row.rule}|${row.subject}`;
      if (row.state === "open" && !seen.has(key) && !skip.has(row.rule)) {
        await tx
          .update(f)
          .set({ state: "resolved", resolvedAt: now, notifiedAt: null })
          .where(eq(f.id, row.id));
      }
    }
    return tx
      .select()
      .from(f)
      .where(and(eq(f.assetId, asset.id), eq(f.stage, stage), eq(f.state, "open")));
  });
}

/* -------------------------------------------------------------------------- */
/* Discoveries                                                                 */
/* -------------------------------------------------------------------------- */

const MAX_DISCOVERIES_PER_ORG = 1000;

/** Remembers host names under the asset's domain as suggestions; known assets and the asset itself are not suggested. */
async function recordDiscoveries(
  asset: AssetRow,
  names: Iterable<string>,
  source: "ct" | "dns",
  now: Date,
): Promise<void> {
  const d = schema.exposureDiscovery;
  const assets = await orgAssets(asset.organizationId);
  const known = new Set(assets.map((a) => a.value));
  const [{ n } = { n: 0 }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(d)
    .where(eq(d.organizationId, asset.organizationId));
  let room = MAX_DISCOVERIES_PER_ORG - n;
  for (const name of names) {
    if (known.has(name) || name === asset.value) continue;
    if (!name.endsWith(`.${asset.value}`) && registrableDomain(name) !== registrableDomain(asset.value))
      continue;
    if (room <= 0) break;
    room -= 1;
    await db
      .insert(d)
      .values({
        id: newId("exd"),
        organizationId: asset.organizationId,
        assetId: asset.id,
        name,
        source,
        firstSeenAt: now,
        lastSeenAt: now,
      })
      .onConflictDoUpdate({ target: [d.organizationId, d.name], set: { lastSeenAt: now } });
  }
}

/* -------------------------------------------------------------------------- */
/* Certificate Transparency                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The opt-in lookup of subdomains in Certificate Transparency logs (ADR 0023): only when the organisation switched it on, only for a
 * domain that proved control itself, at most once a day per asset, within the organisation's daily budget and with a pause between
 * queries. A failure is recorded and never fails the run.
 */
async function lookUpCertificateTransparency(
  asset: AssetRow,
  settings: SettingsRow | undefined,
  deps: ExposureDeps,
  now: Date,
): Promise<void> {
  if (!settings?.ctEnabled || asset.kind !== "domain" || asset.verifyState !== "verified") return;
  if (asset.ctCheckedAt && now.getTime() - asset.ctCheckedAt.getTime() < CT_LIMITS.assetIntervalHours * HOUR)
    return;
  const s = schema.exposureSettings;
  const day = now.toISOString().slice(0, 10);
  const pause = deps.ctPauseMs ?? CT_LIMITS.minGapMs;
  const waitMs = settings.ctLastRequestAt ? settings.ctLastRequestAt.getTime() + pause - now.getTime() : 0;
  if (waitMs > 0 && pause > 0) await sleep(Math.min(waitMs, pause));
  const [claimed] = await db
    .update(s)
    .set({
      ctUsageDay: day,
      ctUsageCount: sql`case when ${s.ctUsageDay} = ${day} then ${s.ctUsageCount} + 1 else 1 end`,
      ctLastRequestAt: now,
    })
    .where(
      and(
        eq(s.organizationId, asset.organizationId),
        eq(s.ctEnabled, true),
        or(sql`${s.ctUsageDay} is distinct from ${day}`, lt(s.ctUsageCount, CT_LIMITS.dailyBudget)),
      ),
    )
    .returning({ id: s.organizationId });
  if (!claimed) return; // switched off meanwhile, or the day's budget is used up
  let error: string | null = null;
  try {
    const names = await (
      deps.ct ?? crtShFetch(undefined, lookupFor(await publicDnsOf(asset.organizationId)))
    )(asset.value);
    await recordDiscoveries(asset, names, "ct", now);
  } catch (e) {
    error = e instanceof CtError ? e.code : "unreachable";
  }
  await db.update(s).set({ ctLastError: error }).where(eq(s.organizationId, asset.organizationId));
  await db
    .update(schema.exposureAsset)
    .set({ ctCheckedAt: now })
    .where(eq(schema.exposureAsset.id, asset.id));
}

/* -------------------------------------------------------------------------- */
/* Stage 1                                                                     */
/* -------------------------------------------------------------------------- */

/** The earliest certificate expiry across the handshakes of a snapshot, in days; null if no certificate was seen. */
function soonestExpiry(tls: TlsSnapshot[], now: Date): number | null {
  const days = tls.flatMap((t) => (t.cert ? [daysToExpiry(t.cert.validTo, now)] : []));
  return days.length > 0 ? Math.min(...days) : null;
}

/** Stage 1 of one run: DNS, TLS, the home page, discoveries; findings and notifications. */
export async function runPassive(runId: string, deps: ExposureDeps = {}): Promise<void> {
  const now = nowOf(deps);
  const run = await claimRun(runId, now);
  if (!run) return;
  try {
    const [asset] = await db
      .select()
      .from(schema.exposureAsset)
      .where(eq(schema.exposureAsset.id, run.assetId))
      .limit(1);
    if (!asset) throw new RunError("assetRemoved");
    const env = await netOf(deps, asset.organizationId);
    const isAddress = asset.kind === "ip";
    const all = await orgAssets(asset.organizationId);
    const [settings] = await db
      .select()
      .from(schema.exposureSettings)
      .where(eq(schema.exposureSettings.organizationId, asset.organizationId))
      .limit(1);

    const resolved = await resolveAssetAddresses(env, asset.value);
    const dns: DnsSnapshot | null = isAddress ? null : await readDns(env, asset.value, resolved);
    if (dns) dns.dnssec = await readDnssec(env, asset.value, now);
    const addresses = resolved.addresses.slice(0, MAX_ADDRESSES_PER_ASSET);

    const tls: TlsSnapshot[] = [];
    let legacyDone = false;
    for (const address of addresses) {
      const probe = await tlsFull(env, {
        address,
        port: env.httpsPort ?? 443,
        servername: isAddress ? null : asset.value,
        withLegacy: !legacyDone,
      });
      if (probe.ok) legacyDone = true;
      tls.push({ ...probe, port: 443 });
    }
    const httpsOpen = tls.some((t) => t.ok || t.error === "handshake");
    const target = { name: asset.value, isAddress };
    const http =
      httpsOpen && addresses.length > 0
        ? await fetchHomepage(env, target, addresses, verifiedHosts(all), mayFollowRedirect)
        : null;
    const plain = addresses.length > 0 ? await fetchPlain(env, target, addresses) : null;

    const ptr = isAddress && addresses.length > 0 ? await readPtr(env, addresses) : [];

    const snapshot: PassiveSnapshot = {
      version: 1,
      takenAt: now.toISOString(),
      kind: asset.kind,
      name: asset.value,
      addresses,
      nonPublic: resolved.nonPublic,
      dns,
      ptr,
      tls,
      http,
      plain,
      resolves: resolved.a.length + resolved.aaaa.length > 0 || (isAddress && addresses.length > 0),
      httpsOpen,
    };

    if (dns) {
      const names = [...dns.cname, ...dns.mx.map((m) => m.exchange), ...dns.ns]
        .map((n) => n.toLowerCase().replace(/\.$/, ""))
        .filter(
          (n) => n.endsWith(`.${asset.value}`) || registrableDomain(n) === registrableDomain(asset.value),
        );
      const valid = names.flatMap((n) => {
        const checked = checkAsset(n);
        return checked.ok && checked.kind === "domain" ? [checked.value] : [];
      });
      await recordDiscoveries(asset, new Set(valid), "dns", now);
    }
    await lookUpCertificateTransparency(asset, settings, deps, now);

    const drafts = evaluatePassive(snapshot, now);
    await syncFindings(asset, "passive", drafts, new Set(unjudgedRules(snapshot)), now);
    const counts = countBySeverity(drafts);

    // Certificate expiry warnings: once per step (30, 14, 7 days, expired), again after a renewal.
    const days = soonestExpiry(tls, now);
    let notifiedLevel = asset.certNotifiedLevel;
    if (days !== null) {
      const level = expiryLevel(days);
      if (expiryWarningDue(level, asset.certNotifiedLevel)) {
        await tellUsers({
          organizationId: asset.organizationId,
          titleKey: level === 0 ? "exposureCertificateExpired" : "exposureCertificateExpiring",
          params: { asset: asset.value, days: Math.max(days, 0) },
          link: `/websites/${asset.id}`,
        });
      }
      notifiedLevel = level;
    }

    await db
      .update(schema.exposureAsset)
      .set({
        passive: snapshot,
        lastPassiveAt: now,
        passiveError: null,
        certNotifiedLevel: notifiedLevel,
        updatedAt: now,
      })
      .where(eq(schema.exposureAsset.id, asset.id));
    await finishRun(run, { error: null, counts }, nowOf(deps));
  } catch (error) {
    const code = errorCodeOf(error);
    if (code === "unexpected") console.error("exposure passive:", (error as Error)?.name ?? "error");
    await db
      .update(schema.exposureAsset)
      .set({ passiveError: code, updatedAt: now })
      .where(eq(schema.exposureAsset.id, run.assetId))
      .catch(() => {});
    await finishRun(run, { error: code }, nowOf(deps));
  }
}

/* -------------------------------------------------------------------------- */
/* Stage 2                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Stage 2 of one run. It refuses unless the asset is switched on, acknowledged, verified with a proof confirmed in the last 48 hours
 * and not scanned in the last 24 hours; it checks the proof again before the first connection and between ports, and stops at once if
 * the proof or the switch is gone. It connects, and reads what a service sends first; it never writes to a port.
 */
export async function runActive(runId: string, deps: ExposureDeps = {}): Promise<void> {
  const now = nowOf(deps);
  const run = await claimRun(runId, now);
  if (!run) return;
  const a = schema.exposureAsset;
  try {
    const [asset] = await db.select().from(a).where(eq(a.id, run.assetId)).limit(1);
    if (!asset) throw new RunError("assetRemoved");
    const env = await netOf(deps, asset.organizationId);
    let all = await orgAssets(asset.organizationId);

    // Switched on, acknowledged and covered by a verification; the proof itself is looked at again below.
    const refusalBefore = stage2Refusal(asset, all, now, { requireFresh: false });
    if (refusalBefore) throw new RunError(refusalBefore);
    if (
      asset.lastActiveAt &&
      now.getTime() - asset.lastActiveAt.getTime() < ACTIVE_LIMITS.minIntervalHours * HOUR
    ) {
      throw new RunError("tooSoon");
    }
    // The proof must be there now, not only at the last daily check. An inconclusive look fails closed.
    const effective = effectiveVerification(verifiable(asset), all.map(verifiable));
    const holder =
      effective.via === "parent" ? (all.find((x) => x.id === effective.parentId) ?? asset) : asset;
    const proof = await checkProof(env, holder);
    await applyProof(holder, proof, now);
    if (!proof.ok) throw new RunError(proof.definitive ? "notVerified" : proof.code);
    all = await orgAssets(asset.organizationId);
    const [fresh] = all.filter((x) => x.id === asset.id);
    const refusal = fresh ? stage2Refusal(fresh, all, now) : "assetRemoved";
    if (refusal) throw new RunError(refusal);

    // The once-a-day limit counts from here, so a run that crashes still uses up its day.
    await db.update(a).set({ lastActiveAt: now, updatedAt: now }).where(eq(a.id, asset.id));

    const resolved = await resolveAssetAddresses(env, asset.value);
    if (resolved.addresses.length === 0) {
      throw new RunError(resolved.nonPublic.length > 0 ? "addressRefused" : "unresolvable");
    }
    const list = deps.ports ?? EXPOSURE_PORTS;
    const open: PortResult[] = [];
    let closed = 0;
    let noAnswer = 0;
    let checked = 0;
    let stopped = false;
    const servername = asset.kind === "domain" ? asset.value : null;
    let stopReason: ExposureErrorCode | null = null;
    const stillAllowed = async () => {
      const rows = await orgAssets(asset.organizationId);
      const current = rows.find((x) => x.id === asset.id);
      stopReason = current ? stage2Refusal(current, rows, nowOf(deps)) : "assetRemoved";
      return stopReason === null;
    };
    for (const address of resolved.addresses) {
      const outcome = await pacedRun(
        list,
        async (spec) => {
          env.onAttempt?.(spec.port, address);
          const probe = await probePort(env, address, spec, servername);
          checked += 1;
          if (probe.state === "open") open.push(portResult(address, spec, probe));
          else if (probe.state === "closed") closed += 1;
          else noAnswer += 1;
        },
        {
          concurrency: ACTIVE_LIMITS.concurrency,
          gapMs: ACTIVE_LIMITS.gapMs,
          stop: async () => !(await stillAllowed()),
        },
      );
      if (outcome.stopped) {
        stopped = true;
        break;
      }
    }
    if (stopped) throw new RunError(stopReason ?? "notVerified");

    const snapshot: ActiveSnapshot = {
      version: 1,
      takenAt: now.toISOString(),
      addresses: resolved.addresses,
      open,
      checked,
      closed,
      noAnswer,
      stopped: null,
    };
    await recordActiveResult(fresh as AssetRow, run, snapshot, now);
    await finishRun(
      run,
      { error: null, counts: countBySeverity(evaluateActive(snapshot, now)), openPorts: open.length },
      nowOf(deps),
    );
  } catch (error) {
    const code = errorCodeOf(error);
    if (code === "unexpected") console.error("exposure active:", (error as Error)?.name ?? "error");
    await db
      .update(a)
      .set({ activeError: code, updatedAt: now })
      .where(eq(a.id, run.assetId))
      .catch(() => {});
    await finishRun(run, { error: code }, nowOf(deps));
  }
}

/** Stores the ports and findings of a finished stage 2 run and tells people about new ports and risky services. */
async function recordActiveResult(
  asset: AssetRow,
  run: RunRow,
  snapshot: ActiveSnapshot,
  now: Date,
): Promise<void> {
  const p = schema.exposurePort;
  const previous = await db.select().from(p).where(eq(p.assetId, asset.id));
  const [earlier] = await db
    .select({ id: schema.exposureRun.id })
    .from(schema.exposureRun)
    .where(
      and(
        eq(schema.exposureRun.assetId, asset.id),
        eq(schema.exposureRun.stage, "active"),
        eq(schema.exposureRun.state, "succeeded"),
        sql`${schema.exposureRun.id} <> ${run.id}`,
      ),
    )
    .limit(1);
  const fresh = newOpenPorts(snapshot.open, previous);
  const byKey = new Map(previous.map((row) => [`${row.address}|${row.port}`, row]));

  await db.transaction(async (tx) => {
    await tx.delete(p).where(eq(p.assetId, asset.id));
    if (snapshot.open.length > 0) {
      await tx.insert(p).values(
        snapshot.open.map((result) => ({
          assetId: asset.id,
          address: result.address,
          port: result.port,
          organizationId: asset.organizationId,
          service: result.service,
          banner: result.banner,
          tls: result.tls,
          firstSeenAt: byKey.get(`${result.address}|${result.port}`)?.firstSeenAt ?? now,
          lastSeenAt: now,
        })),
      );
    }
    await tx
      .update(schema.exposureAsset)
      .set({ active: snapshot, activeError: null, updatedAt: now })
      .where(eq(schema.exposureAsset.id, asset.id));
  });

  const drafts = evaluateActive(snapshot, now);
  const rows = await syncFindings(asset, "active", drafts, new Set(), now);

  // A port that is new since the last successful run. The first run is the baseline and says nothing.
  if (earlier && fresh.length > 0) {
    const ports = [...new Set(fresh.map((x) => x.port))].sort((x, y) => x - y);
    await tellUsers({
      organizationId: asset.organizationId,
      titleKey: "exposureNewOpenPort",
      params: { asset: asset.value, count: ports.length, ports: ports.slice(0, 5).join(", ") },
      link: `/websites/${asset.id}`,
    });
  }
  // A risky service is announced once for as long as it stays open.
  const risky = rows.filter(
    (row) => row.rule === "portExposed" && row.notifiedAt === null && isRiskyService(row.severity),
  );
  if (risky.length > 0) {
    const first = risky[0] as FindingRow;
    await tellUsers({
      organizationId: asset.organizationId,
      titleKey: "exposureRiskyService",
      params: {
        asset: asset.value,
        count: risky.length,
        port: Number(first.subject),
        service: String(first.params.service ?? ""),
      },
      link: `/websites/${asset.id}`,
    });
    await db
      .update(schema.exposureFinding)
      .set({ notifiedAt: now })
      .where(
        inArray(
          schema.exposureFinding.id,
          risky.map((row) => row.id),
        ),
      );
  }
}

/* -------------------------------------------------------------------------- */
/* Schedule                                                                    */
/* -------------------------------------------------------------------------- */

const TICK_LIMITS = { verify: 50, passive: 25, active: 10 };

/** Inserts a queued run unless one is queued or running for this asset and stage (a unique index decides). */
async function queueRun(
  boss: PgBoss,
  asset: Pick<AssetRow, "id" | "organizationId">,
  stage: "passive" | "active",
  now: Date,
): Promise<boolean> {
  const id = newId("exr");
  const inserted = await db
    .insert(schema.exposureRun)
    .values({
      id,
      organizationId: asset.organizationId,
      assetId: asset.id,
      stage,
      state: "queued",
      trigger: "schedule",
      createdAt: now,
    })
    .onConflictDoNothing()
    .returning({ id: schema.exposureRun.id });
  if (inserted.length === 0) return false;
  await boss.send(
    EXPOSURE_RUN_QUEUE,
    { runId: id },
    { ...EXPOSURE_JOB, singletonKey: `${asset.id}:${stage}` },
  );
  return true;
}

/**
 * One tick of the website monitoring schedule (every 15 minutes), for organisations that switched the module on: checks proofs that are a day old, queues stage 1 for assets last looked at more
 * than a day ago, queues stage 2 for assets whose schedule is due and that may run, sends again runs that were lost between queueing and
 * sending, and fails runs that have been running for far too long.
 */
export async function exposureTick(boss: PgBoss, deps: ExposureDeps = {}): Promise<void> {
  const now = nowOf(deps);
  const a = schema.exposureAsset;
  const r = schema.exposureRun;

  const proofDue = await db
    .select({ id: a.id })
    .from(a)
    .where(
      and(
        inArray(a.organizationId, enabledOrganizations()),
        or(
          isNull(a.verifyCheckedAt),
          lt(a.verifyCheckedAt, new Date(now.getTime() - VERIFY_INTERVAL_HOURS * HOUR)),
        ),
      ),
    )
    .orderBy(asc(a.verifyCheckedAt))
    .limit(TICK_LIMITS.verify);
  for (const asset of proofDue) {
    await boss.send(
      EXPOSURE_VERIFY_QUEUE,
      { assetId: asset.id },
      { retryLimit: 0, expireInSeconds: 600, singletonKey: asset.id },
    );
  }

  const passiveDue = await db
    .select({ id: a.id, organizationId: a.organizationId })
    .from(a)
    .where(
      and(
        eq(a.passiveEnabled, true),
        inArray(a.organizationId, enabledOrganizations()),
        or(
          isNull(a.lastPassiveAt),
          lt(a.lastPassiveAt, new Date(now.getTime() - PASSIVE_INTERVAL_HOURS * HOUR)),
        ),
      ),
    )
    .orderBy(sql`${a.lastPassiveAt} asc nulls first`)
    .limit(TICK_LIMITS.passive);
  for (const asset of passiveDue) await queueRun(boss, asset, "passive", now);

  const candidates = await db
    .select()
    .from(a)
    .where(and(eq(a.stage2Enabled, true), inArray(a.organizationId, enabledOrganizations())));
  const byOrg = new Map<string, AssetRow[]>();
  let queued = 0;
  for (const asset of candidates) {
    if (queued >= TICK_LIMITS.active) break;
    const hours = SCHEDULE_HOURS[asset.stage2Schedule];
    const due = !asset.lastActiveAt || now.getTime() - asset.lastActiveAt.getTime() >= hours * HOUR;
    if (!due) continue;
    const all = byOrg.get(asset.organizationId) ?? (await orgAssets(asset.organizationId));
    byOrg.set(asset.organizationId, all);
    if (stage2Refusal(asset, all, now)) continue;
    if (await queueRun(boss, asset, "active", now)) queued += 1;
  }

  const stranded = await db
    .select({ id: r.id, assetId: r.assetId, stage: r.stage })
    .from(r)
    .where(and(eq(r.state, "queued"), lt(r.createdAt, new Date(now.getTime() - 2 * 60_000))))
    .limit(100);
  for (const run of stranded) {
    await boss.send(
      EXPOSURE_RUN_QUEUE,
      { runId: run.id },
      { ...EXPOSURE_JOB, singletonKey: `${run.assetId}:${run.stage}` },
    );
  }
  await db
    .update(r)
    .set({ state: "failed", error: "timeout", finishedAt: now })
    .where(and(eq(r.state, "running"), lt(r.startedAt, new Date(now.getTime() - 30 * 60_000))));
}

/** Registers the tick: every 15 minutes, cron evaluated in UTC. */
export async function startExposureScheduler(boss: PgBoss, deps: ExposureDeps = {}): Promise<void> {
  await boss.createQueue(EXPOSURE_TICK_QUEUE);
  await boss.schedule(EXPOSURE_TICK_QUEUE, `*/${EXPOSURE_TICK_MINUTES} * * * *`, null, { tz: "UTC" });
  await boss.work(EXPOSURE_TICK_QUEUE, { batchSize: 1 }, async () => {
    await exposureTick(boss, deps);
  });
}

/** Runs the job of a queued run, whichever stage it is. */
export async function runExposure(runId: string, deps: ExposureDeps = {}): Promise<void> {
  const [run] = await db
    .select({ stage: schema.exposureRun.stage })
    .from(schema.exposureRun)
    .where(eq(schema.exposureRun.id, runId))
    .limit(1);
  if (!run) return;
  if (run.stage === "passive") await runPassive(runId, deps);
  else await runActive(runId, deps);
}
