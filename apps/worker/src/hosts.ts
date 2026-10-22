/**
 * Servers (ADR 0011): the organisation's SSH access key, the host key scan and the inventory.
 *
 * An inventory connects with the access key to a server whose host key an admin has
 * confirmed, runs the fixed `inventory` command, parses the report defensively, stores the
 * packages and matches them against the local vulnerability database with grype, the same
 * database and matcher repositories use. Whatever the server prints is data: it is parsed,
 * bounded and stored, never executed, never interpolated into a command and never echoed
 * into an error message.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { HostError, type HostErrorCode, hostErrorMessage, newId } from "@garnetops/core";
import {
  buildHostSbom,
  INVENTORY_TIMEOUT_SECONDS,
  InventoryParseError,
  type InventoryReport,
  knownHostsLine,
  MAX_REPORT_BYTES,
  parseInventoryReport,
} from "@garnetops/core/hosts";
import { fingerprint, generateDeployKey } from "@garnetops/core/ssh";
import { open, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, inArray, lt, or, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { env, vaultPrivateKey } from "./env.ts";
import { addAdvisoryDates, type ParsedReport, parseReport, scanTarget } from "./grype.ts";
import {
  classifySshFailure,
  hostSshArgs,
  resolveTarget,
  runCapped,
  type Ssh,
  scanHostKeys,
  sshEnv,
  sshTools,
} from "./host-ssh.ts";
import { tellUsers } from "./user-notify.ts";
import { upsertVulnerabilities } from "./vulnerability-store.ts";

export const HOST_KEYSCAN_QUEUE = "host.keyscan";
export const HOST_INVENTORY_QUEUE = "host.inventory";
export const HOST_ACCESS_KEY_QUEUE = "host.access-key";

/** Same job options as inventories queued by the API (apps/api/src/routes/hosts.ts). */
export const HOST_INVENTORY_JOB = { retryLimit: 1, expireInSeconds: 20 * 60 };

type HostRow = typeof schema.host.$inferSelect;

/** What a test can replace: resolving the address (so a local test server can be used) and the ssh tools. */
export interface HostDeps {
  resolve?: (address: string) => Promise<string>;
  tools?: Ssh;
  /** Smaller limits than the real ones, to test what happens when they are hit. */
  timeoutMs?: number;
  maxBytes?: number;
}

/* -------------------------------------------------------------------------- */
/* Access key                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Creates the organisation's SSH access key if it has none. The private half is generated
 * here, sealed straight away and never stored or logged in clear; the API only ever gets the
 * public half. Safe to call concurrently and repeatedly.
 */
export async function ensureHostAccessKey(organizationId: string): Promise<{ created: boolean }> {
  return db.transaction(async (tx) => {
    // One creator per organisation at a time; the unique index is the second line of defence.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`host-access-key:${organizationId}`}))`);
    const [existing] = await tx
      .select({ id: schema.hostAccessKey.id })
      .from(schema.hostAccessKey)
      .where(
        and(
          eq(schema.hostAccessKey.organizationId, organizationId),
          eq(schema.hostAccessKey.state, "active"),
        ),
      )
      .limit(1);
    if (existing) return { created: false };

    const key = generateDeployKey("garnetops-host-access");
    const secretId = newId("sec");
    const keyId = newId("hak");
    await tx.insert(schema.secret).values({
      id: secretId,
      organizationId,
      purpose: "host-ssh-key",
      sealed: seal(
        key.privateKey,
        { organizationId, recordId: secretId, purpose: "host-ssh-key" },
        vaultPublicKeyOf(vaultPrivateKey),
      ),
      vaultKeyId: vaultPrivateKey.id,
    });
    const keyFingerprint = fingerprint(key.publicKey.split(" ")[1] as string);
    await tx.insert(schema.hostAccessKey).values({
      id: keyId,
      organizationId,
      publicKey: key.publicKey,
      fingerprint: keyFingerprint,
      secretId,
    });
    await tx.insert(schema.auditLog).values({
      organizationId,
      action: "host.access_key_created",
      targetType: "host_access_key",
      targetId: keyId,
      data: { fingerprint: keyFingerprint },
    });
    return { created: true };
  });
}

/* -------------------------------------------------------------------------- */
/* Host key scan                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Reads the server's SSH host keys and stores the best one as the candidate an admin
 * confirms. A server that already has a confirmed key and still presents it is left alone;
 * one that presents none of its pinned keys is marked "changed" (and audited) and stays
 * blocked until an admin confirms the new fingerprint.
 */
export async function scanHost(hostId: string, deps: HostDeps = {}): Promise<void> {
  const [host] = await db.select().from(schema.host).where(eq(schema.host.id, hostId)).limit(1);
  if (!host) return;
  const home = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "keyscan-"));
  try {
    const tools = deps.tools ?? (await sshTools());
    const target = await (deps.resolve ?? resolveTarget)(host.address);
    const { keys } = await scanHostKeys(tools, target, host.port, home);
    await recordScan(host, keys);
  } catch (error) {
    const code = errorCode(error, "keyscanFailed");
    await db
      .update(schema.host)
      .set({ lastError: hostErrorMessage(code), updatedAt: new Date() })
      .where(eq(schema.host.id, hostId));
    if (!(error instanceof HostError)) console.error(`host ${hostId} key scan:`, (error as Error).message);
  } finally {
    await rm(home, { recursive: true, force: true }).catch(() => {});
  }
}

async function recordScan(
  host: HostRow,
  keys: { type: string; key: string; fingerprint: string }[],
): Promise<void> {
  const best = keys[0];
  if (!best) return;
  const now = new Date();
  if (host.hostKeyStatus === "confirmed" || host.hostKeyStatus === "changed") {
    const pinned = keys.find((k) => k.type === host.hostKeyType && k.key === host.hostKey);
    if (pinned) {
      // Still the pinned key: not a change. An earlier alarm (a one-off mismatch) clears itself.
      if (host.hostKeyStatus === "changed" || host.candidateKey) {
        await db
          .update(schema.host)
          .set({
            hostKeyStatus: "confirmed",
            candidateKeyType: null,
            candidateKey: null,
            candidateKeyFingerprint: null,
            candidateKeySeenAt: null,
            lastError: null,
            updatedAt: now,
          })
          .where(eq(schema.host.id, host.id));
      }
      return;
    }
    let news = false;
    await db.transaction(async (tx) => {
      await tx
        .update(schema.host)
        .set({
          hostKeyStatus: "changed",
          candidateKeyType: best.type,
          candidateKey: best.key,
          candidateKeyFingerprint: best.fingerprint,
          candidateKeySeenAt: now,
          lastError: hostErrorMessage("hostKeyChanged"),
          updatedAt: now,
        })
        .where(eq(schema.host.id, host.id));
      if (host.hostKeyStatus !== "changed" || host.candidateKeyFingerprint !== best.fingerprint) {
        news = true;
        await tx.insert(schema.auditLog).values({
          organizationId: host.organizationId,
          action: "host.key_changed",
          targetType: "host",
          targetId: host.id,
          data: { pinned: host.hostKeyFingerprint, seen: best.fingerprint },
        });
      }
    });
    // Owners and admins hear of it once per change, like the audit entry (ADR 0019).
    if (news) {
      await tellUsers({
        organizationId: host.organizationId,
        titleKey: "hostKeyChanged",
        params: { server: host.name },
        link: `/servers/${host.id}`,
      });
    }
    return;
  }
  // First contact: a proposal for an admin to confirm.
  await db
    .update(schema.host)
    .set({
      candidateKeyType: best.type,
      candidateKey: best.key,
      candidateKeyFingerprint: best.fingerprint,
      candidateKeySeenAt: now,
      lastError: null,
      updatedAt: now,
    })
    .where(eq(schema.host.id, host.id));
}

/* -------------------------------------------------------------------------- */
/* Inventory                                                                   */
/* -------------------------------------------------------------------------- */

function errorCode(error: unknown, fallback: HostErrorCode): HostErrorCode {
  return error instanceof HostError ? error.code : fallback;
}

/** A running inventory older than this lost its worker (matches the job expiry). */
const STALE_RUNNING = sql`now() - interval '20 minutes'`;

async function failRun(run: typeof schema.hostInventoryRun.$inferSelect, code: HostErrorCode, params = {}) {
  const message = hostErrorMessage(code, params);
  await db.transaction(async (tx) => {
    await tx
      .update(schema.hostInventoryRun)
      .set({ state: "failed", error: message, finishedAt: sql`now()` })
      .where(eq(schema.hostInventoryRun.id, run.id));
    await tx
      .update(schema.host)
      .set({ lastError: message, updatedAt: new Date() })
      .where(eq(schema.host.id, run.hostId));
  });
}

/** Runs one queued inventory. Never throws for a problem of the server; those become the run's error. */
export async function runHostInventory(runId: string, deps: HostDeps = {}): Promise<void> {
  const [run] = await db
    .update(schema.hostInventoryRun)
    .set({ state: "running", startedAt: sql`now()` })
    .where(
      and(
        eq(schema.hostInventoryRun.id, runId),
        or(
          eq(schema.hostInventoryRun.state, "queued"),
          and(
            eq(schema.hostInventoryRun.state, "running"),
            lt(schema.hostInventoryRun.startedAt, STALE_RUNNING),
          ),
        ),
      ),
    )
    .returning();
  if (!run) return; // taken, finished or cancelled

  const root = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "host-"));
  try {
    const [host] = await db.select().from(schema.host).where(eq(schema.host.id, run.hostId)).limit(1);
    if (!host) throw new HostError("hostRemoved");
    if (host.hostKeyStatus === "changed") throw new HostError("hostKeyChanged");
    if (host.hostKeyStatus !== "confirmed" || !host.hostKey || !host.hostKeyType) {
      throw new HostError("hostKeyNotConfirmed");
    }

    const report = await fetchReport(host, root, deps);
    await storeInventory(run, host, report, root);
  } catch (error) {
    if (error instanceof HostError) {
      const params = error.code === "inventoryTimeout" ? { seconds: INVENTORY_TIMEOUT_SECONDS } : {};
      if (error.code === "inventoryTooLarge") {
        await failRun(run, error.code, { limit: MAX_REPORT_BYTES / 1024 / 1024 });
      } else await failRun(run, error.code, params);
      if (error.code === "hostKeyChanged") await rescanAfterMismatch(run.hostId, deps);
    } else {
      console.error(`host inventory ${runId}:`, (error as Error).message);
      await failRun(run, "unexpected");
    }
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => {});
  }
}

/** ssh refused the pinned key: look at what the server presents now, so an admin can decide. */
async function rescanAfterMismatch(hostId: string, deps: HostDeps) {
  await scanHost(hostId, deps).catch(() => {});
  // scanHost records the new key as a candidate and marks the host changed; keep the reason visible.
  await db
    .update(schema.host)
    .set({ lastError: hostErrorMessage("hostKeyChanged") })
    .where(and(eq(schema.host.id, hostId), eq(schema.host.hostKeyStatus, "changed")));
}

/** Connects, runs `inventory` and returns the parsed report. */
async function fetchReport(host: HostRow, root: string, deps: HostDeps): Promise<InventoryReport> {
  const [access] = await db
    .select()
    .from(schema.hostAccessKey)
    .where(
      and(
        eq(schema.hostAccessKey.organizationId, host.organizationId),
        eq(schema.hostAccessKey.state, "active"),
      ),
    )
    .limit(1);
  if (!access?.secretId) throw new HostError("accessKeyMissing");
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, access.secretId),
        eq(schema.secret.organizationId, host.organizationId),
        eq(schema.secret.purpose, "host-ssh-key"),
      ),
    )
    .limit(1);
  if (!secret) throw new HostError("accessKeyMissing");

  const tools = deps.tools ?? (await sshTools());
  const target = await (deps.resolve ?? resolveTarget)(host.address);

  const sshDir = join(root, "ssh");
  const home = join(root, "home");
  await mkdir(sshDir, { mode: 0o700 });
  await mkdir(home);
  const keyFile = join(sshDir, "id_ed25519");
  const knownHostsFile = join(sshDir, "known_hosts");
  await writeFile(knownHostsFile, knownHostsLine(host.hostKeyType as string, host.hostKey as string), {
    mode: 0o600,
  });
  // The private key exists on disk only while ssh runs (ssh reads keys from files, not from memory).
  const privateKey = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose: "host-ssh-key" },
    vaultPrivateKey,
  );
  await writeFile(keyFile, privateKey, { mode: 0o600 });
  privateKey.fill(0);

  let result: Awaited<ReturnType<typeof runCapped>>;
  try {
    result = await runCapped(
      tools.bin,
      hostSshArgs({
        target,
        port: host.port,
        user: host.sshUser,
        keyFile,
        knownHostsFile,
        kex: tools.kex,
      }),
      {
        env: sshEnv(home),
        timeoutMs: deps.timeoutMs ?? INVENTORY_TIMEOUT_SECONDS * 1000,
        maxBytes: deps.maxBytes ?? MAX_REPORT_BYTES,
      },
    );
  } finally {
    await rm(keyFile, { force: true });
  }
  if (result.timedOut) throw new HostError("inventoryTimeout", { seconds: INVENTORY_TIMEOUT_SECONDS });
  if (result.tooLarge) throw new HostError("inventoryTooLarge", { limit: MAX_REPORT_BYTES / 1024 / 1024 });
  if (result.code !== 0) throw new HostError(classifySshFailure(result));

  try {
    return parseInventoryReport(result.stdout.toString("utf8"));
  } catch (error) {
    if (error instanceof InventoryParseError) throw new HostError("inventoryInvalid");
    throw error;
  }
}

/**
 * Stores the inventory, then matches it. The packages are stored even when matching is not
 * possible (an unknown operating system, no vulnerability database): that run is marked
 * failed with the reason, so a server that could not be checked never shows up as clean.
 */
async function storeInventory(
  run: typeof schema.hostInventoryRun.$inferSelect,
  host: HostRow,
  report: InventoryReport,
  root: string,
): Promise<void> {
  const now = new Date();
  const securityUpdates = report.packages.filter((p) => p.upgradableTo && p.securityUpdate).length;
  await db.transaction(async (tx) => {
    await tx.delete(schema.hostPackage).where(eq(schema.hostPackage.hostId, host.id));
    for (let i = 0; i < report.packages.length; i += 1000) {
      await tx.insert(schema.hostPackage).values(
        report.packages.slice(i, i + 1000).map((p) => ({
          id: newId("hpk"),
          organizationId: host.organizationId,
          hostId: host.id,
          name: p.name,
          version: p.version,
          arch: p.arch,
          type: p.type,
          origin: p.origin,
          originVersion: p.originVersion,
          upgradableTo: p.upgradableTo,
          securityUpdate: p.securityUpdate,
        })),
      );
    }
    await tx
      .update(schema.host)
      .set({
        osId: report.os.id,
        osVersionId: report.os.versionId,
        osName: report.os.prettyName ?? report.os.name,
        kernel: report.kernel,
        arch: report.arch,
        packageCount: report.packages.length,
        pendingUpdates: report.pendingUpdates,
        securityUpdates,
        lastInventoryAt: now,
        updatedAt: now,
      })
      .where(eq(schema.host.id, host.id));
  });

  if (!report.os.id) {
    await db
      .update(schema.hostInventoryRun)
      .set({ packageCount: report.packages.length, pendingUpdates: report.pendingUpdates })
      .where(eq(schema.hostInventoryRun.id, run.id));
    throw new HostError("osUnknown");
  }

  const out = join(root, "out");
  await mkdir(out);
  const sbomFile = join(out, "host.syft.json");
  await writeFile(
    sbomFile,
    JSON.stringify(buildHostSbom({ name: host.name, os: report.os, packages: report.packages })),
  );
  let parsed: ParsedReport;
  try {
    const json = await scanTarget(`sbom:${sbomFile}`, out);
    parsed = parseReport(json, host.id);
  } catch (error) {
    console.error(`host inventory ${run.id}: matching failed:`, (error as Error).message.slice(0, 300));
    await db
      .update(schema.hostInventoryRun)
      .set({ packageCount: report.packages.length, pendingUpdates: report.pendingUpdates })
      .where(eq(schema.hostInventoryRun.id, run.id));
    throw new HostError("scannerFailed");
  }
  addAdvisoryDates(parsed.vulnerabilities, env.GARNETOPS_GRYPE_DB_DIR);
  await persistFindings(run, host, report, parsed);
}

async function persistFindings(
  run: typeof schema.hostInventoryRun.$inferSelect,
  host: HostRow,
  report: InventoryReport,
  parsed: ParsedReport,
) {
  const f = schema.hostFinding;
  const now = new Date();
  const counts: Record<string, number> = {};
  for (const finding of parsed.findings.values())
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;

  await db.transaction(async (tx) => {
    await upsertVulnerabilities(tx, parsed.vulnerabilities.values(), now);
    const existing = await tx
      .select({ id: f.id, dedupKey: f.dedupKey, state: f.state })
      .from(f)
      .where(eq(f.hostId, host.id));
    const byKey = new Map(existing.map((e) => [e.dedupKey, e]));

    let newFindings = 0;
    for (const p of parsed.findings.values()) {
      const prior = byKey.get(p.dedupKey);
      const common = {
        packageVersion: p.packageVersion,
        packagePurl: p.packagePurl,
        fixedIn: p.fixedIn,
        fixState: p.fixState,
        severity: p.severity,
        severityRank: p.severityRank,
        lastSeenRunId: run.id,
        lastSeenAt: now,
        updatedAt: now,
      };
      if (!prior) {
        newFindings++;
        await tx.insert(f).values({
          id: newId("hfn"),
          organizationId: host.organizationId,
          hostId: host.id,
          vulnerabilityId: p.vulnerabilityId,
          dedupKey: p.dedupKey,
          packageName: p.packageName,
          packageType: p.packageType,
          state: "open",
          firstSeenRunId: run.id,
          firstSeenAt: now,
          ...common,
        });
      } else if (prior.state === "resolved") {
        // It came back: reopen and count it as new in this run.
        newFindings++;
        await tx
          .update(f)
          .set({ ...common, state: "open", resolvedAt: null, firstSeenRunId: run.id })
          .where(eq(f.id, prior.id));
      } else {
        await tx.update(f).set(common).where(eq(f.id, prior.id));
      }
    }
    const gone = existing
      .filter((e) => e.state !== "resolved" && !parsed.findings.has(e.dedupKey))
      .map((e) => e.id);
    for (let i = 0; i < gone.length; i += 500) {
      await tx
        .update(f)
        .set({ state: "resolved", resolvedAt: now, updatedAt: now })
        .where(inArray(f.id, gone.slice(i, i + 500)));
    }

    await tx
      .update(schema.hostInventoryRun)
      .set({
        state: "succeeded",
        finishedAt: now,
        packageCount: report.packages.length,
        pendingUpdates: report.pendingUpdates,
        severityCounts: counts,
        newFindings,
        resolvedFindings: gone.length,
        scannerVersions: parsed.grypeVersion ? { grype: parsed.grypeVersion } : {},
        vulnDbBuiltAt: parsed.dbBuiltAt,
        error: null,
      })
      .where(eq(schema.hostInventoryRun.id, run.id));
    await tx.update(schema.host).set({ lastError: null, updatedAt: now }).where(eq(schema.host.id, host.id));
  });
}
