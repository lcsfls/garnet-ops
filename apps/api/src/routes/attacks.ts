/**
 * The attack overview (ADR 0016): the source addresses of attacks and authentication failures that
 * the Wazuh sync aggregates, placed on a map and in tables with the help of local GeoIP data, and
 * optionally scored by an OSINT provider.
 *
 * Everyone in the organisation reads the page. Owners and admins configure: the GeoIP data (manual
 * import or an opt-in monthly download), how long addresses are kept, and the optional OSINT
 * lookups. Anything that makes data leave the network, replaces the location data or raises the
 * retention needs a recent sign-in (step-up); every change is audited without any secret. The API
 * only seals the OSINT key; the worker is the only process that opens it and that talks to DB-IP
 * and to the provider. Nothing here contacts the outside.
 */
import { Readable } from "node:stream";
import { newId } from "@garnetops/core";
import {
  type AttackSource,
  asnTotals,
  countryCount,
  countryTotals,
  internalTotals,
} from "@garnetops/core/attacks";
import {
  canonicalIp,
  DBIP_ATTRIBUTION,
  DBIP_HOST,
  DBIP_LICENSE,
  DBIP_SITE,
  dbipUrlPattern,
  GEOIP_ERROR_TEXT,
  GEOIP_KINDS,
  GEOIP_LIMITS,
  GEOIP_STALE_MONTHS,
  GeoipError,
  type GeoipKind,
  ipKey,
  monthsSince,
  newParseStats,
  parseDatasetFilename,
  parseIp,
  RETENTION,
  readDataset,
} from "@garnetops/core/geoip";
import {
  OSINT_ACKNOWLEDGEMENTS,
  OSINT_LIMITS,
  OSINT_PROVIDER_IDS,
  OSINT_PROVIDERS,
  osintProvider,
} from "@garnetops/core/osint";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { seal } from "@garnetops/core/vault";
import { ATTACK_GROUPS, WINDOWS } from "@garnetops/core/wazuh";
import {
  datasetStatus,
  GeoipBusyError,
  importDataset,
  loadAttackSources,
  lookupIps,
  schema,
} from "@garnetops/db";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { pageInMemory } from "../lib/paginate-memory.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const SUMMARY_JOB = { retryLimit: 0, expireInSeconds: 15 * 60 };
/** AI requests share the budgets of AI triage (ADR 0013). */
const AI_USER_PER_MINUTE = 12;
const AI_ORG_PER_MINUTE = 40;
const SUMMARY_GRACE_MINUTES = 15;
/** A manual import must finish within this time, however slowly the file arrives. */
const UPLOAD_DEADLINE_MS = 10 * 60_000;

const s = schema.attackSettings;
const iso = (d: Date | null) => d?.toISOString() ?? null;

type FieldError = { field: string; code: string };
function invalid(errors: FieldError[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((x) => ({ path: x.field, message: x.code })),
  });
}

/* -------------------------------------------------------------------------- */
/* Settings                                                                    */
/* -------------------------------------------------------------------------- */

const DEFAULTS = {
  retentionDays: RETENTION.defaultDays,
  geoipDownloadEnabled: false,
  osintEnabled: false,
  osintTopN: OSINT_LIMITS.topN.default,
  osintDailyBudget: OSINT_LIMITS.dailyBudget.default,
} as const;

type SettingsRow = typeof s.$inferSelect;

async function loadSettings(organizationId: string): Promise<SettingsRow | null> {
  const [row] = await db.select().from(s).where(eq(s.organizationId, organizationId)).limit(1);
  return row ?? null;
}

async function ensureSettings(organizationId: string): Promise<SettingsRow> {
  await db.insert(s).values({ organizationId }).onConflictDoNothing();
  const row = await loadSettings(organizationId);
  if (!row) throw new Error("Settings row missing");
  return row;
}

async function aiAvailability(organizationId: string) {
  const [row] = await db
    .select({ enabled: schema.aiSettings.enabled, model: schema.aiSettings.model })
    .from(schema.aiSettings)
    .where(eq(schema.aiSettings.organizationId, organizationId))
    .limit(1);
  if (!row) return { state: "not-configured" as const };
  if (!row.enabled) return { state: "disabled" as const };
  return { state: "ready" as const, model: row.model };
}

async function wazuhConnection(organizationId: string) {
  const [row] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.organizationId, organizationId))
    .limit(1);
  return row ?? null;
}

type DatasetView = Awaited<ReturnType<typeof datasetStatus>>[number];

function presentDatasets(statuses: DatasetView[], now: Date) {
  return statuses.map((d) => ({
    kind: d.kind,
    active: d.active
      ? {
          source: d.active.source,
          month: d.active.month,
          rows: d.active.rows,
          loadedAt: d.active.loadedAt.toISOString(),
          sha256: d.active.sha256,
          stale: d.active.month !== null && monthsSince(d.active.month, now) > GEOIP_STALE_MONTHS,
        }
      : null,
    lastFailure: d.lastFailure
      ? { source: d.lastFailure.source, error: d.lastFailure.error, at: d.lastFailure.at.toISOString() }
      : null,
  }));
}

const attribution = {
  text: DBIP_ATTRIBUTION,
  url: DBIP_SITE,
  licenseUrl: DBIP_LICENSE,
};

/* -------------------------------------------------------------------------- */
/* Sources table                                                               */
/* -------------------------------------------------------------------------- */

const SORTS = ["count", "ip", "country", "asn", "firstSeen", "lastSeen", "score"] as const;
type SortName = (typeof SORTS)[number];

interface SourceRow extends AttackSource {
  id: string;
  osint: { score: number; reports: number; lastReportedAt: string | null; checkedAt: string } | null;
}

const regionNames = {
  en: new Intl.DisplayNames(["en"], { type: "region" }),
  de: new Intl.DisplayNames(["de"], { type: "region" }),
};
function countryNames(code: string): string {
  const names: string[] = [];
  for (const lang of ["en", "de"] as const) {
    try {
      const name = regionNames[lang].of(code);
      if (name) names.push(name);
    } catch {
      // A code the platform does not know has no name to search for.
    }
  }
  return names.join(" ").toLowerCase();
}

function matches(row: SourceRow, q: string): boolean {
  const needle = q.toLowerCase();
  if (row.ip.toLowerCase().includes(needle)) return true;
  if (row.country && (row.country.toLowerCase() === needle || countryNames(row.country).includes(needle)))
    return true;
  if (row.asn !== null && (`as${row.asn}` === needle.replace(/\s/g, "") || String(row.asn) === needle))
    return true;
  if (row.org?.toLowerCase().includes(needle)) return true;
  if (row.agents.some((a) => a.name.toLowerCase().includes(needle) || a.agentId === needle)) return true;
  if (row.groups.some((g) => g.toLowerCase().includes(needle))) return true;
  if (row.scope === "internal" && "internal".includes(needle)) return true;
  return false;
}

const sortKey = (name: SortName, row: SourceRow): string | number => {
  switch (name) {
    case "count":
      return row.count;
    case "ip": {
      const parsed = parseIp(row.ip);
      return parsed ? ipKey(parsed).toString().padStart(40, "0") : row.ip;
    }
    case "country":
      return row.scope === "internal" ? "~internal" : (row.country ?? "~");
    case "asn":
      return row.asn ?? -1;
    case "firstSeen":
      return row.firstSeen ? Date.parse(row.firstSeen) : 0;
    case "lastSeen":
      return row.lastSeen ? Date.parse(row.lastSeen) : 0;
    case "score":
      return row.osint?.score ?? -1;
  }
};
const numericSort: Record<SortName, boolean> = {
  count: true,
  ip: false,
  country: false,
  asn: true,
  firstSeen: true,
  lastSeen: true,
  score: true,
};
const defaultDir: Record<SortName, "asc" | "desc"> = {
  count: "desc",
  ip: "asc",
  country: "asc",
  asn: "asc",
  firstSeen: "desc",
  lastSeen: "desc",
  score: "desc",
};

const sourceQuery = z.object({
  period: z.enum(WINDOWS).default("24h"),
  q: z.string().trim().max(100).optional(),
  country: z
    .string()
    .regex(/^([A-Z]{2}|internal|unknown)$/)
    .optional(),
  asn: z.coerce.number().int().min(0).max(4_294_967_295).optional(),
  agent: z
    .string()
    .regex(/^\d{1,8}$/)
    .optional(),
  group: z.enum(ATTACK_GROUPS).optional(),
  sort: z.enum(SORTS).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
});

/** The stored OSINT scores of the organisation for these addresses; empty while OSINT is off. */
async function osintFor(organizationId: string, settings: SettingsRow | null, ips: string[]) {
  const out = new Map<string, NonNullable<SourceRow["osint"]>>();
  if (!settings?.osintEnabled || !settings.osintProvider || ips.length === 0) return out;
  const o = schema.attackOsintResult;
  const rows = await db
    .select()
    .from(o)
    .where(
      and(eq(o.organizationId, organizationId), eq(o.provider, settings.osintProvider), inArray(o.ip, ips)),
    );
  for (const r of rows) {
    out.set(r.ip, {
      score: r.score,
      reports: r.reports,
      lastReportedAt: iso(r.lastReportedAt),
      checkedAt: r.checkedAt.toISOString(),
    });
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Request bodies                                                              */
/* -------------------------------------------------------------------------- */

const patchBody = z
  .object({
    retentionDays: z.number().int().min(RETENTION.minDays).max(RETENTION.maxDays).optional(),
    geoipDownloadEnabled: z.boolean().optional(),
    osint: z
      .object({
        enabled: z.boolean().optional(),
        provider: z.enum(OSINT_PROVIDER_IDS).optional(),
        apiKey: z.string().max(300).nullable().optional(),
        topN: z.number().int().min(OSINT_LIMITS.topN.min).max(OSINT_LIMITS.topN.max).optional(),
        dailyBudget: z
          .number()
          .int()
          .min(OSINT_LIMITS.dailyBudget.min)
          .max(OSINT_LIMITS.dailyBudget.max)
          .optional(),
        acknowledge: z.array(z.enum(OSINT_ACKNOWLEDGEMENTS)).max(OSINT_ACKNOWLEDGEMENTS.length).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

const kindParam = z.enum(GEOIP_KINDS);
const summaryBody = z.object({ language: z.enum(["en", "de"]).default("en") });

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

export const attackRoutes = new Hono<AppEnv>()
  /* ------------------------------ the page ------------------------------ */
  .get("/overview", async (c) => {
    const actor = c.get("actor");
    const { period } = z.object({ period: z.enum(WINDOWS).default("24h") }).parse(c.req.query());
    const now = new Date();
    const connection = await wazuhConnection(actor.organizationId);
    const settings = await loadSettings(actor.organizationId);
    const datasets = presentDatasets(await datasetStatus(db), now);
    const provider =
      settings?.osintEnabled && settings.osintProvider ? osintProvider(settings.osintProvider) : null;
    const base = {
      connected: connection !== null,
      attribution,
      geoip: {
        datasets,
        missing: datasets.some((d) => d.kind === "country" && d.active === null),
        asnMissing: datasets.some((d) => d.kind === "asn" && d.active === null),
      },
      osint: provider
        ? { enabled: true, provider: provider.id, providerName: provider.name }
        : { enabled: false },
      retentionDays: settings?.retentionDays ?? DEFAULTS.retentionDays,
      ai: await aiAvailability(actor.organizationId),
      period,
    };
    if (!connection) return c.json({ ...base, syncedAt: null, window: null });

    const w = schema.wazuhAttackWindow;
    const [numbers] = await db
      .select()
      .from(w)
      .where(and(eq(w.connectionId, connection.id), eq(w.window, period)))
      .limit(1);
    if (!numbers) return c.json({ ...base, syncedAt: iso(connection.lastSyncAt), window: null });

    const sources = await loadAttackSources(db, connection.id, period);
    const located = countryTotals(sources);
    const countries = located.filter((t) => t.country !== null && t.country !== "ZZ");
    const unlocated = located
      .filter((t) => t.country === null || t.country === "ZZ")
      .reduce((n, t) => ({ alerts: n.alerts + t.alerts, sources: n.sources + t.sources }), {
        alerts: 0,
        sources: 0,
      });
    const previousCountries =
      numbers.previousAttackAlerts === null
        ? null
        : new Set(
            [
              ...(
                await lookupIps(
                  db,
                  numbers.previousSources.map((x) => x.ip),
                )
              ).values(),
            ]
              .map((g) => g.country)
              .filter((x): x is string => x !== null && x !== "ZZ"),
          ).size;

    // The agents attacked most: with the confirmed server, if there is one, so the page can link to it.
    const a = schema.wazuhAgent;
    const agentRows = numbers.agents.length
      ? await db
          .select({ agentId: a.agentId, hostId: a.hostId })
          .from(a)
          .where(
            and(
              eq(a.connectionId, connection.id),
              inArray(
                a.agentId,
                numbers.agents.map((x) => x.agentId),
              ),
            ),
          )
      : [];
    const hostOf = new Map(agentRows.map((r) => [r.agentId, r.hostId]));

    return c.json({
      ...base,
      syncedAt: iso(connection.lastSyncAt),
      window: {
        readAt: numbers.readAt.toISOString(),
        attackAlerts: numbers.attackAlerts,
        previousAttackAlerts: numbers.previousAttackAlerts,
        distinctSources: numbers.distinctSources,
        previousDistinctSources: numbers.previousDistinctSources,
        countryCount: countryCount(sources),
        previousCountryCount: previousCountries,
        listedAlerts: sources.reduce((n, x) => n + x.count, 0),
        listedSources: sources.length,
        countries,
        unlocated,
        internal: internalTotals(sources),
        asns: asnTotals(sources)
          .filter((t) => t.asn !== null)
          .slice(0, 25),
        agents: numbers.agents.slice(0, 10).map((x) => ({ ...x, hostId: hostOf.get(x.agentId) ?? null })),
      },
    });
  })

  .get("/sources", async (c) => {
    const actor = c.get("actor");
    const input = sourceQuery.parse(c.req.query());
    const connection = await wazuhConnection(actor.organizationId);
    if (!connection) {
      return c.json({ items: [], total: 0, pageSize: input.pageSize, next: null, prev: null });
    }
    const settings = await loadSettings(actor.organizationId);
    const sources = await loadAttackSources(db, connection.id, input.period);
    const osint = await osintFor(
      actor.organizationId,
      settings,
      sources.map((x) => canonicalIp(x.ip) ?? x.ip),
    );
    const provider =
      settings?.osintEnabled && settings.osintProvider ? osintProvider(settings.osintProvider) : null;
    let rows: SourceRow[] = sources.map((x) => ({
      ...x,
      id: canonicalIp(x.ip) ?? x.ip,
      osint: osint.get(canonicalIp(x.ip) ?? x.ip) ?? null,
    }));
    if (input.country === "internal") rows = rows.filter((r) => r.scope === "internal");
    else if (input.country === "unknown")
      rows = rows.filter((r) => r.scope === "public" && (r.country === null || r.country === "ZZ"));
    else if (input.country) rows = rows.filter((r) => r.country === input.country);
    if (input.asn !== undefined) rows = rows.filter((r) => r.asn === input.asn);
    if (input.agent) rows = rows.filter((r) => r.agents.some((x) => x.agentId === input.agent));
    if (input.group) rows = rows.filter((r) => r.groups.includes(input.group as string));
    if (input.q) rows = rows.filter((r) => matches(r, input.q as string));

    const sort: SortName = input.sort ?? "count";
    const page = pageInMemory(rows, {
      id: (r) => r.id,
      key: (r) => sortKey(sort, r),
      numeric: numericSort[sort],
      dir: input.dir ?? defaultDir[sort],
      cursor: input.cursor,
      pageSize: input.pageSize,
    });
    // The agents an address attacked, with the confirmed server if there is one, so the table can link to it.
    const a = schema.wazuhAgent;
    const agentIds = [...new Set(page.items.flatMap((r) => r.agents.map((x) => x.agentId)))];
    const hostRows = agentIds.length
      ? await db
          .select({ agentId: a.agentId, hostId: a.hostId })
          .from(a)
          .where(and(eq(a.connectionId, connection.id), inArray(a.agentId, agentIds)))
      : [];
    const hostOf = new Map(hostRows.map((r) => [r.agentId, r.hostId]));
    return c.json({
      ...page,
      items: page.items.map((r) => ({
        ip: r.ip,
        scope: r.scope,
        country: r.country,
        asn: r.asn,
        org: r.org,
        count: r.count,
        groups: r.groups,
        agents: r.agents.map((x) => ({ ...x, hostId: hostOf.get(x.agentId) ?? null })),
        firstSeen: r.firstSeen,
        lastSeen: r.lastSeen,
        osint: r.osint
          ? { ...r.osint, pageUrl: provider && r.scope === "public" ? provider.pageUrl(r.id) : null }
          : null,
      })),
    });
  })

  /* ------------------------------ AI summary ------------------------------ */
  .get("/summary", async (c) => {
    const actor = c.get("actor");
    const w = schema.attackSummary;
    const [row] = await db
      .select({ summary: w, author: schema.user.name })
      .from(w)
      .leftJoin(schema.user, eq(schema.user.id, w.requestedBy))
      .where(eq(w.organizationId, actor.organizationId))
      .orderBy(desc(w.createdAt))
      .limit(1);
    if (!row) return c.json({ summary: null });
    const x = row.summary;
    return c.json({
      summary: {
        id: x.id,
        status: x.status,
        content: x.status === "complete" ? x.content : "",
        error: x.error,
        model: x.model,
        language: x.language,
        author: row.author,
        createdAt: x.createdAt.toISOString(),
        finishedAt: iso(x.finishedAt),
      },
    });
  })
  .post("/summary", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const body = summaryBody.parse(await c.req.json().catch(() => ({})));
    const connection = await wazuhConnection(actor.organizationId);
    if (!connection) throw new ProblemError(404, "not-found", "Wazuh connection not found");
    const ai = await aiAvailability(actor.organizationId);
    if (ai.state !== "ready") {
      throw new ProblemError(409, "ai-not-ready", "AI is not available", undefined, { state: ai.state });
    }
    const [numbers] = await db
      .select({ connectionId: schema.wazuhAttackWindow.connectionId })
      .from(schema.wazuhAttackWindow)
      .where(eq(schema.wazuhAttackWindow.connectionId, connection.id))
      .limit(1);
    if (!numbers) throw new ProblemError(409, "no-data", "There is nothing to summarise yet");
    await rateLimit(`ai:user:${actor.userId}`, AI_USER_PER_MINUTE);
    await rateLimit(`ai:org:${actor.organizationId}`, AI_ORG_PER_MINUTE);
    const w = schema.attackSummary;
    const [busy] = await db
      .select({ id: w.id })
      .from(w)
      .where(
        and(
          eq(w.organizationId, actor.organizationId),
          inArray(w.status, ["pending", "running"]),
          // A summary that is still pending after the grace period no longer blocks a new one.
          sql`${w.createdAt} > now() - make_interval(mins => ${SUMMARY_GRACE_MINUTES})`,
        ),
      )
      .limit(1);
    if (busy) throw new ProblemError(429, "summary-busy", "A summary is being written already");
    const id = newId("atm");
    await db.insert(w).values({
      id,
      organizationId: actor.organizationId,
      connectionId: connection.id,
      status: "pending",
      language: body.language,
      requestedBy: actor.userId,
      createdAt: new Date(),
    });
    try {
      await boss.send(QUEUES.attackSummary, { summaryId: id }, SUMMARY_JOB);
    } catch (error) {
      await db
        .update(w)
        .set({ status: "failed", error: "internal", finishedAt: new Date() })
        .where(eq(w.id, id));
      throw error;
    }
    // The prompt is never part of the log, only what was asked about and which model answers.
    await audit(
      actor,
      "ai.request",
      { type: "wazuh_connection", id: connection.id },
      { kind: "attack-summary", model: ai.model, summaryId: id },
    );
    return c.json({ id }, 202);
  })

  /* ------------------------------ settings (owners and admins) ------------------------------ */
  .get("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = (await loadSettings(actor.organizationId)) ?? null;
    const connection = await wazuhConnection(actor.organizationId);
    const now = new Date();
    const datasets = presentDatasets(await datasetStatus(db), now);
    const provider = row?.osintProvider ? osintProvider(row.osintProvider) : null;
    const today = now.toISOString().slice(0, 10);
    return c.json({
      wazuhConnected: connection !== null,
      retentionDays: row?.retentionDays ?? DEFAULTS.retentionDays,
      retention: { default: RETENTION.defaultDays, min: RETENTION.minDays, max: RETENTION.maxDays },
      geoip: {
        datasets,
        attribution,
        host: DBIP_HOST,
        urls: { country: dbipUrlPattern("country"), asn: dbipUrlPattern("asn") },
        limits: {
          maxCompressedBytes: GEOIP_LIMITS.maxCompressedBytes,
          maxDecompressedBytes: GEOIP_LIMITS.maxDecompressedBytes,
        },
        errors: GEOIP_ERROR_TEXT,
        download: {
          enabled: row?.geoipDownloadEnabled ?? false,
          enabledAt: iso(row?.geoipDownloadEnabledAt ?? null),
          lastAttemptAt: iso(row?.geoipDownloadLastAttemptAt ?? null),
          lastError: row?.geoipDownloadLastError ?? null,
        },
      },
      osint: {
        enabled: row?.osintEnabled ?? false,
        provider: provider ? provider.id : null,
        providers: Object.values(OSINT_PROVIDERS).map((p) => ({
          id: p.id,
          name: p.name,
          host: p.host,
          termsUrl: p.termsUrl,
          termsConfirmed: p.termsConfirmed,
          freeDailyLimit: p.freeDailyLimit,
        })),
        keySet: row?.osintSecretId != null,
        topN: row?.osintTopN ?? DEFAULTS.osintTopN,
        dailyBudget: row?.osintDailyBudget ?? DEFAULTS.osintDailyBudget,
        limits: {
          topN: OSINT_LIMITS.topN,
          dailyBudget: OSINT_LIMITS.dailyBudget,
          cacheHours: OSINT_LIMITS.cacheHours,
        },
        acknowledgedAt: iso(row?.osintAcknowledgedAt ?? null),
        usageToday: row?.osintUsageDay === today ? row.osintUsageCount : 0,
        lastRunAt: iso(row?.osintLastRunAt ?? null),
        lastError: row?.osintLastError ?? null,
      },
    });
  })

  .patch("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = patchBody.parse(await c.req.json());
    const row = await ensureSettings(actor.organizationId);
    const errors: FieldError[] = [];
    const changes: Partial<typeof s.$inferInsert> = {};
    const events: { action: string; data: Record<string, unknown> }[] = [];
    let stepUp = false;

    if (body.retentionDays !== undefined && body.retentionDays !== row.retentionDays) {
      changes.retentionDays = body.retentionDays;
      // Keeping addresses longer is the privacy-relevant direction.
      if (body.retentionDays > row.retentionDays) stepUp = true;
      events.push({
        action: "attacks.settings_changed",
        data: { retentionDays: body.retentionDays, previous: row.retentionDays },
      });
    }

    if (body.geoipDownloadEnabled !== undefined && body.geoipDownloadEnabled !== row.geoipDownloadEnabled) {
      changes.geoipDownloadEnabled = body.geoipDownloadEnabled;
      if (body.geoipDownloadEnabled) {
        // Outbound traffic to DB-IP starts: an explicit, recent decision.
        stepUp = true;
        changes.geoipDownloadEnabledBy = actor.userId;
        changes.geoipDownloadEnabledAt = new Date();
        changes.geoipDownloadLastAttemptAt = null;
        changes.geoipDownloadLastError = null;
      }
      events.push({
        action: body.geoipDownloadEnabled
          ? "attacks.geoip_download_enabled"
          : "attacks.geoip_download_disabled",
        data: { host: DBIP_HOST },
      });
    }

    let newKey: string | null = null;
    let dropKey = false;
    let purgeOsint = false;
    const o = body.osint;
    if (o) {
      const providerId = o.provider ?? row.osintProvider ?? OSINT_PROVIDER_IDS[0];
      const provider = osintProvider(providerId);
      if (!provider) errors.push({ field: "osint.provider", code: "provider_unknown" });
      if (o.provider !== undefined && o.provider !== row.osintProvider) {
        changes.osintProvider = o.provider;
        stepUp = true;
        purgeOsint = true;
      }
      if (o.topN !== undefined && o.topN !== row.osintTopN) {
        changes.osintTopN = o.topN;
        events.push({
          action: "attacks.settings_changed",
          data: { osintTopN: o.topN, previous: row.osintTopN },
        });
      }
      if (o.dailyBudget !== undefined && o.dailyBudget !== row.osintDailyBudget) {
        changes.osintDailyBudget = o.dailyBudget;
        events.push({
          action: "attacks.settings_changed",
          data: { osintDailyBudget: o.dailyBudget, previous: row.osintDailyBudget },
        });
      }
      if (o.apiKey !== undefined) {
        if (o.apiKey === null) {
          // Removing the key switches OSINT off: there is nothing to ask with.
          dropKey = true;
          stepUp = true;
        } else {
          const key = o.apiKey.trim();
          const problem = provider?.keyProblem(key);
          if (problem) errors.push({ field: "osint.apiKey", code: `key_${problem}` });
          else {
            newKey = key;
            stepUp = true;
          }
        }
      }
      if (o.enabled !== undefined && o.enabled !== row.osintEnabled) {
        if (o.enabled) {
          if (!newKey && !row.osintSecretId) errors.push({ field: "osint.apiKey", code: "key_empty" });
          if (dropKey) errors.push({ field: "osint.apiKey", code: "key_empty" });
          // Both statements are confirmed again every time OSINT is switched on.
          for (const ack of OSINT_ACKNOWLEDGEMENTS) {
            if (!o.acknowledge?.includes(ack))
              errors.push({ field: "osint.acknowledge", code: `ack_${ack}` });
          }
          stepUp = true;
        }
      }
    }
    if (errors.length > 0) throw invalid(errors);
    if (stepUp) requireRecentSignIn(actor);

    // --- apply
    const previousSecret = row.osintSecretId;
    let secretId: string | null | undefined;
    if (newKey) {
      secretId = newId("sec");
      await db.insert(schema.secret).values({
        id: secretId,
        organizationId: actor.organizationId,
        purpose: "osint-api-key",
        sealed: seal(
          newKey,
          { organizationId: actor.organizationId, recordId: secretId, purpose: "osint-api-key" },
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      changes.osintSecretId = secretId;
      events.push({
        action: "attacks.osint_key_changed",
        data: { provider: body.osint?.provider ?? row.osintProvider },
      });
      purgeOsint = true;
    }
    if (dropKey) {
      changes.osintSecretId = null;
      changes.osintEnabled = false;
      purgeOsint = true;
      if (row.osintEnabled)
        events.push({ action: "attacks.osint_disabled", data: { reason: "key removed" } });
      events.push({ action: "attacks.osint_key_removed", data: {} });
    }
    if (o?.enabled !== undefined && o.enabled !== row.osintEnabled && !dropKey) {
      changes.osintEnabled = o.enabled;
      if (o.enabled) {
        changes.osintProvider = o.provider ?? row.osintProvider ?? OSINT_PROVIDER_IDS[0];
        changes.osintAcknowledgedBy = actor.userId;
        changes.osintAcknowledgedAt = new Date();
        changes.osintLastError = null;
        events.push({
          action: "attacks.osint_enabled",
          data: {
            provider: changes.osintProvider,
            topN: changes.osintTopN ?? row.osintTopN,
            dailyBudget: changes.osintDailyBudget ?? row.osintDailyBudget,
            acknowledged: [...OSINT_ACKNOWLEDGEMENTS],
          },
        });
      } else {
        purgeOsint = true;
        events.push({ action: "attacks.osint_disabled", data: {} });
      }
    }
    if (Object.keys(changes).length > 0) {
      await db
        .update(s)
        .set({ ...changes, updatedAt: new Date() })
        .where(eq(s.organizationId, actor.organizationId));
    }
    if (purgeOsint) {
      // Switching off, changing the key or the provider: what the old provider said is not kept.
      await db
        .delete(schema.attackOsintResult)
        .where(eq(schema.attackOsintResult.organizationId, actor.organizationId));
    }
    if (previousSecret && (newKey || dropKey)) {
      await db.delete(schema.secret).where(eq(schema.secret.id, previousSecret));
    }
    for (const event of events) {
      await audit(actor, event.action, { type: "attack_settings", id: actor.organizationId }, event.data);
    }
    return c.body(null, 204);
  })

  /* ------------------------------ GeoIP data (owners and admins) ------------------------------ */
  .put("/geoip/:kind", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const kind: GeoipKind = kindParam.parse(c.req.param("kind"));
    const filename = z.string().max(200).optional().parse(c.req.query("filename"));
    const length = Number(c.req.header("content-length"));
    if (!Number.isFinite(length) || length <= 0) {
      throw new ProblemError(411, "length-required", "The file size is required");
    }
    if (length > GEOIP_LIMITS.maxCompressedBytes) {
      throw new ProblemError(413, "geoip-too-large", GEOIP_ERROR_TEXT.tooLarge, undefined, {
        reason: "tooLarge",
      });
    }
    const named = filename ? parseDatasetFilename(filename) : null;
    if (named && named.kind !== kind) {
      throw new ProblemError(422, "geoip-invalid", GEOIP_ERROR_TEXT.wrongKind, undefined, {
        reason: "wrongKind",
      });
    }
    await rateLimit(`attacks-geoip:${actor.organizationId}`, 20, 60 * 60_000);
    const body = c.req.raw.body;
    if (!body) throw new ProblemError(400, "empty-body", "The request has no file");

    const source = Readable.fromWeb(body as never);
    // However slowly the file arrives, the whole import ends at the deadline.
    const timer = setTimeout(() => source.destroy(new GeoipError("timeout")), UPLOAD_DEADLINE_MS);
    const stats = newParseStats();
    const target = { type: "geoip_dataset", id: kind };
    try {
      const result = await importDataset(db, {
        kind,
        source: "import",
        month: named?.month ?? null,
        importedBy: actor.userId,
        rows: readDataset(kind, source, stats),
        stats,
      });
      await audit(actor, "attacks.geoip_imported", target, {
        kind,
        month: named?.month ?? null,
        rows: result.rows,
        compressedBytes: stats.compressedBytes,
        sha256: stats.sha256,
        source: "import",
      });
      return c.json({ rows: result.rows, month: named?.month ?? null }, 201);
    } catch (error) {
      if (error instanceof GeoipBusyError) {
        throw new ProblemError(409, "geoip-busy", "Another import of this kind is running");
      }
      if (error instanceof GeoipError) {
        await audit(actor, "attacks.geoip_import_failed", target, {
          kind,
          error: error.code,
          source: "import",
        });
        throw new ProblemError(
          error.code === "tooLarge" || error.code === "decompressedTooLarge" ? 413 : 422,
          "geoip-invalid",
          error.message,
          undefined,
          { reason: error.code },
        );
      }
      throw error;
    } finally {
      clearTimeout(timer);
      source.destroy();
    }
  })
  .delete("/geoip/:kind", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const kind: GeoipKind = kindParam.parse(c.req.param("kind"));
    const d = schema.geoipDataset;
    const removed = await db.delete(d).where(eq(d.kind, kind)).returning({ id: d.id });
    if (removed.length === 0) throw new ProblemError(404, "not-found", "No dataset to remove");
    await audit(actor, "attacks.geoip_removed", { type: "geoip_dataset", id: kind }, { kind });
    return c.body(null, 204);
  })

  /* ------------------------------ erasure ------------------------------ */
  .delete("/data", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const addresses = await db
      .delete(schema.wazuhSourceIp)
      .where(eq(schema.wazuhSourceIp.organizationId, actor.organizationId))
      .returning({ id: schema.wazuhSourceIp.id });
    const windows = await db
      .delete(schema.wazuhAttackWindow)
      .where(eq(schema.wazuhAttackWindow.organizationId, actor.organizationId))
      .returning({ id: schema.wazuhAttackWindow.connectionId });
    const osint = await db
      .delete(schema.attackOsintResult)
      .where(eq(schema.attackOsintResult.organizationId, actor.organizationId))
      .returning({ id: schema.attackOsintResult.id });
    await audit(
      actor,
      "attacks.data_purged",
      { type: "attack_settings", id: actor.organizationId },
      { sourceAddresses: addresses.length, attackWindows: windows.length, osintResults: osint.length },
    );
    return c.json({
      sourceAddresses: addresses.length,
      attackWindows: windows.length,
      osintResults: osint.length,
    });
  });
