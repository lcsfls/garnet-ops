/**
 * Website monitoring (ADR 0023, a module since ADR 0033): the organisation's own public assets seen from the outside. Every
 * route answers 409 `module-off` until an owner or admin switches the module on (`PUT /organization/modules/websites`). Everyone in the organisation reads.
 * Owners and admins add and change assets and ask for checks. Switching stage 2 (light active probing) on, running it by hand and
 * switching on the Certificate Transparency lookup also need a recent sign-in (step-up), an explicit acknowledgement, and are
 * written to the audit log. The API never connects to an asset itself: every look is a job for the worker.
 */

import { newId } from "@garnetops/core";
import {
  ACTIVE_LIMITS,
  ACTIVE_SCHEDULES,
  type AssetKind,
  CT_LIMITS,
  CT_PROVIDER,
  challengeName,
  EXPOSURE_PORTS,
  type ExposureSeverity,
  effectiveVerification,
  MAX_ASSETS,
  type PassiveSnapshot,
  SCHEDULE_HOURS,
  STAGE2_ACKNOWLEDGEMENT_ID,
  VERIFY_FILE_PATH,
  type VerifiableAsset,
  verifyFileUrl,
  verifyRecordValue,
} from "@garnetops/core/exposure";
import { checkAsset, newVerifyToken } from "@garnetops/core/exposure-assets";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { detectSoftware, judgeSoftware, SOFTWARE_NAMES } from "@garnetops/core/software";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, getTableColumns, ilike, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, requireRole } from "../lib/context.ts";
import { allowTestRanges } from "../lib/exposure-policy.ts";
import { requireModule } from "../lib/modules.ts";
import {
  type KeysetSpec,
  keysetQuery,
  parseDate,
  parseNumber,
  parseText,
  type SortOption,
  sortSpec,
  toPage,
} from "../lib/paginate.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const a = schema.exposureAsset;
type AssetRow = typeof a.$inferSelect;
type SortKey = string | number | Date;

/** Same job options as runs queued by the worker's schedule. One try: the next tick is the retry. */
const RUN_JOB = { retryLimit: 0, expireInSeconds: 25 * 60 };
const HOUR = 3_600_000;

const escapeLike = (text: string) => `%${text.replace(/[%_\\]/g, "\\$&")}%`;
const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

/* -------------------------------------------------------------------------- */
/* Lists                                                                       */
/* -------------------------------------------------------------------------- */

const openOf = (severity: string) =>
  sql`(select count(*)::int from ${schema.exposureFinding} f where f.asset_id = ${a.id} and f.state = 'open' and f.severity = ${severity})`;

/** Soonest certificate expiry of stage 1 (the first handshake), or far in the future when there is none. */
const certExpiry = sql`coalesce(date_trunc('milliseconds', (${a.passive} #>> '{tls,0,cert,validTo}')::timestamptz), 'infinity'::timestamptz)`;

const SORTS = {
  value: { keys: [a.value], parse: [parseText], dir: "asc" },
  // Lost first, then unverified, then verified.
  verification: {
    keys: [sql`case ${a.verifyState} when 'lost' then 0 when 'unverified' then 1 else 2 end`],
    parse: [parseNumber],
    dir: "asc",
  },
  critical: { keys: [openOf("critical")], parse: [parseNumber], dir: "desc" },
  high: { keys: [openOf("high")], parse: [parseNumber], dir: "desc" },
  medium: { keys: [openOf("medium")], parse: [parseNumber], dir: "desc" },
  low: { keys: [openOf("low")], parse: [parseNumber], dir: "desc" },
  certificate: { keys: [certExpiry], parse: [parseDate], dir: "asc" },
  stage2: { keys: [sql`case when ${a.stage2Enabled} then 0 else 1 end`], parse: [parseNumber], dir: "asc" },
  lastPassive: {
    keys: [sql`coalesce(date_trunc('milliseconds', ${a.lastPassiveAt}), 'epoch'::timestamptz)`],
    parse: [parseDate],
    dir: "desc",
  },
  lastActive: {
    keys: [sql`coalesce(date_trunc('milliseconds', ${a.lastActiveAt}), 'epoch'::timestamptz)`],
    parse: [parseDate],
    dir: "desc",
  },
} satisfies Record<string, SortOption>;
type SortName = keyof typeof SORTS;
const sortNames = Object.keys(SORTS) as [SortName, ...SortName[]];

type ListRow = AssetRow & { sortKeys?: SortKey[] };
const defaultSpec: KeysetSpec<ListRow> = {
  keys: [a.value, a.id],
  direction: "asc",
  keyOf: (row) => [row.value, row.id],
  parse: [parseText, parseText],
};

const STATUSES = ["all", "attention", "unverified", "stage2"] as const;
const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  q: z.string().trim().max(100).optional(),
  /** "attention": open critical or high findings, a lost verification or a failed run. */
  status: z.enum(STATUSES).default("all"),
  sort: z.enum(sortNames).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

const attentionSql = sql`(${a.verifyState} = 'lost' or ${a.passiveError} is not null or ${a.activeError} is not null or exists (
  select 1 from ${schema.exposureFinding} f where f.asset_id = ${a.id} and f.state = 'open' and f.severity in ('critical', 'high')))`;

function statusFilter(status: (typeof STATUSES)[number]) {
  if (status === "attention") return attentionSql;
  if (status === "unverified") return sql`${a.verifyState} <> 'verified'`;
  if (status === "stage2") return sql`${a.stage2Enabled}`;
  return undefined;
}
const searchFilter = (q: string | undefined) => (q ? ilike(a.value, escapeLike(q)) : undefined);

/* -------------------------------------------------------------------------- */
/* Presenting                                                                  */
/* -------------------------------------------------------------------------- */

const record = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** A few facts of the stage 1 snapshot for the table. The snapshot itself is in the detail. */
function passiveSummary(snapshot: unknown) {
  const s = record(snapshot);
  if (!s) return null;
  const tls = list(s.tls).map(record);
  const expiries = tls.flatMap((t) => {
    const validTo = str(record(t?.cert)?.validTo);
    return validTo ? [validTo] : [];
  });
  const http = record(s.http);
  return {
    takenAt: str(s.takenAt),
    addresses: list(s.addresses).filter((x): x is string => typeof x === "string"),
    resolves: s.resolves === true,
    httpsOpen: s.httpsOpen === true,
    certificateExpires: expiries.sort()[0] ?? null,
    httpStatus: num(http?.status),
  };
}

function activeSummary(snapshot: unknown) {
  const s = record(snapshot);
  if (!s) return null;
  return { takenAt: str(s.takenAt), open: list(s.open).length, checked: num(s.checked) };
}

interface LatestRun {
  id: string;
  state: "queued" | "running" | "succeeded" | "failed";
  trigger: "manual" | "schedule" | "enable";
  error: string | null;
  createdAt: Date;
  finishedAt: Date | null;
}

const verifiable = (
  row: Pick<AssetRow, "id" | "kind" | "value" | "verifyState" | "includeSubdomains">,
): VerifiableAsset => ({
  id: row.id,
  kind: row.kind,
  value: row.value,
  verifyState: row.verifyState,
  includeSubdomains: row.includeSubdomains,
});

async function orgVerifiables(organizationId: string): Promise<VerifiableAsset[]> {
  const rows = await db
    .select({
      id: a.id,
      kind: a.kind,
      value: a.value,
      verifyState: a.verifyState,
      includeSubdomains: a.includeSubdomains,
    })
    .from(a)
    .where(eq(a.organizationId, organizationId));
  return rows.map(verifiable);
}

async function openCounts(assetIds: string[]) {
  const map = new Map<string, Record<ExposureSeverity, number>>();
  if (assetIds.length === 0) return map;
  const f = schema.exposureFinding;
  const rows = await db
    .select({ assetId: f.assetId, severity: f.severity, n: count() })
    .from(f)
    .where(and(eq(f.state, "open"), inArray(f.assetId, assetIds)))
    .groupBy(f.assetId, f.severity);
  for (const row of rows) {
    const entry = map.get(row.assetId) ?? { critical: 0, high: 0, medium: 0, low: 0 };
    entry[row.severity] = row.n;
    map.set(row.assetId, entry);
  }
  return map;
}

/** The latest run of each stage for each asset, in any state, so queued and running ones show up. */
async function latestRuns(assetIds: string[]) {
  const map = new Map<string, { passive?: LatestRun; active?: LatestRun }>();
  if (assetIds.length === 0) return map;
  const r = schema.exposureRun;
  const rows = await db
    .selectDistinctOn([r.assetId, r.stage], {
      assetId: r.assetId,
      stage: r.stage,
      id: r.id,
      state: r.state,
      trigger: r.trigger,
      error: r.error,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
    })
    .from(r)
    .where(inArray(r.assetId, assetIds))
    .orderBy(r.assetId, r.stage, desc(r.createdAt), desc(r.id));
  for (const { assetId, stage, ...run } of rows)
    map.set(assetId, { ...(map.get(assetId) ?? {}), [stage]: run });
  return map;
}

/** What the web app shows of an asset. The proof token only goes to people who can verify (see `instructions`). */
function present(
  row: AssetRow,
  all: VerifiableAsset[],
  open: Record<ExposureSeverity, number> | undefined,
  runs: { passive?: LatestRun; active?: LatestRun } | undefined,
) {
  const effective = effectiveVerification(verifiable(row), all);
  const parent = effective.parentId ? all.find((x) => x.id === effective.parentId) : undefined;
  return {
    id: row.id,
    kind: row.kind,
    value: row.value,
    includeSubdomains: row.includeSubdomains,
    verification: {
      state: row.verifyState,
      method: row.verifyMethod,
      confirmedAt: iso(row.verifiedAt),
      checkedAt: iso(row.verifyCheckedAt),
      error: row.verifyError,
      /** True when the asset's own proof, or a verified parent domain that includes subdomains, covers it. */
      effective: effective.verified,
      via: effective.via,
      parent: parent ? { id: parent.id, value: parent.value } : null,
    },
    stage1: {
      enabled: row.passiveEnabled,
      lastAt: iso(row.lastPassiveAt),
      error: row.passiveError,
      run: runs?.passive ?? null,
      summary: passiveSummary(row.passive),
    },
    stage2: {
      enabled: row.stage2Enabled,
      schedule: row.stage2Schedule,
      acknowledgedAt: iso(row.stage2AcknowledgedAt),
      lastAt: iso(row.lastActiveAt),
      error: row.activeError,
      run: runs?.active ?? null,
      summary: activeSummary(row.active),
      /** When the next manual run is possible (the once-a-day limit). */
      nextManualAt: row.lastActiveAt
        ? new Date(row.lastActiveAt.getTime() + ACTIVE_LIMITS.minIntervalHours * HOUR).toISOString()
        : null,
    },
    open: open ?? { critical: 0, high: 0, medium: 0, low: 0 },
    createdAt: row.createdAt.toISOString(),
  };
}

async function ownAsset(organizationId: string, id: string): Promise<AssetRow> {
  const [row] = await db
    .select()
    .from(a)
    .where(and(eq(a.id, id), eq(a.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Asset");
  return row;
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

function invalid(errors: { field: string; code: string }[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((e) => ({ path: e.field, message: e.code })),
  });
}

async function countAssets(organizationId: string) {
  const [row] = await db.select({ n: count() }).from(a).where(eq(a.organizationId, organizationId));
  return row?.n ?? 0;
}

/** Queues a run of a stage unless one is queued or running (the unique index decides). */
async function queueRun(
  asset: Pick<AssetRow, "id" | "organizationId">,
  stage: "passive" | "active",
  trigger: "manual" | "enable",
  requestedBy: string,
): Promise<{ runId: string; alreadyQueued: boolean }> {
  const r = schema.exposureRun;
  const id = newId("exr");
  const inserted = await db
    .insert(r)
    .values({
      id,
      organizationId: asset.organizationId,
      assetId: asset.id,
      stage,
      state: "queued",
      trigger,
      requestedBy,
      // Millisecond precision on purpose: this column is a pagination key.
      createdAt: new Date(),
    })
    .onConflictDoNothing()
    .returning({ id: r.id });
  if (inserted.length === 0) {
    const [existing] = await db
      .select({ id: r.id })
      .from(r)
      .where(and(eq(r.assetId, asset.id), eq(r.stage, stage), inArray(r.state, ["queued", "running"])))
      .limit(1);
    return { runId: existing?.id ?? id, alreadyQueued: true };
  }
  await boss.send(QUEUES.exposureRun, { runId: id }, { ...RUN_JOB, singletonKey: `${asset.id}:${stage}` });
  return { runId: id, alreadyQueued: false };
}

async function queueVerify(assetId: string) {
  await boss.send(
    QUEUES.exposureVerify,
    { assetId },
    { retryLimit: 0, expireInSeconds: 600, singletonKey: assetId },
  );
}

/**
 * Switches stage 2 off for every asset of the organisation that is no longer covered by a verification: after a change that removes
 * a cover (subdomains no longer included, a parent removed, a new token). Each one is audited.
 */
async function stopUncovered(actor: Actor, reason: string): Promise<void> {
  const rows = await db.select().from(a).where(eq(a.organizationId, actor.organizationId));
  const all = rows.map(verifiable);
  for (const row of rows) {
    if (!row.stage2Enabled || effectiveVerification(verifiable(row), all).verified) continue;
    await db
      .update(a)
      .set({
        stage2Enabled: false,
        stage2AcknowledgedBy: null,
        stage2AcknowledgedAt: null,
        updatedAt: new Date(),
      })
      .where(eq(a.id, row.id));
    await audit(
      actor,
      "exposure.stage2_stopped",
      { type: "exposure_asset", id: row.id },
      { value: row.value, reason },
    );
  }
}

const createBody = z.object({ value: z.string().max(300), includeSubdomains: z.boolean().optional() });
const patchBody = z
  .object({ includeSubdomains: z.boolean().optional(), passiveEnabled: z.boolean().optional() })
  .refine((b) => b.includeSubdomains !== undefined || b.passiveEnabled !== undefined, "Nothing to change");
const stage2Body = z.discriminatedUnion("enabled", [
  z.object({
    enabled: z.literal(true),
    schedule: z.enum(ACTIVE_SCHEDULES).default("daily"),
    /** The identifier of the acknowledgement text the person saw. A client that shows an older text is refused. */
    acknowledgement: z.literal(STAGE2_ACKNOWLEDGEMENT_ID),
    confirmed: z.literal(true),
  }),
  z.object({ enabled: z.literal(false) }),
]);
const settingsBody = z.object({
  ct: z.object({
    enabled: z.boolean(),
    /** Acknowledges that domain names are sent to the search service. Needed to switch it on. */
    acknowledged: z.boolean().optional(),
  }),
});

/** Adds one asset: validated, counted, de-duplicated, audited, and queued for a first look. */
async function createAsset(
  actor: Actor,
  raw: string,
  options: { includeSubdomains?: boolean; source: "manual" | "discovery" },
): Promise<{ id: string; kind: AssetKind; value: string }> {
  const checked = checkAsset(raw, { allowTestRanges: allowTestRanges() });
  if (!checked.ok) throw invalid([{ field: "value", code: checked.problem }]);
  if ((await countAssets(actor.organizationId)) >= MAX_ASSETS) {
    throw new ProblemError(
      409,
      "limit-reached",
      "The organisation has reached the number of assets it may have",
    );
  }
  const [existing] = await db
    .select({ id: a.id })
    .from(a)
    .where(and(eq(a.organizationId, actor.organizationId), eq(a.value, checked.value)))
    .limit(1);
  if (existing) throw new ProblemError(409, "duplicate", "This asset is already added");
  const id = newId("exa");
  await db.insert(a).values({
    id,
    organizationId: actor.organizationId,
    kind: checked.kind,
    value: checked.value,
    includeSubdomains: checked.kind === "domain" ? (options.includeSubdomains ?? false) : false,
    verifyToken: newVerifyToken(),
    createdBy: actor.userId,
  });
  await audit(
    actor,
    "exposure.asset_added",
    { type: "exposure_asset", id },
    { value: checked.value, kind: checked.kind, source: options.source },
  );
  await queueRun({ id, organizationId: actor.organizationId }, "passive", "manual", actor.userId);
  await queueVerify(id);
  return { id, kind: checked.kind, value: checked.value };
}

/** The software a passive snapshot shows, judged now; empty when the home page did not answer. */
function softwareOf(passive: unknown) {
  const http = (passive as PassiveSnapshot | null)?.http;
  if (!http || http.status === null) return [];
  return detectSoftware(http).map((found) => ({
    ...judgeSoftware(found, new Date()),
    name: SOFTWARE_NAMES[found.product],
  }));
}

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

export const exposureRoutes = new Hono<AppEnv>()
  .use("*", requireModule("websites"))
  /* ------------------------------ lists ------------------------------ */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const where = and(
      eq(a.organizationId, actor.organizationId),
      searchFilter(input.q),
      statusFilter(input.status),
    );
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, a.id) : null;
    const activeSpec = (sorted?.spec ?? defaultSpec) as KeysetSpec<ListRow>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow, all] = await Promise.all([
      db
        .select({ ...getTableColumns(a), sortKeys: sorted ? sorted.select : sql<null>`null` })
        .from(a)
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(a).where(where),
      orgVerifiables(actor.organizationId),
    ]);
    const page = toPage(
      activeSpec,
      q,
      rows as ListRow[],
      totalRow[0]?.n ?? 0,
      input.pageSize,
      Boolean(input.cursor),
      (row) => row,
    );
    const ids = page.items.map((x) => x.id);
    const [open, runs] = await Promise.all([openCounts(ids), latestRuns(ids)]);
    return c.json({
      ...page,
      items: page.items.map((row) => present(row, all, open.get(row.id), runs.get(row.id))),
    });
  })
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = z.object({ q: z.string().trim().max(100).optional() }).parse(c.req.query());
    const where = and(eq(a.organizationId, actor.organizationId), searchFilter(input.q));
    const counts = await Promise.all(
      STATUSES.map(async (status) => {
        const [row] = await db
          .select({ n: count() })
          .from(a)
          .where(and(where, statusFilter(status)));
        return [status, row?.n ?? 0] as const;
      }),
    );
    const f = schema.exposureFinding;
    const severities = await db
      .select({ severity: f.severity, n: count() })
      .from(f)
      .where(and(eq(f.organizationId, actor.organizationId), eq(f.state, "open")))
      .groupBy(f.severity);
    const open: Record<ExposureSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of severities) open[row.severity] = row.n;
    return c.json({ ...Object.fromEntries(counts), open, limit: MAX_ASSETS });
  })

  /* ----------------------------- settings ----------------------------- */
  .get("/settings", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select()
      .from(schema.exposureSettings)
      .where(eq(schema.exposureSettings.organizationId, actor.organizationId))
      .limit(1);
    let enabledBy: string | null = null;
    if (row?.ctEnabledBy) {
      const [u] = await db
        .select({ name: schema.user.name })
        .from(schema.user)
        .where(eq(schema.user.id, row.ctEnabledBy))
        .limit(1);
      enabledBy = u?.name ?? null;
    }
    const today = new Date().toISOString().slice(0, 10);
    return c.json({
      certificateTransparency: {
        enabled: row?.ctEnabled ?? false,
        enabledAt: iso(row?.ctEnabledAt),
        enabledBy,
        provider: {
          id: CT_PROVIDER.id,
          name: CT_PROVIDER.name,
          operator: CT_PROVIDER.operator,
          urlTemplate: CT_PROVIDER.urlTemplate,
        },
        usageToday: row?.ctUsageDay === today ? row.ctUsageCount : 0,
        dailyBudget: CT_LIMITS.dailyBudget,
        lastError: row?.ctLastError ?? null,
      },
    });
  })
  .put("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = settingsBody.parse(await c.req.json());
    const s = schema.exposureSettings;
    const [row] = await db.select().from(s).where(eq(s.organizationId, actor.organizationId)).limit(1);
    const was = row?.ctEnabled ?? false;
    if (body.ct.enabled === was) return c.json({ ok: true });
    if (body.ct.enabled) {
      // Domain names of verified assets leave the network: step-up and an explicit acknowledgement.
      if (body.ct.acknowledged !== true)
        throw invalid([{ field: "ct.acknowledged", code: "acknowledgement_required" }]);
      requireRecentSignIn(actor);
    }
    const now = new Date();
    await db
      .insert(s)
      .values({
        organizationId: actor.organizationId,
        ctEnabled: body.ct.enabled,
        ctEnabledBy: body.ct.enabled ? actor.userId : null,
        ctEnabledAt: body.ct.enabled ? now : null,
      })
      .onConflictDoUpdate({
        target: s.organizationId,
        set: {
          ctEnabled: body.ct.enabled,
          ctEnabledBy: body.ct.enabled ? actor.userId : null,
          ctEnabledAt: body.ct.enabled ? now : null,
          ctLastError: null,
          updatedAt: now,
        },
      });
    await audit(
      actor,
      body.ct.enabled ? "exposure.ct_enabled" : "exposure.ct_disabled",
      { type: "organization", id: actor.organizationId },
      { provider: CT_PROVIDER.id, url: CT_PROVIDER.urlTemplate },
    );
    return c.json({ ok: true });
  })

  /* ------------------------------ adding ------------------------------ */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = createBody.parse(await c.req.json());
    await rateLimit(`exposure-add:${actor.organizationId}`, 60, 60 * 60_000);
    const created = await createAsset(actor, body.value, {
      source: "manual",
      ...(body.includeSubdomains !== undefined ? { includeSubdomains: body.includeSubdomains } : {}),
    });
    return c.json({ id: created.id }, 201);
  })
  .post("/discoveries/:id/add", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const d = schema.exposureDiscovery;
    const [found] = await db
      .select()
      .from(d)
      .where(and(eq(d.id, c.req.param("id")), eq(d.organizationId, actor.organizationId)))
      .limit(1);
    if (!found) throw notFound("Suggestion");
    const created = await createAsset(actor, found.name, { source: "discovery" });
    await db.delete(d).where(eq(d.id, found.id));
    return c.json({ id: created.id }, 201);
  })
  .post("/discoveries/:id/dismiss", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const d = schema.exposureDiscovery;
    const done = await db
      .update(d)
      .set({ state: "dismissed" })
      .where(and(eq(d.id, c.req.param("id")), eq(d.organizationId, actor.organizationId)))
      .returning({ id: d.id });
    if (done.length === 0) throw notFound("Suggestion");
    return c.body(null, 204);
  })

  /**
   * The number the navigation shows next to Websites: the assets of the "attention" filter (open critical or high
   * findings, a lost verification, a failed run), and the worst severity among their open findings.
   */
  .get("/attention", async (c) => {
    const actor = c.get("actor");
    const f = schema.exposureFinding;
    const [[assets], severities] = await Promise.all([
      db
        .select({ n: count() })
        .from(a)
        .where(and(eq(a.organizationId, actor.organizationId), attentionSql)),
      db
        .selectDistinct({ severity: f.severity })
        .from(f)
        .where(
          and(
            eq(f.organizationId, actor.organizationId),
            eq(f.state, "open"),
            inArray(f.severity, ["critical", "high"]),
          ),
        ),
    ]);
    const has = (severity: string) => severities.some((r) => r.severity === severity);
    return c.json({
      count: assets?.n ?? 0,
      worst: has("critical") ? "critical" : has("high") ? "high" : null,
    });
  })

  /* ------------------------------ detail ------------------------------ */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    const [all, open, runs] = await Promise.all([
      orgVerifiables(actor.organizationId),
      openCounts([row.id]),
      latestRuns([row.id]),
    ]);
    const f = schema.exposureFinding;
    const [findings, ports, history, suggestions] = await Promise.all([
      db
        .select({
          id: f.id,
          stage: f.stage,
          rule: f.rule,
          subject: f.subject,
          severity: f.severity,
          state: f.state,
          params: f.params,
          firstSeenAt: f.firstSeenAt,
          lastSeenAt: f.lastSeenAt,
          resolvedAt: f.resolvedAt,
        })
        .from(f)
        .where(eq(f.assetId, row.id))
        .orderBy(
          sql`case ${f.state} when 'open' then 0 else 1 end`,
          desc(f.severityRank),
          desc(f.lastSeenAt),
          f.id,
        )
        .limit(200),
      db
        .select()
        .from(schema.exposurePort)
        .where(eq(schema.exposurePort.assetId, row.id))
        .orderBy(schema.exposurePort.port, schema.exposurePort.address),
      db
        .select({
          id: schema.exposureRun.id,
          stage: schema.exposureRun.stage,
          state: schema.exposureRun.state,
          trigger: schema.exposureRun.trigger,
          error: schema.exposureRun.error,
          findingCounts: schema.exposureRun.findingCounts,
          openPorts: schema.exposureRun.openPorts,
          createdAt: schema.exposureRun.createdAt,
          startedAt: schema.exposureRun.startedAt,
          finishedAt: schema.exposureRun.finishedAt,
        })
        .from(schema.exposureRun)
        .where(eq(schema.exposureRun.assetId, row.id))
        .orderBy(desc(schema.exposureRun.createdAt), desc(schema.exposureRun.id))
        .limit(30),
      db
        .select({
          id: schema.exposureDiscovery.id,
          name: schema.exposureDiscovery.name,
          source: schema.exposureDiscovery.source,
        })
        .from(schema.exposureDiscovery)
        .where(and(eq(schema.exposureDiscovery.assetId, row.id), eq(schema.exposureDiscovery.state, "new")))
        .orderBy(schema.exposureDiscovery.name)
        .limit(100),
    ]);
    const admin = actor.role === "owner" || actor.role === "admin";
    const token = row.verifyToken;
    return c.json({
      ...present(row, all, open.get(row.id), runs.get(row.id)),
      passive: row.passive ?? null,
      active: row.active ?? null,
      /** What the site names about its software, judged against the committed end-of-life data (ADR 0038). */
      software: softwareOf(row.passive),
      findings: findings.map((x) => ({
        ...x,
        firstSeenAt: x.firstSeenAt.toISOString(),
        lastSeenAt: x.lastSeenAt.toISOString(),
        resolvedAt: iso(x.resolvedAt),
      })),
      ports: ports.map((p) => ({
        address: p.address,
        port: p.port,
        service: p.service,
        banner: p.banner,
        tls: p.tls ?? null,
        firstSeenAt: p.firstSeenAt.toISOString(),
        lastSeenAt: p.lastSeenAt.toISOString(),
      })),
      runs: history.map((x) => ({
        ...x,
        createdAt: x.createdAt.toISOString(),
        startedAt: iso(x.startedAt),
        finishedAt: iso(x.finishedAt),
      })),
      suggestions,
      // The proof is public by design (it is published in DNS or on the asset), but only people who can verify need it.
      instructions: admin
        ? {
            value: verifyRecordValue(token),
            dns: row.kind === "domain" ? { type: "TXT", name: challengeName(row.value) } : null,
            file: { url: verifyFileUrl(row.value), path: VERIFY_FILE_PATH },
          }
        : null,
      limits: { ports: EXPOSURE_PORTS.length, scheduleHours: SCHEDULE_HOURS },
    });
  })

  /* ------------------------------ changes ----------------------------- */
  .patch("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    const body = patchBody.parse(await c.req.json());
    const changes: Partial<typeof a.$inferInsert> = { updatedAt: new Date() };
    if (body.includeSubdomains !== undefined && body.includeSubdomains !== row.includeSubdomains) {
      if (row.kind !== "domain") throw invalid([{ field: "includeSubdomains", code: "domain_only" }]);
      changes.includeSubdomains = body.includeSubdomains;
    }
    if (body.passiveEnabled !== undefined && body.passiveEnabled !== row.passiveEnabled) {
      changes.passiveEnabled = body.passiveEnabled;
    }
    await db.update(a).set(changes).where(eq(a.id, row.id));
    if (changes.includeSubdomains !== undefined) {
      await audit(
        actor,
        "exposure.include_subdomains_changed",
        { type: "exposure_asset", id: row.id },
        { value: row.value, includeSubdomains: changes.includeSubdomains },
      );
      if (!changes.includeSubdomains) await stopUncovered(actor, "subdomainsNotIncluded");
    }
    if (changes.passiveEnabled !== undefined) {
      await audit(
        actor,
        "exposure.stage1_changed",
        { type: "exposure_asset", id: row.id },
        { value: row.value, enabled: changes.passiveEnabled },
      );
    }
    return c.body(null, 204);
  })
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    await db.delete(a).where(eq(a.id, row.id));
    await audit(
      actor,
      "exposure.asset_removed",
      { type: "exposure_asset", id: row.id },
      { value: row.value, kind: row.kind },
    );
    // Subdomains that were covered by this domain are no longer.
    await stopUncovered(actor, "parentRemoved");
    return c.body(null, 204);
  })

  /* --------------------------- proof of control --------------------------- */
  .post("/:id/verify", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    await rateLimit(`exposure-verify:${row.id}`, 12, 60 * 60_000);
    await queueVerify(row.id);
    return c.json({ queued: true }, 202);
  })
  .post("/:id/verify/rotate", async (c) => {
    // A new token voids the old proof: the asset is unverified again and stage 2 stops.
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    await db
      .update(a)
      .set({
        verifyToken: newVerifyToken(),
        verifyState: "unverified",
        verifyMethod: null,
        verifiedAt: null,
        verifyError: null,
        stage2Enabled: false,
        stage2AcknowledgedBy: null,
        stage2AcknowledgedAt: null,
        updatedAt: new Date(),
      })
      .where(eq(a.id, row.id));
    await audit(
      actor,
      "exposure.verification_reset",
      { type: "exposure_asset", id: row.id },
      { value: row.value, stage2WasOn: row.stage2Enabled },
    );
    await stopUncovered(actor, "verificationReset");
    return c.body(null, 204);
  })

  /* ------------------------------- stage 1 ------------------------------- */
  .post("/:id/run", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    await rateLimit(`exposure-run:${row.id}`, 10, 60 * 60_000);
    const queued = await queueRun(row, "passive", "manual", actor.userId);
    return c.json(queued, queued.alreadyQueued ? 200 : 202);
  })

  /* ------------------------------- stage 2 ------------------------------- */
  .put("/:id/stage2", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    const body = stage2Body.parse(await c.req.json());
    if (!body.enabled) {
      if (row.stage2Enabled) {
        await db
          .update(a)
          .set({
            stage2Enabled: false,
            stage2AcknowledgedBy: null,
            stage2AcknowledgedAt: null,
            updatedAt: new Date(),
          })
          .where(eq(a.id, row.id));
        await audit(
          actor,
          "exposure.stage2_disabled",
          { type: "exposure_asset", id: row.id },
          { value: row.value },
        );
      }
      return c.json({ enabled: false });
    }
    requireRecentSignIn(actor);
    const all = await orgVerifiables(actor.organizationId);
    const effective = effectiveVerification(verifiable(row), all);
    if (!effective.verified) {
      throw new ProblemError(409, "not-verified", "Prove control of the asset before switching on stage 2");
    }
    const now = new Date();
    await db
      .update(a)
      .set({
        stage2Enabled: true,
        stage2Schedule: body.schedule,
        stage2AcknowledgedBy: actor.userId,
        stage2AcknowledgedAt: now,
        activeError: null,
        updatedAt: now,
      })
      .where(eq(a.id, row.id));
    await audit(
      actor,
      "exposure.stage2_enabled",
      { type: "exposure_asset", id: row.id },
      {
        value: row.value,
        schedule: body.schedule,
        // The person confirmed: "I am authorised to test the infrastructure behind this name".
        acknowledgement: body.acknowledgement,
        verifiedVia: effective.via,
        ports: EXPOSURE_PORTS.length,
      },
    );
    // The first run starts at once, unless one ran in the last day (the limit holds whoever asks).
    const recent =
      row.lastActiveAt && now.getTime() - row.lastActiveAt.getTime() < ACTIVE_LIMITS.minIntervalHours * HOUR;
    if (!recent) await queueRun(row, "active", "enable", actor.userId);
    return c.json({ enabled: true, schedule: body.schedule });
  })
  .post("/:id/stage2/run", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const row = await ownAsset(actor.organizationId, c.req.param("id"));
    if (!row.stage2Enabled)
      throw new ProblemError(409, "stage2-off", "Stage 2 is not switched on for this asset");
    const now = new Date();
    if (
      row.lastActiveAt &&
      now.getTime() - row.lastActiveAt.getTime() < ACTIVE_LIMITS.minIntervalHours * HOUR
    ) {
      throw new ProblemError(409, "too-soon", "This asset was checked in the last 24 hours", undefined, {
        nextAt: new Date(row.lastActiveAt.getTime() + ACTIVE_LIMITS.minIntervalHours * HOUR).toISOString(),
      });
    }
    await rateLimit(`exposure-stage2-run:${row.id}`, 3, 60 * 60_000);
    const queued = await queueRun(row, "active", "manual", actor.userId);
    await audit(
      actor,
      "exposure.stage2_run_requested",
      { type: "exposure_asset", id: row.id },
      { value: row.value },
    );
    return c.json(queued, queued.alreadyQueued ? 200 : 202);
  });
