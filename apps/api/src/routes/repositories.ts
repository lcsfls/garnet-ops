import { isSshRepoUrl, newId, repoUrlSchema } from "@garnetops/core";
import { parseGradeFilter } from "@garnetops/core/grades";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { fingerprint, generateDeployKey, parseKnownHosts } from "@garnetops/core/ssh";
import { seal } from "@garnetops/core/vault";
import {
  isTimeZone,
  openFindingsTrend,
  openTotalsByRepository,
  repositoryVisibleTo,
  schema,
  type Viewer,
} from "@garnetops/db";
import { and, count, desc, eq, getTableColumns, ilike, inArray, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import {
  gradeDistribution,
  gradeFieldsOf,
  gradeFilterSql,
  gradeRankSql,
  REPOSITORY_FINDINGS,
} from "../lib/grades.ts";
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
import { renovateRoutes, writeAccessRoutes, writeAccessSummary } from "./fixes.ts";

const r = schema.repository;

type RepoRow = typeof r.$inferSelect;

const spec: KeysetSpec<RepoRow> = {
  keys: [r.name, r.id],
  direction: "asc",
  keyOf: (row) => [row.name, row.id],
  parse: [parseText, parseText],
};

const countsQuery = z.object({ q: z.string().trim().max(100).optional() });
const trendQuery = z.object({ tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC") });
const pageQuery = z.object({ cursor: z.string().optional(), pageSize: pageSizeSchema });

type PatchRow = { id: string; resolvedAt: Date } & Record<string, unknown>;
// Newest fix first. Resolved findings always have a resolution time.
const patchSpec: KeysetSpec<PatchRow> = {
  keys: [schema.finding.resolvedAt, schema.finding.id],
  direction: "desc",
  keyOf: (row) => [row.resolvedAt, row.id],
  parse: [parseDate, parseText],
};

/** The repository, if the caller sees it: shared with the organisation, or their own private one (ADR 0030). */
async function ownRepository(viewer: Viewer, id: string) {
  const [row] = await db
    .select({ id: r.id })
    .from(r)
    .where(and(eq(r.id, id), repositoryVisibleTo(viewer)))
    .limit(1);
  if (!row) throw notFound("Repository");
  return row;
}

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  q: z.string().trim().max(100).optional(),
  /** "blocked" = has open critical findings, "attention" = open high findings. */
  status: z.enum(["all", "blocked", "attention", "clean"]).default("all"),
  /** The viewer's zone, for the calendar days of the small trend line. */
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
  /** One or more grades, comma-separated: "F,E". "none" is a repository that was never scanned (ADR 0018). */
  grade: z
    .string()
    .optional()
    .transform((value, ctx) => {
      if (value === undefined || value === "") return undefined;
      const parsed = parseGradeFilter(value);
      if (!parsed) {
        ctx.addIssue({ code: "custom", message: "Use grades A to F, or none, separated by commas" });
        return z.NEVER;
      }
      return parsed;
    }),
  /** Without a sort the list is by name. */
  sort: z.enum(["name", "grade", "critical", "high", "medium", "lastScan"]).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

const openOf = (severity: string) =>
  sql`(select count(*)::int from ${schema.finding} f where f.repository_id = ${r.id} and f.state = 'open' and f.severity = ${severity})`;

/** The grade rank of a repository (ADR 0018): 0 (A) to 5 (F), -1 when it was never scanned successfully. */
const gradeRank = gradeRankSql(REPOSITORY_FINDINGS, sql`${r.id}`, sql`${r.lastScanId} is not null`);

/** Columns the list can be sorted by (table headers). */
const SORTS: Record<NonNullable<z.infer<typeof listQuery>["sort"]>, SortOption> = {
  name: { keys: [r.name], parse: [parseText], dir: "asc" },
  // Worst first; repositories that were never scanned come last.
  grade: { keys: [gradeRank], parse: [parseNumber], dir: "desc" },
  critical: { keys: [openOf("critical")], parse: [parseNumber], dir: "desc" },
  high: { keys: [openOf("high")], parse: [parseNumber], dir: "desc" },
  medium: { keys: [openOf("medium")], parse: [parseNumber], dir: "desc" },
  lastScan: {
    keys: [sql`coalesce(date_trunc('milliseconds', ${r.lastScanAt}), 'epoch'::timestamptz)`],
    parse: [parseDate],
    dir: "desc",
  },
};

const createBody = z.object({
  url: repoUrlSchema,
  name: z.string().trim().min(1).max(120).optional(),
  branch: z
    .string()
    .trim()
    .max(200)
    .regex(/^[A-Za-z0-9][\w./-]*$/, "Use a plain branch name")
    .optional(),
  auth: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("none") }),
    z.object({ kind: z.literal("https-token"), token: z.string().min(8).max(500) }),
    /** The key pair is generated here; the private half never leaves the vault. */
    z.object({ kind: z.literal("ssh-deploy-key") }),
  ]),
});

/**
 * Several HTTPS repositories at once, all with the same access: public, or one token that
 * can read all of them. SSH repositories are added one at a time, because every one gets
 * its own deploy key.
 */
export const BULK_LIMIT = 50;
const bulkBody = z.object({
  urls: z.array(repoUrlSchema).min(1).max(BULK_LIMIT),
  branch: createBody.shape.branch,
  auth: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("none") }),
    z.object({ kind: z.literal("https-token"), token: z.string().min(8).max(500) }),
  ]),
});

/** Who sees the repository (ADR 0030), as the caller may know it. */
function sharing(row: RepoRow, userId: string) {
  return {
    visibility: row.visibility,
    mine: row.ownerUserId === userId,
    shareRequested: row.visibility === "private" && row.shareRequestedAt !== null,
  };
}

/** Pinned SSH host keys as shown to the user, so they can compare them with the forge's published fingerprints. */
function hostKeys(row: RepoRow) {
  if (!row.sshKnownHosts) return null;
  return {
    pinnedAt: row.sshKnownHostsPinnedAt,
    keys: (parseKnownHosts(row.sshKnownHosts) ?? []).map((h) => ({
      host: h.host,
      type: h.type,
      fingerprint: fingerprint(h.key),
    })),
  };
}

/** Seals a credential to the vault and stores it; returns the secret's id. */
async function storeSecret(
  organizationId: string,
  createdBy: string,
  purpose: "ssh-private-key" | "forge-token",
  plaintext: string,
): Promise<string> {
  const secretId = newId("sec");
  const sealed = seal(plaintext, { organizationId, recordId: secretId, purpose }, vaultPublicKey);
  await db.insert(schema.secret).values({
    id: secretId,
    organizationId,
    purpose,
    sealed,
    vaultKeyId: vaultPublicKey.id,
    createdBy,
  });
  return secretId;
}

function nameFromUrl(url: string): string {
  const last = url
    .replace(/\.git$/, "")
    .split(/[/:]/)
    .filter(Boolean)
    .pop();
  return last ?? url;
}

/** Open findings per repository and severity, for the rows on one page. */
async function openCounts(organizationId: string, repoIds: string[]) {
  if (repoIds.length === 0) return new Map<string, Record<string, number>>();
  const rows = await db
    .select({ repositoryId: schema.finding.repositoryId, severity: schema.finding.severity, n: count() })
    .from(schema.finding)
    .where(
      and(
        eq(schema.finding.organizationId, organizationId),
        eq(schema.finding.state, "open"),
        inArray(schema.finding.repositoryId, repoIds),
      ),
    )
    .groupBy(schema.finding.repositoryId, schema.finding.severity);
  const map = new Map<string, Record<string, number>>();
  for (const row of rows) {
    const entry = map.get(row.repositoryId) ?? {};
    entry[row.severity] = row.n;
    map.set(row.repositoryId, entry);
  }
  return map;
}

function statusFilter(status: string) {
  const hasOpen = (severity: string) =>
    sql`exists (select 1 from ${schema.finding} f where f.repository_id = ${r.id} and f.state = 'open' and f.severity = ${severity})`;
  if (status === "blocked") return hasOpen("critical");
  if (status === "attention") return sql`(${hasOpen("high")} and not ${hasOpen("critical")})`;
  if (status === "clean")
    return sql`not exists (select 1 from ${schema.finding} f where f.repository_id = ${r.id} and f.state = 'open' and f.severity in ('critical','high'))`;
  return undefined;
}

/**
 * The most recent scan of each repository in any state, so queued and running scans show up
 * (repository.last_scan_id only moves on success). Uses scan_repo_created_idx.
 */
async function latestScans(repoIds: string[]) {
  const scans = repoIds.length
    ? await db
        .selectDistinctOn([schema.scan.repositoryId], {
          repositoryId: schema.scan.repositoryId,
          id: schema.scan.id,
          state: schema.scan.state,
          finishedAt: schema.scan.finishedAt,
          error: schema.scan.error,
        })
        .from(schema.scan)
        // Checks of other refs (pull requests) are not the repository's state.
        .where(and(inArray(schema.scan.repositoryId, repoIds), isNull(schema.scan.ref)))
        .orderBy(schema.scan.repositoryId, desc(schema.scan.createdAt))
    : [];
  return new Map(scans.map(({ repositoryId, ...s }) => [repositoryId, s]));
}

/** Grade fields of the given repositories (ADR 0018). */
async function gradesOf(
  organizationId: string,
  rows: { id: string; lastScanId: string | null }[],
  latestScan: Awaited<ReturnType<typeof latestScans>>,
) {
  return gradeFieldsOf(
    db,
    REPOSITORY_FINDINGS,
    organizationId,
    rows.map((row) => ({
      id: row.id,
      scanned: row.lastScanId !== null,
      failed: latestScan.get(row.id)?.state === "failed",
    })),
  );
}

export const repositoryRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const filters = and(
      repositoryVisibleTo(actor),
      input.q ? ilike(r.name, `%${input.q.replace(/[%_\\]/g, "\\$&")}%`) : undefined,
      statusFilter(input.status),
      input.grade ? gradeFilterSql(gradeRank, input.grade) : undefined,
    );
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, r.id) : null;
    const activeSpec = (sorted?.spec ?? spec) as KeysetSpec<
      RepoRow & { sortKeys?: (string | number | Date)[] }
    >;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({ ...getTableColumns(r), sortKeys: sorted ? sorted.select : sql<null>`null` })
        .from(r)
        .where(and(filters, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(r).where(filters),
    ]);
    const page = toPage(
      activeSpec,
      q,
      rows as (RepoRow & { sortKeys?: (string | number | Date)[] })[],
      totalRow[0]?.n ?? 0,
      input.pageSize,
      Boolean(input.cursor),
      (row) => row,
    );
    const counts = await openCounts(
      actor.organizationId,
      page.items.map((x) => x.id),
    );
    const repoIds = page.items.map((x) => x.id);
    const latestScan = await latestScans(repoIds);
    // Scanners of the last successful scan, and open findings over the last 14 days.
    const lastScanIds = page.items.flatMap((x) => (x.lastScanId ? [x.lastScanId] : []));
    const [scanners, trends] = await Promise.all([
      lastScanIds.length
        ? db
            .select({ id: schema.scan.id, versions: schema.scan.scannerVersions })
            .from(schema.scan)
            .where(inArray(schema.scan.id, lastScanIds))
        : [],
      openTotalsByRepository(db, {
        organizationId: actor.organizationId,
        timeZone: input.tz,
        repositoryIds: repoIds,
        days: 14,
      }),
    ]);
    const scannersOf = new Map(scanners.map((s) => [s.id, Object.keys(s.versions ?? {}).sort()]));
    const grades = await gradesOf(actor.organizationId, page.items, latestScan);
    return c.json({
      ...page,
      items: page.items.map((row) => ({
        id: row.id,
        name: row.name,
        url: row.url,
        branch: row.branch,
        authKind: row.authKind,
        deployPublicKey: row.deployPublicKey,
        sshHostKeys: hostKeys(row),
        ...sharing(row, actor.userId),
        lastScanAt: row.lastScanAt,
        lastScan: latestScan.get(row.id) ?? null,
        open: counts.get(row.id) ?? {},
        scanners: (row.lastScanId && scannersOf.get(row.lastScanId)) || [],
        trend: trends.get(row.id) ?? [],
        ...grades.get(row.id),
      })),
    });
  })
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = createBody.parse(await c.req.json());
    if (input.auth.kind === "https-token" && isSshRepoUrl(input.url)) {
      throw new ProblemError(422, "auth-mismatch", "A token needs an https:// repository URL");
    }
    if (input.auth.kind === "ssh-deploy-key" && !isSshRepoUrl(input.url)) {
      throw new ProblemError(422, "auth-mismatch", "A deploy key needs an SSH repository URL");
    }
    if (input.auth.kind === "none" && isSshRepoUrl(input.url)) {
      throw new ProblemError(422, "auth-mismatch", "An SSH repository needs a deploy key");
    }
    const [existing] = await db
      .select({ id: r.id })
      .from(r)
      .where(and(eq(r.organizationId, actor.organizationId), eq(r.url, input.url)))
      .limit(1);
    if (existing) throw new ProblemError(409, "duplicate", "This repository is already connected");

    const repositoryId = newId("repo");
    let secretId: string | null = null;
    let deployPublicKey: string | null = null;
    if (input.auth.kind === "ssh-deploy-key") {
      const key = generateDeployKey(`garnetops-${repositoryId}`);
      secretId = await storeSecret(actor.organizationId, actor.userId, "ssh-private-key", key.privateKey);
      deployPublicKey = key.publicKey;
    } else if (input.auth.kind === "https-token") {
      secretId = await storeSecret(actor.organizationId, actor.userId, "forge-token", input.auth.token);
    }
    await db.insert(r).values({
      id: repositoryId,
      organizationId: actor.organizationId,
      name: input.name ?? nameFromUrl(input.url),
      url: input.url,
      branch: input.branch ?? null,
      authKind: input.auth.kind,
      secretId,
      deployPublicKey,
      ownerUserId: actor.userId,
    });
    await audit(
      actor,
      "repository.created",
      { type: "repository", id: repositoryId },
      { url: input.url, auth: input.auth.kind },
    );
    // A new deploy key is not on the forge yet; the user adds it first and then starts the scan.
    if (deployPublicKey) return c.json({ id: repositoryId, scanId: null, deployPublicKey }, 201);
    const scanId = await queueScan(actor.organizationId, repositoryId, actor.userId, "manual");
    return c.json({ id: repositoryId, scanId, deployPublicKey: null }, 201);
  })
  .post("/bulk", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = bulkBody.parse(await c.req.json());
    const urls = [...new Set(input.urls)];
    const ssh = urls.filter(isSshRepoUrl);
    if (ssh.length > 0) {
      throw new ProblemError(422, "auth-mismatch", "Add SSH repositories one at a time", undefined, {
        urls: ssh,
      });
    }
    const existing = await db
      .select({ url: r.url })
      .from(r)
      .where(and(eq(r.organizationId, actor.organizationId), inArray(r.url, urls)));
    const known = new Set(existing.map((x) => x.url));
    const fresh = urls.filter((url) => !known.has(url));

    // Every repository gets its own sealed copy of the token, so removing one never
    // affects another, exactly as if they had been added one by one.
    const created: { id: string; name: string; url: string; scanId: string }[] = [];
    for (const url of fresh) {
      const id = newId("repo");
      const secretId =
        input.auth.kind === "https-token"
          ? await storeSecret(actor.organizationId, actor.userId, "forge-token", input.auth.token)
          : null;
      const name = nameFromUrl(url);
      await db.insert(r).values({
        id,
        organizationId: actor.organizationId,
        name,
        url,
        branch: input.branch ?? null,
        authKind: input.auth.kind,
        secretId,
        deployPublicKey: null,
        ownerUserId: actor.userId,
      });
      await audit(
        actor,
        "repository.created",
        { type: "repository", id },
        { url, auth: input.auth.kind, bulk: true },
      );
      const scanId = await queueScan(actor.organizationId, id, actor.userId, "manual");
      created.push({ id, name, url, scanId });
    }
    const skipped = urls
      .filter((url) => known.has(url))
      .map((url) => ({ url, reason: "duplicate" as const }));
    return c.json({ created, skipped }, 201);
  })
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = countsQuery.parse(c.req.query());
    const where = and(
      repositoryVisibleTo(actor),
      input.q ? ilike(r.name, `%${input.q.replace(/[%_\\]/g, "\\$&")}%`) : undefined,
    );
    const counts = await Promise.all(
      (["all", "blocked", "attention", "clean"] as const).map(async (status) => {
        const [row] = await db
          .select({ n: count() })
          .from(r)
          .where(and(where, statusFilter(status)));
        return [status, row?.n ?? 0] as const;
      }),
    );
    return c.json(Object.fromEntries(counts));
  })
  /** How many repositories have each grade (ADR 0018), for the grade filter and the overview. */
  .get("/grades", async (c) => {
    const actor = c.get("actor");
    const input = countsQuery.parse(c.req.query());
    const where = and(
      repositoryVisibleTo(actor),
      input.q ? ilike(r.name, `%${input.q.replace(/[%_\\]/g, "\\$&")}%`) : undefined,
    );
    return c.json(await gradeDistribution(db, gradeRank, sql`${r}`, where ?? sql`true`));
  })
  .post("/scan-all", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    // Repositories with a queued or running scan keep it; every other one gets a new scan.
    const idle = await db
      .select({ id: r.id })
      .from(r)
      .where(
        and(
          repositoryVisibleTo(actor),
          sql`not exists (select 1 from ${schema.scan} s where s.repository_id = ${r.id} and s.state in ('queued', 'running'))`,
        ),
      );
    for (const repo of idle) {
      const scanId = await queueScan(actor.organizationId, repo.id, actor.userId, "manual");
      await audit(actor, "scan.requested", { type: "repository", id: repo.id }, { scanId, scope: "all" });
    }
    return c.json({ queued: idle.length }, 202);
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select()
      .from(r)
      .where(and(eq(r.id, c.req.param("id")), repositoryVisibleTo(actor)))
      .limit(1);
    if (!row) throw notFound("Repository");
    const [counts, states, [lastScan], latestScan] = await Promise.all([
      openCounts(actor.organizationId, [row.id]),
      db
        .select({ state: schema.finding.state, n: count() })
        .from(schema.finding)
        .where(eq(schema.finding.repositoryId, row.id))
        .groupBy(schema.finding.state),
      db
        .select({
          id: schema.scan.id,
          state: schema.scan.state,
          finishedAt: schema.scan.finishedAt,
          error: schema.scan.error,
        })
        .from(schema.scan)
        .where(eq(schema.scan.repositoryId, row.id))
        .orderBy(desc(schema.scan.createdAt), desc(schema.scan.id))
        .limit(1),
      latestScans([row.id]),
    ]);
    const grades = await gradesOf(actor.organizationId, [row], latestScan);
    return c.json({
      id: row.id,
      name: row.name,
      url: row.url,
      branch: row.branch,
      authKind: row.authKind,
      deployPublicKey: row.deployPublicKey,
      sshHostKeys: hostKeys(row),
      ...sharing(row, actor.userId),
      createdAt: row.createdAt,
      lastScanAt: row.lastScanAt,
      lastScanId: row.lastScanId,
      lastScan: lastScan ?? null,
      open: counts.get(row.id) ?? {},
      states: Object.fromEntries(states.map((s) => [s.state, s.n])),
      writeAccess: await writeAccessSummary(row.id, row.url),
      ...grades.get(row.id),
    });
  })
  /** Open findings of this repository per calendar day of the viewer (ADR 0005). */
  .get("/:id/trend", async (c) => {
    const actor = c.get("actor");
    const { tz } = trendQuery.parse(c.req.query());
    const repo = await ownRepository(actor, c.req.param("id"));
    const days = await openFindingsTrend(db, {
      organizationId: actor.organizationId,
      userId: actor.userId,
      repositoryId: repo.id,
      timeZone: tz,
    });
    return c.json({ timeZone: tz, days });
  })
  /**
   * Patch history: findings that were resolved, newest first, with the version the
   * repository has now (from its latest package inventory), so "what was fixed when and
   * how" can be read off one list.
   */
  .get("/:id/patches", async (c) => {
    const actor = c.get("actor");
    const input = pageQuery.parse(c.req.query());
    const repo = await ownRepository(actor, c.req.param("id"));
    const f = schema.finding;
    const where = and(eq(f.repositoryId, repo.id), eq(f.state, "resolved"));
    const q = keysetQuery(patchSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          id: f.id,
          resolvedAt: f.resolvedAt,
          severity: f.severity,
          vulnerabilityId: f.vulnerabilityId,
          packageName: f.packageName,
          packageType: f.packageType,
          version: f.packageVersion,
          fixedIn: f.fixedIn,
          firstSeenAt: f.firstSeenAt,
          // Versions of the package in the latest inventory; empty: it was removed.
          currentVersions: sql<string[]>`coalesce((
            select array_agg(distinct p.version order by p.version)
            from ${schema.repositoryPackage} p
            where p.repository_id = ${f.repositoryId} and p.name = ${f.packageName} and p.type = ${f.packageType}
          ), '{}')`,
        })
        .from(f)
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(f).where(where),
    ]);
    return c.json(
      toPage(
        patchSpec,
        q,
        rows as PatchRow[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        (row) => row,
      ),
    );
  })
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    const id = c.req.param("id");
    // Admins remove any repository they see; a member removes their own private one (ADR 0030).
    const [target] = await db
      .select({ visibility: r.visibility, ownerUserId: r.ownerUserId })
      .from(r)
      .where(and(eq(r.id, id), repositoryVisibleTo(actor)))
      .limit(1);
    if (!target) throw notFound("Repository");
    if (!(target.visibility === "private" && target.ownerUserId === actor.userId))
      requireRole(actor, "admin");
    // The write token (fix pull requests, ADR 0014) is a secret of its own; it goes with the repository.
    const [writeToken] = await db
      .select({ secretId: schema.repositoryWriteAccess.secretId })
      .from(schema.repositoryWriteAccess)
      .where(
        and(
          eq(schema.repositoryWriteAccess.repositoryId, id),
          eq(schema.repositoryWriteAccess.organizationId, actor.organizationId),
        ),
      )
      .limit(1);
    const [row] = await db
      .delete(r)
      .where(and(eq(r.id, id), repositoryVisibleTo(actor)))
      .returning({ secretId: r.secretId, url: r.url, visibility: r.visibility });
    if (!row) throw notFound("Repository");
    if (row.secretId) await db.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    if (writeToken) await db.delete(schema.secret).where(eq(schema.secret.id, writeToken.secretId));
    await audit(
      actor,
      "repository.deleted",
      { type: "repository", id },
      { url: row.url, visibility: row.visibility },
    );
    return c.body(null, 204);
  })
  .delete("/:id/ssh-host-keys", async (c) => {
    // Forgetting a pinned host key re-opens trust on first use; only admins may, and it is audited.
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const id = c.req.param("id");
    const [before] = await db
      .select()
      .from(r)
      .where(and(eq(r.id, id), repositoryVisibleTo(actor)))
      .limit(1);
    if (!before) throw notFound("Repository");
    if (!before.sshKnownHosts) return c.body(null, 204);
    await db
      .update(r)
      .set({ sshKnownHosts: null, sshKnownHostsPinnedAt: null, updatedAt: new Date() })
      .where(eq(r.id, id));
    await audit(
      actor,
      "repository.ssh_host_keys_cleared",
      { type: "repository", id },
      {
        url: before.url,
        fingerprints: hostKeys(before)?.keys.map((k) => k.fingerprint) ?? [],
      },
    );
    return c.body(null, 204);
  })
  .route("/:id/write-access", writeAccessRoutes)
  .route("/:id/renovate-config", renovateRoutes)
  .post("/:id/scans", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const id = c.req.param("id");
    const [row] = await db
      .select({ id: r.id })
      .from(r)
      .where(and(eq(r.id, id), repositoryVisibleTo(actor)))
      .limit(1);
    if (!row) throw notFound("Repository");
    const [active] = await db
      .select({ id: schema.scan.id })
      .from(schema.scan)
      .where(and(eq(schema.scan.repositoryId, id), inArray(schema.scan.state, ["queued", "running"])))
      .limit(1);
    if (active) return c.json({ scanId: active.id, alreadyQueued: true }, 200);
    const scanId = await queueScan(actor.organizationId, id, actor.userId, "manual");
    await audit(actor, "scan.requested", { type: "repository", id }, { scanId });
    return c.json({ scanId }, 202);
  });

export async function queueScan(
  organizationId: string,
  repositoryId: string,
  requestedBy: string | null,
  trigger: "manual" | "schedule" | "webhook" | "ci",
  /** Gate checks of another ref (ADR 0008): scanned on their own, never changing the repository's findings. */
  check: { ref: string | null; expectedSha: string | null } = { ref: null, expectedSha: null },
): Promise<string> {
  const scanId = newId("scan");
  await db.insert(schema.scan).values({
    id: scanId,
    organizationId,
    repositoryId,
    state: "queued",
    trigger,
    requestedBy,
    ref: check.ref,
    expectedSha: check.expectedSha,
    // Millisecond precision on purpose: this column is a pagination key (see lib/paginate.ts).
    createdAt: new Date(),
  });
  await boss.send(
    QUEUES.scanRepository,
    { scanId },
    // One job per repository and ref at a time; a check of a pull request does not wait for the nightly scan.
    {
      singletonKey: check.ref ? `${repositoryId}@${check.ref}@${check.expectedSha ?? ""}` : repositoryId,
      retryLimit: 1,
      expireInSeconds: 1800,
    },
  );
  return scanId;
}
