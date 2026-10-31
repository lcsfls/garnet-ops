/**
 * Fix proposals, the per-repository write credential and fix pull requests (ADR 0014).
 *
 * The API never talks to a forge and never opens the write token: it seals it (vault purpose
 * "forge-write-token"), computes the proposals from our own data, validates a request and
 * queues it. The worker opens the token and opens the pull request.
 */
import { newId, SEVERITIES } from "@garnetops/core";
import {
  ACTIVE_FIX_PR_STATES,
  apiBaseProblem,
  branchName,
  buildProposals,
  connectionCoversRepository,
  connectionWriteProblem,
  defaultApiBase,
  detectForge,
  FIX_PR_STATES,
  type FindingFact,
  FORGE_KINDS,
  isProposalKey,
  type ManifestFact,
  type Proposal,
  parseRepoLocation,
  renovateConfig,
} from "@garnetops/core/fix-prs";
import { isSafePackageName, type ManifestKind } from "@garnetops/core/manifests";
import { decodeCursor, encodeCursor, pageSizeSchema } from "@garnetops/core/pagination";
import { seal } from "@garnetops/core/vault";
import { repositoryVisibleTo, schema, type Viewer, visibleRepository } from "@garnetops/db";
import { and, desc, eq, getTableColumns, inArray, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { type KeysetSpec, keysetQuery, parseDate, parseText, toPage } from "../lib/paginate.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

/* -------------------------------------------------------------------------- */
/* Proposals                                                                   */
/* -------------------------------------------------------------------------- */

type PrRow = typeof schema.fixPr.$inferSelect;
type AccessRow = typeof schema.repositoryWriteAccess.$inferSelect;

/** Every proposal of the organisation (or one repository) from the open findings and the last manifests. */
async function loadProposals(viewer: Viewer, repositoryId?: string) {
  const { organizationId } = viewer;
  const f = schema.finding;
  const repositories = await db
    .select({ id: schema.repository.id, name: schema.repository.name, url: schema.repository.url })
    .from(schema.repository)
    .where(
      and(
        repositoryVisibleTo(viewer),
        // Repositories set aside get no fix proposals in the organisation's list (ADR 0043).
        repositoryId ? eq(schema.repository.id, repositoryId) : isNull(schema.repository.inactiveAt),
      ),
    );
  if (repositories.length === 0)
    return { proposals: [], repositories: new Map<string, (typeof repositories)[number]>() };
  const ids = repositories.map((r) => r.id);
  const [findings, manifests] = await Promise.all([
    db
      .select({
        id: f.id,
        repositoryId: f.repositoryId,
        vulnerabilityId: f.vulnerabilityId,
        severity: f.severity,
        severityRank: f.severityRank,
        packageName: f.packageName,
        packageType: f.packageType,
        packageVersion: f.packageVersion,
        fixedIn: f.fixedIn,
        locations: f.locations,
      })
      .from(f)
      .where(
        and(
          eq(f.organizationId, organizationId),
          eq(f.state, "open"),
          inArray(f.repositoryId, ids),
          sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0`,
        ),
      ),
    db
      .select()
      .from(schema.repositoryManifest)
      .where(
        and(
          eq(schema.repositoryManifest.organizationId, organizationId),
          inArray(schema.repositoryManifest.repositoryId, ids),
        ),
      ),
  ]);
  const findingsOf = new Map<string, FindingFact[]>();
  for (const row of findings) {
    const list = findingsOf.get(row.repositoryId) ?? [];
    list.push({ ...row, fixedIn: row.fixedIn ?? [], locations: row.locations ?? [] });
    findingsOf.set(row.repositoryId, list);
  }
  const manifestsOf = new Map<string, ManifestFact[]>();
  for (const row of manifests) {
    const list = manifestsOf.get(row.repositoryId) ?? [];
    list.push({
      path: row.path,
      kind: row.kind as ManifestKind,
      blobSha: row.blobSha,
      dependencies: row.dependencies as never,
    });
    manifestsOf.set(row.repositoryId, list);
  }
  const proposals: Proposal[] = [];
  for (const repo of repositories) {
    proposals.push(
      ...buildProposals({
        repositoryId: repo.id,
        findings: findingsOf.get(repo.id) ?? [],
        manifests: manifestsOf.get(repo.id) ?? [],
      }),
    );
  }
  return { proposals, repositories: new Map(repositories.map((r) => [r.id, r])) };
}

const ACTIVE = new Set<string>(ACTIVE_FIX_PR_STATES);

/** Per proposal key: the live pull request if there is one, else the newest one. */
async function pullRequestsByKey(viewer: Viewer, repositoryId?: string) {
  const rows = await db
    .select()
    .from(schema.fixPr)
    .where(
      and(
        eq(schema.fixPr.organizationId, viewer.organizationId),
        visibleRepository(schema.fixPr.repositoryId, viewer),
        repositoryId ? eq(schema.fixPr.repositoryId, repositoryId) : undefined,
      ),
    )
    .orderBy(desc(schema.fixPr.createdAt))
    .limit(5000);
  const byKey = new Map<string, PrRow>();
  for (const row of rows) {
    const id = `${row.repositoryId}|${row.proposalKey}`;
    const current = byKey.get(id);
    if (!current || (!ACTIVE.has(current.state) && ACTIVE.has(row.state))) byKey.set(id, row);
  }
  return byKey;
}

async function requesterNames(rows: PrRow[]) {
  const ids = [...new Set(rows.flatMap((r) => (r.requestedBy ? [r.requestedBy] : [])))];
  if (ids.length === 0) return new Map<string, string>();
  const users = await db
    .select({ id: schema.user.id, name: schema.user.name })
    .from(schema.user)
    .where(inArray(schema.user.id, ids));
  return new Map(users.map((u) => [u.id, u.name]));
}

const prDto = (row: PrRow, names: Map<string, string>) => ({
  id: row.id,
  state: row.state,
  reason: row.reason,
  number: row.prNumber,
  url: row.prUrl,
  from: row.fromVersion,
  to: row.toVersion,
  branch: row.branch,
  requestedBy: row.requestedBy ? (names.get(row.requestedBy) ?? null) : null,
  /** "connection": opened in the requester's own name (ADR 0039); "repository": with the repository's write token. */
  via: row.via,
  createdAt: row.createdAt,
  openedAt: row.openedAt,
  closedAt: row.closedAt,
  lastCheckedAt: row.lastCheckedAt,
});

/** The AI suggestion of the newest finished triage among the proposal's findings: read-only text, never used for the version. */
async function aiSuggestions(organizationId: string, findingIds: string[]) {
  if (findingIds.length === 0) return new Map<string, Suggestion>();
  const rows = await db
    .select({
      findingId: schema.chatThread.findingId,
      structured: schema.chatMessage.structured,
      createdAt: schema.chatMessage.createdAt,
    })
    .from(schema.chatMessage)
    .innerJoin(schema.chatThread, eq(schema.chatThread.id, schema.chatMessage.threadId))
    .where(
      and(
        eq(schema.chatThread.organizationId, organizationId),
        inArray(schema.chatThread.findingId, findingIds),
        eq(schema.chatMessage.kind, "triage"),
        eq(schema.chatMessage.status, "complete"),
        sql`${schema.chatMessage.structured} is not null`,
      ),
    )
    .orderBy(desc(schema.chatMessage.createdAt));
  const out = new Map<string, Suggestion>();
  for (const row of rows) {
    const s = row.structured ?? {};
    if (typeof s.summary !== "string") continue;
    out.set(row.findingId, {
      findingId: row.findingId,
      summary: s.summary.slice(0, 700),
      recommendation: typeof s.recommendation === "string" ? s.recommendation.slice(0, 900) : "",
      confidence: s.confidence === "high" || s.confidence === "medium" ? s.confidence : "low",
      upgradeTo:
        typeof s.upgradeTo === "string" && /^[0-9A-Za-z.!+_-]{1,100}$/.test(s.upgradeTo) ? s.upgradeTo : null,
    });
  }
  return out;
}

interface Suggestion {
  findingId: string;
  summary: string;
  recommendation: string;
  confidence: "low" | "medium" | "high";
  upgradeTo: string | null;
}

/* ---- list, filter, sort, cursor ---- */

const csv = <T extends string>(values: readonly T[]) =>
  z
    .string()
    .optional()
    .transform((s, ctx) => {
      if (!s) return [] as T[];
      const parts = s.split(",").filter(Boolean);
      for (const p of parts) {
        if (!(values as readonly string[]).includes(p)) {
          ctx.addIssue({ code: "custom", message: `Unknown value: ${p}` });
          return z.NEVER;
        }
      }
      return parts as T[];
    });

const SORTS = ["severity", "package", "repository", "vulnerabilities", "ecosystem", "status"] as const;
const PR_FILTERS = ["all", "none", "open", "merged", "closed", "failed"] as const;
const ECOSYSTEM_FILTERS = ["npm", "pypi", "go", "cargo", "composer", "other"] as const;

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  repositoryId: z.string().max(40).optional(),
  q: z.string().trim().max(120).optional(),
  severity: csv(SEVERITIES),
  ecosystem: csv(ECOSYSTEM_FILTERS),
  /** "edit": GarnetOps can open a pull request; "manual": a person has to act. */
  action: z.enum(["all", "edit", "manual"]).default("all"),
  pr: z.enum(PR_FILTERS).default("all"),
  sort: z.enum(SORTS).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

type Row = Proposal & {
  repositoryName: string;
  pr: PrRow | null;
  write: AccessRow | null;
};

const pad = (n: number, width: number) =>
  String(Math.max(0, Math.min(n, 10 ** width - 1))).padStart(width, "0");
const prRank = (row: Row) =>
  row.pr ? ({ open: 1, queued: 2, running: 2, failed: 3, merged: 4, closed: 5 }[row.pr.state] ?? 6) : 0;

/** Text sort keys: compared as strings, so one comparison works for every column. The natural direction is ascending. */
const SORT_KEYS: Record<(typeof SORTS)[number], (row: Row) => string> = {
  severity: (r) =>
    `${pad(9 - r.severityRank, 1)}${pad(999 - r.vulnerabilityIds.length, 3)}${r.packageName.toLowerCase()}`,
  package: (r) => `${r.packageName.toLowerCase()}\u0000${r.repositoryName.toLowerCase()}`,
  repository: (r) => `${r.repositoryName.toLowerCase()}\u0000${r.packageName.toLowerCase()}`,
  vulnerabilities: (r) => `${pad(999 - r.vulnerabilityIds.length, 3)}${r.packageName.toLowerCase()}`,
  ecosystem: (r) => `${r.packageType}\u0000${r.packageName.toLowerCase()}`,
  status: (r) => `${prRank(r)}${r.action === "edit" ? "0" : "1"}${r.packageName.toLowerCase()}`,
};

function matches(row: Row, input: z.infer<typeof listQuery>, skip: "action" | null = null): boolean {
  if (input.severity.length && !input.severity.includes(row.severity as never)) return false;
  if (input.ecosystem.length) {
    const eco = row.ecosystem ?? "other";
    if (!input.ecosystem.includes(eco)) return false;
  }
  if (skip !== "action" && input.action !== "all" && row.action !== input.action) return false;
  if (input.pr !== "all") {
    const state = row.pr?.state ?? "none";
    const group = state === "queued" || state === "running" ? "open" : state;
    if (group !== input.pr) return false;
  }
  if (input.q) {
    const q = input.q.toLowerCase();
    const hit =
      row.packageName.toLowerCase().includes(q) ||
      row.vulnerabilityIds.some((id) => id.toLowerCase().includes(q)) ||
      (row.manifestPath ?? "").toLowerCase().includes(q) ||
      row.repositoryName.toLowerCase().includes(q);
    if (!hit) return false;
  }
  return true;
}

/** One page of an in-memory list, with the same cursors as every SQL-backed list. */
function pageOf<T extends { key: string }>(
  rows: T[],
  sortKey: (row: T) => string,
  dir: "asc" | "desc",
  cursor: string | undefined,
  pageSize: number,
) {
  const sign = dir === "asc" ? 1 : -1;
  type Keyed = { k: string; id: string; row: T };
  /** Position of a row relative to a boundary in the list's own direction: negative before, positive after. */
  const compare = (a: { k: string; id: string }, b: { k: string; id: string }) =>
    sign * (a.k < b.k ? -1 : a.k > b.k ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const sorted: Keyed[] = rows.map((row) => ({ row, k: sortKey(row), id: row.key })).sort(compare);
  const c = decodeCursor(cursor);
  let start = 0;
  let end = pageSize;
  if (c) {
    const boundary = { k: String(c.k), id: c.id };
    if (c.d === "a") {
      start = sorted.findIndex((x) => compare(x, boundary) > 0);
      if (start < 0) start = sorted.length;
      end = start + pageSize;
    } else {
      const at = sorted.findIndex((x) => compare(x, boundary) >= 0);
      end = at < 0 ? sorted.length : at;
      start = Math.max(0, end - pageSize);
    }
  }
  const slice = sorted.slice(start, end);
  const make = (x: Keyed | undefined, d: "a" | "b") => (x ? encodeCursor({ k: x.k, id: x.id, d }) : null);
  return {
    items: slice.map((x) => x.row),
    total: sorted.length,
    pageSize,
    next: end < sorted.length ? make(slice[slice.length - 1], "a") : null,
    prev: start > 0 ? make(slice[0], "b") : null,
  };
}

const writeState = (access: AccessRow | null) =>
  !access ? "off" : access.status === "failed" ? "failed" : "on";

/* ---- the caller's own connections (ADR 0039) ---- */

type ConnectionRow = typeof schema.forgeConnection.$inferSelect;

/** The caller's own forge connections. Never anybody else's, for admins neither. */
async function ownConnections(viewer: Viewer): Promise<ConnectionRow[]> {
  return db
    .select()
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.organizationId, viewer.organizationId),
        eq(schema.forgeConnection.userId, viewer.userId),
      ),
    );
}

/** Why a connection cannot open a pull request now, or null when it can. */
function connectionProblem(
  connection: ConnectionRow,
): "connection-disabled" | "write-scope-missing" | "connection-failed" | null {
  const problem = connectionWriteProblem(connection);
  if (problem) return problem;
  return connection.state === "failed" || !connection.secretId ? "connection-failed" : null;
}

/**
 * The caller's connection for a repository: one on the repository's host that can open pull requests (the most specific
 * forge address first), else the best one that cannot, with its problem, else none.
 */
function connectionFor(
  connections: ConnectionRow[],
  repositoryUrl: string,
): { connection: ConnectionRow; problem: ReturnType<typeof connectionProblem> } | null {
  const covering = connections
    .filter((c) => connectionCoversRepository(c.webBaseUrl, repositoryUrl))
    .map((connection) => ({ connection, problem: connectionProblem(connection) }))
    .sort(
      (a, b) =>
        Number(a.problem !== null) - Number(b.problem !== null) ||
        b.connection.webBaseUrl.length - a.connection.webBaseUrl.length,
    );
  return covering[0] ?? null;
}

const CONNECTION_PROBLEMS = {
  "connection-disabled": [
    "connection-pull-requests-off",
    "Pull requests are not switched on for your connected account on this forge",
  ],
  "write-scope-missing": [
    "connection-write-scope-missing",
    "Your connected account was signed in without write access. Sign in again with write access",
  ],
  "connection-failed": ["connection-failed", "Your connected account on this forge does not work. Check it"],
} as const;

/* -------------------------------------------------------------------------- */
/* Routes                                                                      */
/* -------------------------------------------------------------------------- */

const createBody = z.object({
  repositoryId: z.string().min(1).max(40),
  key: z.string().refine(isProposalKey, "Not a proposal"),
  /**
   * "connection": in the caller's own name, with their connected account on the repository's forge (ADR 0039).
   * "repository" or left out: with the repository's write token (ADR 0014), as before.
   */
  via: z.enum(["connection", "repository"]).optional(),
});

const prListQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  repositoryId: z.string().max(40).optional(),
  state: z.enum(["all", ...FIX_PR_STATES]).default("all"),
});

type PrListRow = PrRow & { repositoryName: string };
const prSpec: KeysetSpec<PrListRow> = {
  keys: [schema.fixPr.createdAt, schema.fixPr.id],
  direction: "desc",
  keyOf: (r) => [r.createdAt, r.id],
  parse: [parseDate, parseText],
};

export const fixRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const [{ proposals, repositories }, prs, access, connections] = await Promise.all([
      loadProposals(actor, input.repositoryId),
      pullRequestsByKey(actor, input.repositoryId),
      db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.organizationId, actor.organizationId)),
      ownConnections(actor),
    ]);
    // Per repository: the caller's own connection that can open a pull request there (ADR 0039).
    const usableConnection = new Map<string, ConnectionRow | null>();
    for (const repo of repositories.values()) {
      const found = connectionFor(connections, repo.url);
      usableConnection.set(repo.id, found && found.problem === null ? found.connection : null);
    }
    const accessOf = new Map(access.map((a) => [a.repositoryId, a]));
    const rows: Row[] = proposals.map((p) => ({
      ...p,
      repositoryName: repositories.get(p.repositoryId)?.name ?? "",
      pr: prs.get(`${p.repositoryId}|${p.key}`) ?? null,
      write: accessOf.get(p.repositoryId) ?? null,
    }));
    const filtered = rows.filter((r) => matches(r, input));
    const sort = input.sort ?? "severity";
    const page = pageOf(filtered, SORT_KEYS[sort], input.dir ?? "asc", input.cursor, input.pageSize);
    const [suggestions, names] = await Promise.all([
      aiSuggestions(
        actor.organizationId,
        page.items.flatMap((r) => r.findingIds),
      ),
      requesterNames(page.items.flatMap((r) => (r.pr ? [r.pr] : []))),
    ]);
    const counts = { all: 0, edit: 0, manual: 0 };
    for (const r of rows) {
      if (!matches(r, input, "action")) continue;
      counts.all++;
      counts[r.action]++;
    }
    return c.json({
      ...page,
      counts,
      items: page.items.map((r) => {
        const suggestion = r.findingIds.map((id) => suggestions.get(id)).find(Boolean) ?? null;
        const live = r.pr && ACTIVE.has(r.pr.state);
        const connection = usableConnection.get(r.repositoryId) ?? null;
        return {
          key: r.key,
          repositoryId: r.repositoryId,
          repositoryName: r.repositoryName,
          ecosystem: r.ecosystem,
          packageType: r.packageType,
          packageName: r.packageName,
          installedVersion: r.installedVersion,
          targetVersion: r.targetVersion,
          majorUpgrade: r.majorUpgrade,
          severity: r.severity,
          vulnerabilityIds: r.vulnerabilityIds,
          unresolvedIds: r.unresolvedIds,
          findingIds: r.findingIds.slice(0, 20),
          manifestPath: r.manifestPath,
          dependency: r.dependency,
          section: r.section,
          dev: r.dev,
          currentSpec: r.currentSpec,
          newSpec: r.newSpec,
          action: r.action,
          reason: r.reason,
          writeAccess: writeState(r.write),
          branch: r.action === "edit" && r.targetVersion ? branchName(r.packageName, r.targetVersion) : null,
          creatable: r.action === "edit" && r.write !== null && r.write.status !== "failed" && !live,
          /** The caller's own connected account that can open this pull request in their name (ADR 0039). */
          connection: connection
            ? { id: connection.id, forgeKind: connection.forgeKind, accountLogin: connection.accountLogin }
            : null,
          creatableViaConnection: r.action === "edit" && connection !== null && !live,
          pr: r.pr ? prDto(r.pr, names) : null,
          aiSuggestion: suggestion,
        };
      }),
    });
  })
  /** Pull requests GarnetOps opened (including merged and closed ones, whose proposals are gone). */
  .get("/prs", async (c) => {
    const actor = c.get("actor");
    const input = prListQuery.parse(c.req.query());
    const where = and(
      eq(schema.fixPr.organizationId, actor.organizationId),
      visibleRepository(schema.fixPr.repositoryId, actor),
      input.repositoryId ? eq(schema.fixPr.repositoryId, input.repositoryId) : undefined,
      input.state === "all" ? undefined : eq(schema.fixPr.state, input.state),
    );
    const q = keysetQuery(prSpec, input.cursor, input.pageSize);
    const [rows, [total]] = await Promise.all([
      db
        .select({ ...getTableColumns(schema.fixPr), repositoryName: schema.repository.name })
        .from(schema.fixPr)
        .innerJoin(schema.repository, eq(schema.repository.id, schema.fixPr.repositoryId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: sql<number>`count(*)::int` }).from(schema.fixPr).where(where),
    ]);
    const names = await requesterNames(rows);
    return c.json(
      toPage(prSpec, q, rows as PrListRow[], total?.n ?? 0, input.pageSize, Boolean(input.cursor), (r) => ({
        ...prDto(r, names),
        repositoryId: r.repositoryId,
        repositoryName: r.repositoryName,
        ecosystem: r.ecosystem,
        packageName: r.packageName,
        manifestPath: r.manifestPath,
        majorUpgrade: r.majorUpgrade,
        severity: r.severity,
        vulnerabilityIds: r.vulnerabilityIds,
      })),
    );
  })
  /**
   * Opens a fix pull request for one proposal. The proposal is computed again here from our own
   * data; the client only names it. Needs a recent sign-in, and either a repository with write
   * access or (`via: "connection"`, ADR 0039) the caller's own connected account on the
   * repository's forge with pull requests switched on. Rate limited and audited. The worker does
   * the rest.
   */
  .post("/prs", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = createBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    await Promise.all([
      rateLimit(`fixpr:user:${actor.userId}`, 10),
      rateLimit(`fixpr:org:${actor.organizationId}`, 100, 3_600_000),
    ]);
    const [repo] = await db
      .select({ id: schema.repository.id, branch: schema.repository.branch, url: schema.repository.url })
      .from(schema.repository)
      .where(and(eq(schema.repository.id, input.repositoryId), repositoryVisibleTo(actor)))
      .limit(1);
    if (!repo) throw notFound("Repository");
    const via = input.via ?? "repository";
    let forge: string;
    let connectionId: string | null = null;
    if (via === "connection") {
      // Only the caller's own connections are looked at: another person's token is never a candidate.
      const found = connectionFor(await ownConnections(actor), repo.url);
      if (!found) {
        throw new ProblemError(
          409,
          "no-connection",
          "You have no connected account on this repository's forge",
        );
      }
      if (found.problem) {
        const [code, detail] = CONNECTION_PROBLEMS[found.problem];
        throw new ProblemError(409, code, detail);
      }
      forge = found.connection.forgeKind;
      connectionId = found.connection.id;
    } else {
      const [access] = await db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id))
        .limit(1);
      if (!access) {
        throw new ProblemError(
          409,
          "write-access-off",
          "Fix pull requests are not switched on for this repository",
        );
      }
      if (access.status === "failed") {
        throw new ProblemError(409, "write-access-failed", "The write token does not work", undefined, {
          reason: access.statusReason,
        });
      }
      forge = access.forgeKind;
    }
    const { proposals } = await loadProposals(actor, repo.id);
    const proposal = proposals.find((p) => p.key === input.key);
    if (!proposal) throw notFound("Proposal");
    if (
      proposal.action !== "edit" ||
      !proposal.ecosystem ||
      !proposal.targetVersion ||
      !proposal.manifestPath ||
      !proposal.manifestBlobSha ||
      !isSafePackageName(proposal.packageName)
    ) {
      throw new ProblemError(422, "not-editable", "GarnetOps cannot change this automatically", undefined, {
        reason: proposal.reason,
      });
    }
    const id = newId("fpr");
    try {
      await db.insert(schema.fixPr).values({
        id,
        organizationId: actor.organizationId,
        repositoryId: repo.id,
        proposalKey: proposal.key,
        ecosystem: proposal.ecosystem,
        packageName: proposal.packageName,
        fromVersion: proposal.installedVersion,
        toVersion: proposal.targetVersion,
        majorUpgrade: proposal.majorUpgrade,
        manifestPath: proposal.manifestPath,
        expectedBlobSha: proposal.manifestBlobSha,
        severity: proposal.severity,
        vulnerabilityIds: proposal.vulnerabilityIds,
        state: "queued",
        requestedBy: actor.userId,
        via,
        connectionId,
      });
    } catch (error) {
      // The unique index on live requests: somebody else asked a moment ago.
      if (
        (error as { cause?: { code?: string }; code?: string }).cause?.code === "23505" ||
        (error as { code?: string }).code === "23505"
      ) {
        throw new ProblemError(
          409,
          "already-open",
          "A pull request for this change is already open or being created",
        );
      }
      throw error;
    }
    await audit(
      actor,
      "fix_pr.created",
      { type: "fix_pr", id },
      {
        repositoryId: repo.id,
        package: proposal.packageName,
        from: proposal.installedVersion,
        to: proposal.targetVersion,
        manifest: proposal.manifestPath,
        major: proposal.majorUpgrade,
        forge,
        via,
        ...(connectionId ? { connection: connectionId } : {}),
      },
    );
    await boss.send(
      QUEUES.fixPrCreate,
      { fixPrId: id },
      { retryLimit: 0, expireInSeconds: 15 * 60, singletonKey: id },
    );
    return c.json({ id }, 202);
  })
  /** Asks the worker to look at the open pull requests on the forge now. */
  .post("/refresh", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    await rateLimit(`fixpr:refresh:${actor.userId}`, 6);
    const body = z
      .object({ repositoryId: z.string().max(40).optional() })
      .parse(await c.req.json().catch(() => ({})));
    if (body.repositoryId) {
      const [repo] = await db
        .select({ id: schema.repository.id })
        .from(schema.repository)
        .where(and(eq(schema.repository.id, body.repositoryId), repositoryVisibleTo(actor)))
        .limit(1);
      if (!repo) throw notFound("Repository");
    }
    await boss.send(
      QUEUES.fixPrRefresh,
      {
        organizationId: actor.organizationId,
        ...(body.repositoryId ? { repositoryId: body.repositoryId } : {}),
      },
      {
        retryLimit: 0,
        expireInSeconds: 600,
        singletonKey: `${actor.organizationId}:${body.repositoryId ?? "all"}`,
      },
    );
    return c.json({ queued: true }, 202);
  });

/* -------------------------------------------------------------------------- */
/* Write access (mounted under /repositories/:id/write-access)                 */
/* -------------------------------------------------------------------------- */

async function ownRepository(viewer: Viewer, id: string) {
  const [row] = await db
    .select({ id: schema.repository.id, url: schema.repository.url, name: schema.repository.name })
    .from(schema.repository)
    .where(and(eq(schema.repository.id, id), repositoryVisibleTo(viewer)))
    .limit(1);
  if (!row) throw notFound("Repository");
  return row;
}

/** What the repository page shows. Never anything about the token itself. */
export async function writeAccessSummary(repositoryId: string, url: string) {
  const [row] = await db
    .select({ access: schema.repositoryWriteAccess, enabledByName: schema.user.name })
    .from(schema.repositoryWriteAccess)
    .leftJoin(schema.user, eq(schema.user.id, schema.repositoryWriteAccess.enabledBy))
    .where(eq(schema.repositoryWriteAccess.repositoryId, repositoryId))
    .limit(1);
  const location = parseRepoLocation(url);
  const suggested = location ? detectForge(location.host) : null;
  return {
    /** The repository address names an owner and a repository on a host, which is what the forge API needs. */
    supported: location !== null,
    suggested: location
      ? { forgeKind: suggested, apiBaseUrl: suggested ? defaultApiBase(suggested, location.host) : null }
      : null,
    enabled: row !== undefined,
    access: row
      ? {
          forgeKind: row.access.forgeKind,
          apiBaseUrl: row.access.apiBaseUrl,
          enabledAt: row.access.enabledAt,
          enabledBy: row.enabledByName,
          status: row.access.status,
          statusReason: row.access.statusReason,
          warning: row.access.warning,
          checkedAt: row.access.checkedAt,
        }
      : null,
  };
}

/** Printable ASCII, no spaces: a token can never carry a line break into a request header. */
const tokenSchema = z
  .string()
  .min(8)
  .max(500)
  .regex(/^[\x21-\x7e]+$/, "A token has no spaces or special characters");

const enableBody = z.object({
  token: tokenSchema,
  forgeKind: z.enum(FORGE_KINDS),
  apiBaseUrl: z.string().trim().max(300).optional(),
});

export const writeAccessRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const repo = await ownRepository(actor, c.req.param("id") as string);
    return c.json(await writeAccessSummary(repo.id, repo.url));
  })
  /** Switches fix pull requests on, or replaces the token. Owners and admins, with a recent sign-in. */
  .put("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const repo = await ownRepository(actor, c.req.param("id") as string);
    const input = enableBody.parse(await c.req.json());
    const location = parseRepoLocation(repo.url);
    if (!location) {
      throw new ProblemError(
        422,
        "unsupported-repository",
        "Fix pull requests need a repository address with an owner and a name on a GitHub, Gitea or Forgejo host",
      );
    }
    const apiBaseUrl = (input.apiBaseUrl || defaultApiBase(input.forgeKind, location.host)).replace(
      /\/+$/,
      "",
    );
    const problem = apiBaseProblem(input.forgeKind, apiBaseUrl);
    if (problem) throw new ProblemError(422, "invalid-api-address", problem);
    requireRecentSignIn(actor);
    await rateLimit(`fixpr:access:${actor.userId}`, 10);

    const secretId = newId("sec");
    const sealed = seal(
      input.token,
      { organizationId: actor.organizationId, recordId: secretId, purpose: "forge-write-token" },
      vaultPublicKey,
    );
    const replaced = await db.transaction(async (tx) => {
      const [existing] = await tx
        .select({ secretId: schema.repositoryWriteAccess.secretId })
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id))
        .limit(1);
      await tx.insert(schema.secret).values({
        id: secretId,
        organizationId: actor.organizationId,
        purpose: "forge-write-token",
        sealed,
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      const values = {
        secretId,
        forgeKind: input.forgeKind,
        apiBaseUrl,
        enabledBy: actor.userId,
        enabledAt: new Date(),
        status: "unchecked" as const,
        statusReason: null,
        warning: null,
        checkedAt: null,
      };
      if (existing) {
        await tx
          .update(schema.repositoryWriteAccess)
          .set(values)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id));
        // The old token is gone for good.
        await tx.delete(schema.secret).where(eq(schema.secret.id, existing.secretId));
      } else {
        await tx
          .insert(schema.repositoryWriteAccess)
          .values({ repositoryId: repo.id, organizationId: actor.organizationId, ...values });
      }
      return Boolean(existing);
    });
    await audit(
      actor,
      replaced ? "fix_pr.write_token_replaced" : "fix_pr.write_access_enabled",
      { type: "repository", id: repo.id },
      { url: repo.url, forge: input.forgeKind, apiUrl: apiBaseUrl },
    );
    await boss.send(QUEUES.fixPrCheck, { repositoryId: repo.id }, { retryLimit: 0, expireInSeconds: 300 });
    return c.json(await writeAccessSummary(repo.id, repo.url));
  })
  /** Asks the worker to check the stored token again. */
  .post("/check", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const repo = await ownRepository(actor, c.req.param("id") as string);
    await rateLimit(`fixpr:check:${actor.userId}`, 10);
    const [access] = await db
      .select({ repositoryId: schema.repositoryWriteAccess.repositoryId })
      .from(schema.repositoryWriteAccess)
      .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id))
      .limit(1);
    if (!access) throw new ProblemError(409, "write-access-off", "Fix pull requests are not switched on");
    await db
      .update(schema.repositoryWriteAccess)
      .set({ status: "unchecked", statusReason: null })
      .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id));
    await boss.send(QUEUES.fixPrCheck, { repositoryId: repo.id }, { retryLimit: 0, expireInSeconds: 300 });
    return c.json({ queued: true }, 202);
  })
  /** Switches fix pull requests off and deletes the sealed token. */
  .delete("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const repo = await ownRepository(actor, c.req.param("id") as string);
    const [row] = await db
      .select({
        secretId: schema.repositoryWriteAccess.secretId,
        forge: schema.repositoryWriteAccess.forgeKind,
      })
      .from(schema.repositoryWriteAccess)
      .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id))
      .limit(1);
    if (!row) return c.body(null, 204);
    // Deleting the secret removes the access row with it (foreign key), so no state is left half off.
    await db.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    await audit(
      actor,
      "fix_pr.write_access_disabled",
      { type: "repository", id: repo.id },
      { url: repo.url, forge: row.forge },
    );
    return c.body(null, 204);
  });

/* -------------------------------------------------------------------------- */
/* Renovate configuration (mounted under /repositories/:id/renovate-config)    */
/* -------------------------------------------------------------------------- */

/** A renovate.json for customers who run their own Renovate. GarnetOps never runs or bundles it. */
export const renovateRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const repo = await ownRepository(actor, c.req.param("id") as string);
  const { proposals } = await loadProposals(actor, repo.id);
  const config = renovateConfig(proposals);
  return c.json({
    packages: (config.packageRules as unknown[]).length,
    json: `${JSON.stringify(config, null, 2)}\n`,
  });
});
