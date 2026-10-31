import { activeRepository, schema, visibleRepository } from "@garnetops/db";
import { and, desc, eq, ilike, inArray, isNull, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { queueScan } from "./repositories.ts";

/**
 * The open pull requests of the repositories a person sees, with the gate result of each head commit (ADR 0032). The
 * worker reads them from the forges; this only reads what it stored, and can ask it to read again or to check a pull
 * request's head like a CI pipeline would.
 */
const pr = schema.pullRequest;
const r = schema.repository;

/** At most this many pull requests in one answer, most recently updated first. */
export const PULL_REQUEST_LIMIT = 500;

const GATE_FILTERS = ["passed", "notes", "blocked", "checking", "none"] as const;
const listQuery = z.object({
  repositoryId: z.string().max(40).optional(),
  gate: z.enum(GATE_FILTERS).optional(),
  q: z.string().trim().max(120).optional(),
});

/**
 * The latest gate run for a pull request's head commit, as JSON, or null. Columns of the outer row are spelled out:
 * inside a select list they would lose their table and bind to the subquery's own columns.
 */
const latestGate = sql<{ result: "passed" | "notes" | "blocked"; scanId: string; at: string } | null>`(
  select json_build_object('result', g.result, 'scanId', g.scan_id, 'at', g.created_at)
  from ${schema.gateRun} g join ${schema.scan} s on s.id = g.scan_id
  where g.repository_id = "pull_request"."repository_id" and lower(s.commit_sha) = "pull_request"."head_sha"
  order by g.created_at desc limit 1)`;
/** A check of the head commit is queued or running. */
const checking = sql<boolean>`exists (
  select 1 from ${schema.scan} s
  where s.repository_id = "pull_request"."repository_id" and lower(s.expected_sha) = "pull_request"."head_sha"
    and s.state in ('queued', 'running'))`;

export const pullRequestRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const like = input.q ? `%${input.q.replace(/[%_\\]/g, "\\$&")}%` : null;
    const rows = await db
      .select({
        id: pr.id,
        repositoryId: pr.repositoryId,
        repositoryName: r.name,
        number: pr.number,
        title: pr.title,
        author: pr.author,
        url: pr.url,
        headRef: pr.headRef,
        headSha: pr.headSha,
        baseRef: pr.baseRef,
        draft: pr.draft,
        openedAt: pr.openedAt,
        updatedAt: pr.updatedAt,
        gate: latestGate,
        checking,
      })
      .from(pr)
      .innerJoin(r, eq(r.id, pr.repositoryId))
      .where(
        and(
          eq(pr.organizationId, actor.organizationId),
          visibleRepository(pr.repositoryId, actor),
          // Repositories set aside are left out, unless one is asked for (ADR 0043).
          input.repositoryId ? eq(pr.repositoryId, input.repositoryId) : activeRepository(pr.repositoryId),
          like ? or(ilike(pr.title, like), ilike(r.name, like), ilike(pr.headRef, like)) : undefined,
        ),
      )
      .orderBy(desc(pr.updatedAt), desc(pr.number))
      .limit(PULL_REQUEST_LIMIT);
    const items = rows.filter((row) => {
      if (!input.gate) return true;
      if (input.gate === "checking") return row.checking;
      if (input.gate === "none") return !row.gate && !row.checking;
      return row.gate?.result === input.gate;
    });
    return c.json({ items, truncated: rows.length === PULL_REQUEST_LIMIT });
  })
  /** Per repository: when its pull requests were last read, and why that failed, if it did. */
  .get("/sources", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({
        id: r.id,
        name: r.name,
        checkedAt: r.pullRequestsCheckedAt,
        problem: r.pullRequestsProblem,
        // Spelled out: inside a select list the column names would lose their table.
        open: sql<number>`(select count(*)::int from pull_request p where p.repository_id = "repository"."id")`,
      })
      .from(r)
      .where(
        and(eq(r.organizationId, actor.organizationId), visibleRepository(r.id, actor), isNull(r.inactiveAt)),
      )
      .orderBy(r.name);
    return c.json(rows);
  })
  /** Asks the worker to read the pull requests of the repositories the caller sees again. */
  .post("/refresh", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    await rateLimit(`pull-requests:refresh:${actor.userId}`, 6);
    const repos = await db
      .select({ id: r.id })
      .from(r)
      .where(
        and(eq(r.organizationId, actor.organizationId), visibleRepository(r.id, actor), isNull(r.inactiveAt)),
      );
    if (repos.length > 0) {
      await boss.send(
        QUEUES.pullRequestRefresh,
        { organizationId: actor.organizationId, repositoryIds: repos.map((x) => x.id) },
        { retryLimit: 0, expireInSeconds: 900, singletonKey: `${actor.organizationId}:${actor.userId}` },
      );
    }
    return c.json({ queued: repos.length }, 202);
  })
  /** Checks a pull request's head commit like a CI pipeline would (ADR 0008); a check already waiting is reused. */
  .post("/:id/check", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    await rateLimit(`pull-requests:check:${actor.userId}`, 20);
    const [row] = await db
      .select({ repositoryId: pr.repositoryId, number: pr.number, headSha: pr.headSha })
      .from(pr)
      .where(
        and(
          eq(pr.id, c.req.param("id")),
          eq(pr.organizationId, actor.organizationId),
          visibleRepository(pr.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!row) throw notFound("Pull request");
    const ref = `refs/pull/${row.number}/head`;
    const [running] = await db
      .select({ id: schema.scan.id })
      .from(schema.scan)
      .where(
        and(
          eq(schema.scan.repositoryId, row.repositoryId),
          inArray(schema.scan.state, ["queued", "running"]),
          eq(schema.scan.ref, ref),
          eq(schema.scan.expectedSha, row.headSha),
        ),
      )
      .limit(1);
    const scanId =
      running?.id ??
      (await queueScan(actor.organizationId, row.repositoryId, actor.userId, "manual", {
        ref,
        expectedSha: row.headSha,
      }));
    await audit(
      actor,
      "gate.check_requested",
      { type: "repository", id: row.repositoryId },
      { ref, sha: row.headSha, scanId, reused: Boolean(running), source: "pull-requests" },
    );
    return c.json({ scanId, reused: Boolean(running) }, 202);
  });
