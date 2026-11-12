/**
 * The code viewer (ADR 0048): a person asks for the code of a finding, the worker clones the repository and reads the excerpts,
 * the browser fetches them once. Members and above who see the repository; audited as `code.viewed`; the result is handed over
 * once, then deleted, and never cached.
 */
import { newId } from "@garnetops/core";
import { schema, visibleRepository } from "@garnetops/db";
import { and, eq, inArray, lt, sql } from "drizzle-orm";
import { Hono } from "hono";
import { boss, db, QUEUES } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";

const r = schema.codeRequest;
const f = schema.finding;
const NO_STORE = { "cache-control": "no-store" };

export const codeRoutes = new Hono<AppEnv>()
  /** Ask for the code of a finding. 202 with the request's id; the browser then polls it. */
  .post("/findings/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    await rateLimit(`code:user:${actor.userId}`, 30);
    await rateLimit(`code:org:${actor.organizationId}`, 200, 3600_000);
    const [finding] = await db
      .select({
        id: f.id,
        repositoryId: f.repositoryId,
        packageName: f.packageName,
        scanId: f.lastSeenScanId,
      })
      .from(f)
      .where(
        and(
          eq(f.id, c.req.param("id")),
          eq(f.organizationId, actor.organizationId),
          visibleRepository(f.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!finding) throw notFound("Finding");
    // Old requests go in any state; one clone at a time per organisation.
    await db
      .delete(r)
      .where(
        and(eq(r.organizationId, actor.organizationId), lt(r.createdAt, sql`now() - interval '10 minutes'`)),
      );
    const [busy] = await db
      .select({ id: r.id })
      .from(r)
      .where(
        and(
          eq(r.organizationId, actor.organizationId),
          inArray(r.state, ["queued", "running"]),
          sql`${r.createdAt} > now() - interval '3 minutes'`,
        ),
      )
      .limit(1);
    if (busy)
      throw new ProblemError(409, "busy", "Code of this organisation is being read; try again in a moment");
    const id = newId("cod");
    await db.insert(r).values({
      id,
      organizationId: actor.organizationId,
      requestedBy: actor.userId,
      findingId: finding.id,
      repositoryId: finding.repositoryId,
    });
    try {
      await boss.send(QUEUES.codeFetch, { requestId: id }, { retryLimit: 0, expireInSeconds: 180 });
    } catch (error) {
      await db.delete(r).where(eq(r.id, id));
      throw error;
    }
    const [scan] = await db
      .select({ commitSha: schema.scan.commitSha })
      .from(schema.scan)
      .where(eq(schema.scan.id, finding.scanId))
      .limit(1);
    await audit(
      actor,
      "code.viewed",
      { type: "finding", id: finding.id },
      { repositoryId: finding.repositoryId, package: finding.packageName, commit: scan?.commitSha ?? null },
    );
    return c.json({ id }, 202, NO_STORE);
  })
  /** The request's state; once done or failed, its result, handed over once and then deleted. Only to the person who asked. */
  .get("/requests/:id", async (c) => {
    const actor = c.get("actor");
    const where = and(
      eq(r.id, c.req.param("id")),
      eq(r.organizationId, actor.organizationId),
      eq(r.requestedBy, actor.userId),
    );
    const [row] = await db.select().from(r).where(where).limit(1);
    if (!row) throw notFound("Code request");
    if (row.state === "queued" || row.state === "running") return c.json({ state: row.state }, 200, NO_STORE);
    await db.delete(r).where(where);
    return c.json(
      row.state === "done" ? { state: "done", result: row.result } : { state: "failed", error: row.error },
      200,
      NO_STORE,
    );
  });
