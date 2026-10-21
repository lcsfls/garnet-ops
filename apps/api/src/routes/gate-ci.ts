import { isCommitSha, isSafeGitRef } from "@garnetops/core/gates";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { z } from "zod";
import { db } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { bearerGateToken, hashGateToken } from "../lib/gate-token.ts";
import { clientIp } from "../lib/ip.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { queueScan } from "./repositories.ts";

/** Requests per token and minute; enough for a busy pipeline polling every few seconds. */
const RATE_LIMIT = 30;
const WINDOW_MS = 60_000;

const checkBody = z.object({
  ref: z
    .string()
    .max(200)
    .refine(isSafeGitRef, "Use a branch, tag or ref such as refs/pull/12/head")
    .optional(),
  sha: z.string().refine(isCommitSha, "Use the full commit id").optional(),
});

type GateEnv = {
  Variables: { gateToken: { id: string; organizationId: string; repositoryId: string; prefix: string } };
};

/**
 * Bearer gate token (ADR 0008). Unknown, revoked and malformed tokens get the same answer.
 * The limit is kept in the database, so it survives restarts like the sign-in limits.
 */
const requireGateToken = createMiddleware<GateEnv>(async (c, next) => {
  const token = bearerGateToken(c.req.header("authorization"));
  const [row] = token
    ? await db
        .select({
          id: schema.gateToken.id,
          organizationId: schema.gateToken.organizationId,
          repositoryId: schema.gateToken.repositoryId,
          prefix: schema.gateToken.prefix,
        })
        .from(schema.gateToken)
        .where(and(eq(schema.gateToken.tokenHash, hashGateToken(token)), isNull(schema.gateToken.revokedAt)))
        .limit(1)
    : [];
  if (!row) throw new ProblemError(401, "invalid-gate-token", "The gate token is not valid");

  await rateLimit(`gate:${row.id}`, RATE_LIMIT, WINDOW_MS);
  await db.update(schema.gateToken).set({ lastUsedAt: new Date() }).where(eq(schema.gateToken.id, row.id));
  c.set("gateToken", row);
  await next();
});

/**
 * The API a CI pipeline calls with a gate token. It answers with the result, rule names and
 * counts only: pipeline logs of public projects are public, and a vulnerability list there
 * would tell an attacker where to look. Authenticated by the bearer token alone, never by a
 * cookie, so cross-site requests cannot use it.
 */
export const gateCiRoutes = new Hono<GateEnv>()
  .use("*", requireGateToken)
  .post("/checks", async (c) => {
    const token = c.get("gateToken");
    const input = checkBody.parse(await c.req.json().catch(() => ({})));
    const ref = input.ref ?? null;
    const sha = input.sha?.toLowerCase() ?? null;
    // A check already waiting for the same ref and commit is reused instead of queueing another.
    const [running] = await db
      .select({ id: schema.scan.id })
      .from(schema.scan)
      .where(
        and(
          eq(schema.scan.repositoryId, token.repositoryId),
          inArray(schema.scan.state, ["queued", "running"]),
          ref ? eq(schema.scan.ref, ref) : isNull(schema.scan.ref),
          sha ? eq(schema.scan.expectedSha, sha) : isNull(schema.scan.expectedSha),
        ),
      )
      .limit(1);
    const id =
      running?.id ??
      (await queueScan(token.organizationId, token.repositoryId, null, "ci", { ref, expectedSha: sha }));
    await audit(
      { organizationId: token.organizationId, userId: null, ip: clientIp(c.req.raw.headers) },
      "gate.check_requested",
      { type: "repository", id: token.repositoryId },
      { tokenId: token.id, prefix: token.prefix, ref, sha, scanId: id, reused: Boolean(running) },
    );
    return c.json({ id, state: "queued" }, 202);
  })
  .get("/checks/:id", async (c) => {
    const token = c.get("gateToken");
    const [row] = await db
      .select({
        id: schema.scan.id,
        state: schema.scan.state,
        error: schema.scan.error,
        ref: schema.scan.ref,
        branch: schema.scan.branch,
        commitSha: schema.scan.commitSha,
        result: schema.gateRun.result,
        matches: schema.gateRun.matches,
      })
      .from(schema.scan)
      .leftJoin(schema.gateRun, eq(schema.gateRun.scanId, schema.scan.id))
      .where(and(eq(schema.scan.id, c.req.param("id")), eq(schema.scan.repositoryId, token.repositoryId)))
      .limit(1);
    if (!row) throw notFound("Check");
    return c.json({
      id: row.id,
      state: row.state,
      result: row.result ?? null,
      rules: Object.entries(row.matches ?? {}).map(([rule, m]) => ({ rule, count: m.count, mode: m.mode })),
      ref: row.ref ?? row.branch,
      commit: row.commitSha,
      // A short, user-safe text (never raw scanner output), e.g. a commit that did not match.
      error: row.state === "failed" ? row.error : null,
      details: `${new URL(env.PUBLIC_URL).origin}/repositories/${token.repositoryId}`,
    });
  });
