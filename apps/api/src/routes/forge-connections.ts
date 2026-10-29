import { newId } from "@garnetops/core";
import {
  apiBaseFromWeb,
  apiBaseProblem,
  FORGE_KINDS,
  normalizeForgeWebBase,
  repositoryKey,
} from "@garnetops/core/fix-prs";
import { seal } from "@garnetops/core/vault";
import { repositoryVisibleTo, schema, type Viewer } from "@garnetops/db";
import { and, asc, count, eq, ilike, inArray, or } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";
import { queueScan } from "./repositories.ts";

/**
 * Personal forge connections (ADR 0030): each person connects their own account on a forge with a read token and
 * adds repositories from the list it can see. Every route works on the caller's own connections only; somebody
 * else's connection is "not found", for admins too. The API seals the token and never opens it: the worker checks
 * it and lists the repositories.
 */
const fc = schema.forgeConnection;
const listed = schema.forgeConnectionRepository;
const r = schema.repository;

/** The most repositories added in one request. */
export const PICK_LIMIT = 100;

const tokenSchema = z
  .string()
  .trim()
  .regex(/^[\x21-\x7e]{8,500}$/, "Paste the token as it is: 8 to 500 visible characters");

const createBody = z.object({
  forgeKind: z.enum(FORGE_KINDS),
  webBaseUrl: z.string().trim().max(300),
  /** Only for a forge whose API is not where the web address suggests. */
  apiBaseUrl: z.string().trim().max(300).optional(),
  token: tokenSchema,
});
const tokenBody = z.object({ token: tokenSchema });
const pickBody = z.object({ forgeIds: z.array(z.string().min(1).max(100)).min(1).max(PICK_LIMIT) });
const listQuery = z.object({ q: z.string().trim().max(100).optional() });
const removeQuery = z.object({ removeRepositories: z.enum(["0", "1"]).default("0") });

type ConnectionRow = typeof fc.$inferSelect;

/** The caller's own connection, else 404. */
async function ownConnection(viewer: Viewer, id: string): Promise<ConnectionRow> {
  const [row] = await db
    .select()
    .from(fc)
    .where(and(eq(fc.id, id), eq(fc.organizationId, viewer.organizationId), eq(fc.userId, viewer.userId)))
    .limit(1);
  if (!row) throw notFound("Connection");
  return row;
}

function connectionDto(row: ConnectionRow, repositories: number) {
  return {
    id: row.id,
    forgeKind: row.forgeKind,
    webBaseUrl: row.webBaseUrl,
    apiBaseUrl: row.apiBaseUrl,
    accountLogin: row.accountLogin,
    state: row.state,
    problem: row.problem,
    broadToken: row.broadToken,
    truncated: row.truncated,
    lastCheckedAt: row.lastCheckedAt,
    createdAt: row.createdAt,
    repositories,
  };
}

function sealToken(organizationId: string, token: string) {
  const secretId = newId("sec");
  return {
    secretId,
    sealed: seal(
      token,
      { organizationId, recordId: secretId, purpose: "forge-connection-token" },
      vaultPublicKey,
    ),
  };
}

const queueRefresh = (row: { id: string; organizationId: string; userId: string }) =>
  boss.send(
    QUEUES.forgeConnectionRefresh,
    { connectionId: row.id, organizationId: row.organizationId, userId: row.userId },
    { retryLimit: 0, expireInSeconds: 600, singletonKey: row.id },
  );

export const forgeConnectionRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({ connection: fc, repositories: count(listed.forgeId) })
      .from(fc)
      .leftJoin(listed, eq(listed.connectionId, fc.id))
      .where(and(eq(fc.organizationId, actor.organizationId), eq(fc.userId, actor.userId)))
      .groupBy(fc.id)
      .orderBy(asc(fc.webBaseUrl));
    return c.json(rows.map((row) => connectionDto(row.connection, row.repositories)));
  })
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = createBody.parse(await c.req.json());
    const webBaseUrl = normalizeForgeWebBase(input.webBaseUrl);
    if (!webBaseUrl) {
      throw new ProblemError(
        422,
        "invalid-web-address",
        "Use the forge's https:// address, without user name or query",
      );
    }
    const apiBaseUrl = (input.apiBaseUrl || apiBaseFromWeb(input.forgeKind, webBaseUrl)).replace(/\/+$/, "");
    const problem = apiBaseProblem(input.forgeKind, apiBaseUrl);
    if (problem) throw new ProblemError(422, "invalid-api-address", problem);
    requireRecentSignIn(actor);
    await rateLimit(`forge-connection:change:${actor.userId}`, 10);
    const [existing] = await db
      .select({ id: fc.id })
      .from(fc)
      .where(
        and(
          eq(fc.organizationId, actor.organizationId),
          eq(fc.userId, actor.userId),
          eq(fc.webBaseUrl, webBaseUrl),
        ),
      )
      .limit(1);
    if (existing) throw new ProblemError(409, "duplicate", "You already connected an account on this forge");

    const id = newId("fcn");
    const { secretId, sealed } = sealToken(actor.organizationId, input.token);
    const row = await db.transaction(async (tx) => {
      await tx.insert(schema.secret).values({
        id: secretId,
        organizationId: actor.organizationId,
        purpose: "forge-connection-token",
        sealed,
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      const [created] = await tx
        .insert(fc)
        .values({
          id,
          organizationId: actor.organizationId,
          userId: actor.userId,
          forgeKind: input.forgeKind,
          webBaseUrl,
          apiBaseUrl,
          secretId,
        })
        .returning();
      return created as ConnectionRow;
    });
    await audit(
      actor,
      "forge_connection.added",
      { type: "forge_connection", id },
      { forge: input.forgeKind, web: webBaseUrl, api: apiBaseUrl },
    );
    await queueRefresh(row);
    return c.json(connectionDto(row, 0), 201);
  })
  /** A new token for the same account; the old one is deleted. */
  .put("/:id/token", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const row = await ownConnection(actor, c.req.param("id"));
    const input = tokenBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    await rateLimit(`forge-connection:change:${actor.userId}`, 10);
    const { secretId, sealed } = sealToken(actor.organizationId, input.token);
    await db.transaction(async (tx) => {
      await tx.insert(schema.secret).values({
        id: secretId,
        organizationId: actor.organizationId,
        purpose: "forge-connection-token",
        sealed,
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      await tx
        .update(fc)
        .set({ secretId, state: "unchecked", problem: null, updatedAt: new Date() })
        .where(eq(fc.id, row.id));
      if (row.secretId) await tx.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    });
    await audit(
      actor,
      "forge_connection.replaced",
      { type: "forge_connection", id: row.id },
      { web: row.webBaseUrl },
    );
    await queueRefresh(row);
    return c.body(null, 204);
  })
  /** Asks the worker to check the token and list the repositories again. */
  .post("/:id/refresh", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const row = await ownConnection(actor, c.req.param("id"));
    await rateLimit(`forge-connection:refresh:${actor.userId}`, 6);
    await queueRefresh(row);
    return c.json({ queued: true }, 202);
  })
  /**
   * The repositories the account can see, with whether each is already monitored: added (and visible to the
   * caller, with its id), or monitored privately by someone else (no id, nothing more).
   */
  .get("/:id/repositories", async (c) => {
    const actor = c.get("actor");
    const row = await ownConnection(actor, c.req.param("id"));
    const input = listQuery.parse(c.req.query());
    const pattern = input.q ? `%${input.q.replace(/[%_\\]/g, "\\$&")}%` : null;
    const [items, repos] = await Promise.all([
      db
        .select()
        .from(listed)
        .where(
          and(
            eq(listed.connectionId, row.id),
            pattern ? or(ilike(listed.fullName, pattern), ilike(listed.description, pattern)) : undefined,
          ),
        )
        .orderBy(asc(listed.fullName)),
      db
        .select({ id: r.id, url: r.url, visible: repositoryVisibleTo(actor) })
        .from(r)
        .where(eq(r.organizationId, actor.organizationId)),
    ]);
    const known = new Map(repos.map((x) => [repositoryKey(x.url), x]));
    return c.json({
      connection: connectionDto(row, items.length),
      items: items.map((item) => {
        const match = known.get(repositoryKey(item.cloneUrl));
        return {
          forgeId: item.forgeId,
          fullName: item.fullName,
          description: item.description,
          private: item.private,
          archived: item.archived,
          defaultBranch: item.defaultBranch,
          added: match ? (match.visible ? { repositoryId: match.id } : { elsewhere: true }) : null,
        };
      }),
    });
  })
  /** Adds the chosen repositories, private to the caller, cloned with this connection, and scans them. */
  .post("/:id/repositories", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const row = await ownConnection(actor, c.req.param("id"));
    const input = pickBody.parse(await c.req.json());
    await rateLimit(`forge-connection:pick:${actor.userId}`, 10);
    const ids = [...new Set(input.forgeIds)];
    const [picked, repos] = await Promise.all([
      db
        .select()
        .from(listed)
        .where(and(eq(listed.connectionId, row.id), inArray(listed.forgeId, ids))),
      db.select({ url: r.url }).from(r).where(eq(r.organizationId, actor.organizationId)),
    ]);
    const known = new Set(repos.map((x) => repositoryKey(x.url)));
    const created: { id: string; name: string; scanId: string }[] = [];
    const skipped: { forgeId: string; reason: "duplicate" | "unknown" }[] = ids
      .filter((id) => !picked.some((p) => p.forgeId === id))
      .map((forgeId) => ({ forgeId, reason: "unknown" as const }));
    for (const item of picked) {
      const key = repositoryKey(item.cloneUrl);
      if (known.has(key)) {
        skipped.push({ forgeId: item.forgeId, reason: "duplicate" });
        continue;
      }
      known.add(key);
      const id = newId("repo");
      const name = item.fullName.split("/").pop() ?? item.fullName;
      await db.insert(r).values({
        id,
        organizationId: actor.organizationId,
        name,
        url: item.cloneUrl,
        branch: null,
        authKind: "connection",
        forgeConnectionId: row.id,
        visibility: "private",
        ownerUserId: actor.userId,
      });
      await audit(
        actor,
        "repository.created",
        { type: "repository", id },
        { url: item.cloneUrl, auth: "connection", connection: row.id, visibility: "private" },
      );
      created.push({ id, name, scanId: await queueScan(actor.organizationId, id, actor.userId, "manual") });
    }
    return c.json({ created, skipped }, 201);
  })
  /**
   * Removes the connection and its token. Repositories added through it stay unless asked: the caller's private
   * ones can go with it (`removeRepositories=1`); shared ones always stay and need a new credential.
   */
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownConnection(actor, c.req.param("id"));
    const { removeRepositories } = removeQuery.parse(c.req.query());
    requireRecentSignIn(actor);
    const removed = await db.transaction(async (tx) => {
      let repos: { id: string; secretId: string | null }[] = [];
      if (removeRepositories === "1") {
        const writeTokens = await tx
          .select({ secretId: schema.repositoryWriteAccess.secretId })
          .from(schema.repositoryWriteAccess)
          .innerJoin(r, eq(r.id, schema.repositoryWriteAccess.repositoryId))
          .where(
            and(
              eq(r.forgeConnectionId, row.id),
              eq(r.ownerUserId, actor.userId),
              eq(r.visibility, "private"),
            ),
          );
        repos = await tx
          .delete(r)
          .where(
            and(
              eq(r.organizationId, actor.organizationId),
              eq(r.forgeConnectionId, row.id),
              eq(r.ownerUserId, actor.userId),
              eq(r.visibility, "private"),
            ),
          )
          .returning({ id: r.id, secretId: r.secretId });
        const secrets = [...writeTokens.map((w) => w.secretId), ...repos.map((x) => x.secretId)].filter(
          (id): id is string => Boolean(id),
        );
        if (secrets.length) await tx.delete(schema.secret).where(inArray(schema.secret.id, secrets));
      }
      await tx.delete(fc).where(eq(fc.id, row.id));
      if (row.secretId) await tx.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
      return repos.length;
    });
    await audit(
      actor,
      "forge_connection.removed",
      { type: "forge_connection", id: row.id },
      { web: row.webBaseUrl, repositoriesRemoved: removed },
    );
    return c.body(null, 204);
  });
