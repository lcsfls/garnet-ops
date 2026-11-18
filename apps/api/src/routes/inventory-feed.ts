/**
 * The inventory for scripts (ADR 0053): a bearer inventory token, never a cookie. A `write` token puts and deletes systems by
 * their key and reads nothing; a `read` token reads the inventory and changes nothing. Neither reaches anything else in
 * GarnetOps. What a script sends is text: cleaned, limited, stored, never interpreted and never connected to.
 */
import {
  type InventoryTokenScope,
  inventoryKeySchema,
  inventoryReportSchema,
} from "@garnetops/core/inventory";
import { schema } from "@garnetops/db";
import { and, asc, eq, inArray, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { reportSystem } from "../lib/inventory.ts";
import { bearerInventoryToken, hashInventoryToken } from "../lib/inventory-token.ts";
import { clientIp } from "../lib/ip.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";

/** Requests per token and minute: enough for a fleet reporting from cron within the same minute. */
const RATE_LIMIT = 120;
/** Systems in one answer to a read token. */
const READ_LIMIT = 5000;

const s = schema.inventorySystem;
const sw = schema.inventorySoftware;
const tok = schema.inventoryToken;

type FeedEnv = {
  Variables: {
    inventoryToken: { id: string; organizationId: string; scope: InventoryTokenScope; prefix: string };
  };
};

/**
 * Bearer inventory token. Unknown, revoked and malformed tokens get the same answer. The limit is kept in the database, so it
 * survives restarts like the sign-in limits.
 */
const requireInventoryToken = createMiddleware<FeedEnv>(async (c, next) => {
  const token = bearerInventoryToken(c.req.header("authorization"));
  const [row] = token
    ? await db
        .select({ id: tok.id, organizationId: tok.organizationId, scope: tok.scope, prefix: tok.prefix })
        .from(tok)
        .where(and(eq(tok.tokenHash, hashInventoryToken(token)), isNull(tok.revokedAt)))
        .limit(1)
    : [];
  if (!row) throw new ProblemError(401, "invalid-inventory-token", "The inventory token is not valid");
  await rateLimit(`inventory:${row.id}`, RATE_LIMIT, 60_000);
  await db.update(tok).set({ lastUsedAt: new Date() }).where(eq(tok.id, row.id));
  c.set("inventoryToken", row);
  await next();
});

const requireScope = (scope: InventoryTokenScope) =>
  createMiddleware<FeedEnv>(async (c, next) => {
    if (c.get("inventoryToken").scope !== scope) {
      throw new ProblemError(403, "wrong-scope", `This needs an inventory token with the ${scope} scope`);
    }
    await next();
  });

const keyOf = (value: string) => {
  const key = inventoryKeySchema.safeParse(value);
  if (!key.success) throw notFound("System");
  return key.data;
};

export const inventoryFeedRoutes = new Hono<FeedEnv>()
  .use("*", requireInventoryToken)
  /** The whole inventory for a script that reads it: systems by key, each with its software. */
  .get("/systems", requireScope("read"), async (c) => {
    const token = c.get("inventoryToken");
    const systems = await db
      .select({
        id: s.id,
        key: s.key,
        name: s.name,
        kind: s.kind,
        environment: s.environment,
        notes: s.notes,
        tags: s.tags,
        source: s.source,
        reportedAt: s.reportedAt,
        updatedAt: s.updatedAt,
      })
      .from(s)
      .where(eq(s.organizationId, token.organizationId))
      .orderBy(asc(s.key))
      .limit(READ_LIMIT);
    const software = new Map<string, { name: string; version: string }[]>();
    for (let i = 0; i < systems.length; i += 500) {
      const rows = await db
        .select({ systemId: sw.systemId, name: sw.name, version: sw.version })
        .from(sw)
        .where(
          inArray(
            sw.systemId,
            systems.slice(i, i + 500).map((x) => x.id),
          ),
        )
        .orderBy(asc(sw.name), asc(sw.version));
      for (const row of rows)
        software.set(row.systemId, [
          ...(software.get(row.systemId) ?? []),
          { name: row.name, version: row.version },
        ]);
    }
    return c.json(
      { systems: systems.map(({ id, ...system }) => ({ ...system, software: software.get(id) ?? [] })) },
      200,
      { "cache-control": "no-store" },
    );
  })
  /**
   * Reports one system: created when its key is new, else its software list replaced and the sent fields set. The same report
   * twice changes nothing but the time.
   */
  .put("/systems/:key", requireScope("write"), async (c) => {
    const token = c.get("inventoryToken");
    const key = keyOf(c.req.param("key"));
    const report = inventoryReportSchema.parse(await c.req.json().catch(() => null));
    const { id, created } = await reportSystem(token.organizationId, token.id, key, report);
    // A new system is worth an audit entry; a nightly report of every server is not.
    if (created) {
      await audit(
        { organizationId: token.organizationId, userId: null, ip: clientIp(c.req.raw.headers) },
        "inventory.system_created",
        { type: "inventory_system", id },
        { key, tokenId: token.id, prefix: token.prefix, software: report.software.length },
      );
    }
    return c.json({ key, created, software: report.software.length }, created ? 201 : 200);
  })
  /** Removes the system with this key. */
  .delete("/systems/:key", requireScope("write"), async (c) => {
    const token = c.get("inventoryToken");
    const key = keyOf(c.req.param("key"));
    const [row] = await db
      .delete(s)
      .where(and(eq(s.organizationId, token.organizationId), eq(s.key, key)))
      .returning({ id: s.id, name: s.name });
    if (!row) throw notFound("System");
    await audit(
      { organizationId: token.organizationId, userId: null, ip: clientIp(c.req.raw.headers) },
      "inventory.system_deleted",
      { type: "inventory_system", id: row.id },
      { key, name: row.name, tokenId: token.id, prefix: token.prefix },
    );
    return c.body(null, 204);
  });
