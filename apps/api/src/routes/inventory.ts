/**
 * The inventory in the app (ADR 0053): systems and their software as people and scripts tell them, a search for a piece of
 * software across everything GarnetOps knows, the export, and the tokens scripts use. GarnetOps never connects to an inventory
 * entry and never matches its software against the vulnerability database.
 */
import { newId } from "@garnetops/core";
import {
  cleanInventoryText,
  INVENTORY_KINDS,
  INVENTORY_TOKEN_SCOPES,
  inventorySystemSchema,
} from "@garnetops/core/inventory";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { activeRepository, isTimeZone, schema, visibleRepository } from "@garnetops/db";
import { LANGUAGES } from "@garnetops/i18n";
import { and, asc, count, desc, eq, ilike, inArray, isNull, or, type SQL, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { toCsv } from "../export/csv.ts";
import {
  CONTENT_TYPES,
  EXPORT_FORMATS,
  type ExportFormat,
  exportFileName,
} from "../export/findings-report.ts";
import { inventoryReport } from "../export/inventory-report.ts";
import { toPdf } from "../export/pdf.ts";
import { toText } from "../export/txt.ts";
import { toXlsx } from "../export/xlsx.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { createSystem, updateSystem } from "../lib/inventory.ts";
import { newInventoryToken } from "../lib/inventory-token.ts";
import { modulesOf } from "../lib/modules.ts";
import { notFound } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const s = schema.inventorySystem;
const sw = schema.inventorySoftware;
const tok = schema.inventoryToken;

const filterQuery = z.object({
  /** Part of a system's name or key, of a tag, or of the name of software on it. */
  q: z.string().trim().max(120).optional(),
  kind: z.enum(INVENTORY_KINDS).optional(),
  source: z.enum(["manual", "script"]).optional(),
});
const listQuery = filterQuery.extend({
  /** The offset of the page, as the previous answer's `next` or `prev` gave it. */
  cursor: z
    .string()
    .regex(/^\d{1,7}$/)
    .optional(),
  pageSize: pageSizeSchema,
});
const exportQuery = filterQuery.extend({
  format: z.enum(EXPORT_FORMATS),
  lang: z.enum(LANGUAGES).default("en"),
  tz: z.string().max(64).refine(isTimeZone, "Unknown time zone").default("UTC"),
});
const softwareQuery = z.object({ q: z.string().trim().min(2).max(80) });
const tokenBody = z.object({
  label: z
    .string()
    .max(400)
    .transform((v) => cleanInventoryText(v, 100))
    .refine((v) => v.length > 0, "A name is needed"),
  scope: z.enum(INVENTORY_TOKEN_SCOPES),
});
const MAX_EXPORT_ROWS: Record<ExportFormat, number> = { csv: 50_000, xlsx: 50_000, txt: 50_000, pdf: 5_000 };
const WRITERS = { csv: toCsv, xlsx: toXlsx, pdf: toPdf, txt: toText } as const;
/** Rows of the software search per source. */
const SEARCH_LIMIT = 300;

const escapeLike = (text: string) => text.replace(/[%_\\]/g, "\\$&");

function where(organizationId: string, input: z.infer<typeof filterQuery>): SQL | undefined {
  const like = input.q ? `%${escapeLike(input.q)}%` : null;
  return and(
    eq(s.organizationId, organizationId),
    input.kind ? eq(s.kind, input.kind) : undefined,
    input.source ? eq(s.source, input.source) : undefined,
    like
      ? or(
          ilike(s.name, like),
          ilike(s.key, like),
          sql`exists (select 1 from jsonb_array_elements_text(${s.tags}) t where t ilike ${like})`,
          sql`exists (select 1 from ${sw} where ${sw.systemId} = ${s.id} and ${sw.name} ilike ${like})`,
        )
      : undefined,
  );
}

const softwareOf = async (systemIds: string[]) => {
  const map = new Map<string, { name: string; version: string }[]>();
  if (systemIds.length === 0) return map;
  const rows = await db
    .select({ systemId: sw.systemId, name: sw.name, version: sw.version })
    .from(sw)
    .where(inArray(sw.systemId, systemIds))
    .orderBy(asc(sw.name), asc(sw.version));
  for (const row of rows)
    map.set(row.systemId, [...(map.get(row.systemId) ?? []), { name: row.name, version: row.version }]);
  return map;
};

const columns = {
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
};

export const inventoryRoutes = new Hono<AppEnv>()
  /** The systems, by name, each with how much software it lists and the first few entries. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const condition = where(actor.organizationId, input);
    const offset = input.cursor ? Number(input.cursor) : 0;
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          ...columns,
          softwareCount: sql<number>`(select count(*)::int from ${sw} where ${sw.systemId} = ${s.id})`,
        })
        .from(s)
        .where(condition)
        .orderBy(asc(s.name), asc(s.key))
        .limit(input.pageSize)
        .offset(offset),
      db.select({ n: count() }).from(s).where(condition),
    ]);
    const software = await softwareOf(rows.map((r) => r.id));
    const total = totalRow[0]?.n ?? 0;
    return c.json({
      items: rows.map((row) => ({ ...row, software: (software.get(row.id) ?? []).slice(0, 6) })),
      total,
      pageSize: input.pageSize,
      next: offset + rows.length < total ? String(offset + input.pageSize) : null,
      prev: offset > 0 ? String(Math.max(0, offset - input.pageSize)) : null,
    });
  })
  /**
   * Where a piece of software runs, across the inventory, the packages of hosts with the agent, the images of running containers
   * and the repositories' packages (each as far as the person may see it). Inventory entries are told, not checked.
   */
  .get("/software", async (c) => {
    const actor = c.get("actor");
    const input = softwareQuery.parse(c.req.query());
    const like = `%${escapeLike(input.q)}%`;
    const org = actor.organizationId;
    const hostsOn = (await modulesOf(org)).hosts;
    const h = schema.agentHost;
    const hc = schema.hostContainer;
    const ci = schema.containerImage;
    const p = schema.repositoryPackage;
    const r = schema.repository;
    type Found = { id: string; system: string; detail: string | null; name: string; version: string };
    const none = { rows: [] as Found[] };
    const [inventory, hosts, containers, repositories] = await Promise.all([
      db
        .select({ id: s.id, system: s.name, detail: s.key, name: sw.name, version: sw.version })
        .from(sw)
        .innerJoin(s, eq(s.id, sw.systemId))
        .where(and(eq(sw.organizationId, org), ilike(sw.name, like)))
        .orderBy(asc(sw.name), asc(s.name))
        .limit(SEARCH_LIMIT),
      hostsOn
        ? db.execute<Found>(sql`select ${h.id} as id, ${h.name} as system, null as detail, pkg->>'name' as name,
              pkg->>'version' as version
            from ${h} cross join lateral jsonb_array_elements(coalesce(${h.hostPackages}, '[]'::jsonb)) pkg
            where ${h.organizationId} = ${org} and pkg->>'name' ilike ${like}
            order by 4, 2 limit ${SEARCH_LIMIT}`)
        : none,
      hostsOn
        ? db.execute<Found>(sql`select ${hc.hostId} as id, ${hc.name} as system,
              ${h.name} || ': ' || ${hc.imageRef} as detail, pkg->>'name' as name, pkg->>'version' as version
            from ${hc} join ${h} on ${h.id} = ${hc.hostId}
              join ${ci} on ${ci.organizationId} = ${hc.organizationId} and ${ci.imageId} = ${hc.imageId}
              cross join lateral jsonb_array_elements(coalesce(${ci.packages}, '[]'::jsonb)) pkg
            where ${hc.organizationId} = ${org} and pkg->>'name' ilike ${like}
            order by 4, 2 limit ${SEARCH_LIMIT}`)
        : none,
      db
        .select({ id: r.id, system: r.name, detail: p.type, name: p.name, version: p.version })
        .from(p)
        .innerJoin(r, eq(r.id, p.repositoryId))
        .where(
          and(
            eq(p.organizationId, org),
            visibleRepository(p.repositoryId, actor),
            activeRepository(p.repositoryId),
            ilike(p.name, like),
          ),
        )
        .orderBy(asc(p.name), asc(r.name))
        .limit(SEARCH_LIMIT),
    ]);
    const clip = (v: string | null, max: number) => (v === null ? null : v.slice(0, max));
    const rows = (source: "inventory" | "host" | "container" | "repository", found: Found[]) =>
      found.map((f) => ({
        source,
        id: f.id,
        system: clip(f.system, 200),
        detail: clip(f.detail, 300),
        name: clip(f.name, 200),
        version: clip(f.version, 100),
        /** Matched against the vulnerability database by a scan or the agent; inventory entries are not. */
        checked: source !== "inventory",
      }));
    const items = [
      ...rows("inventory", inventory),
      ...rows("host", hosts.rows),
      ...rows("container", containers.rows),
      ...rows("repository", repositories),
    ];
    const limited = [inventory, hosts.rows, containers.rows, repositories].some(
      (x) => x.length >= SEARCH_LIMIT,
    );
    return c.json({ items, limited, hostsOn });
  })
  /** The inventory as filtered, as a file: one row per system and piece of software. */
  .get("/export", async (c) => {
    const actor = c.get("actor");
    const input = exportQuery.parse(c.req.query());
    const condition = where(actor.organizationId, input);
    const max = MAX_EXPORT_ROWS[input.format];
    const systems = await db
      .select(columns)
      .from(s)
      .where(condition)
      .orderBy(asc(s.name), asc(s.key))
      .limit(max);
    const software = await softwareOf(systems.map((x) => x.id));
    const now = new Date();
    const filters = [input.q, input.kind, input.source].filter((x): x is string => Boolean(x));
    const report = inventoryReport(
      systems.map((system) => ({ ...system, software: software.get(system.id) ?? [] })),
      { language: input.lang, timeZone: input.tz, filters, repositoryName: null, total: systems.length, now },
      max,
    );
    const file = WRITERS[input.format](report);
    await audit(actor, "inventory.exported", undefined, { format: input.format, systems: systems.length });
    return c.body(new Uint8Array(file), 200, {
      "content-type": CONTENT_TYPES[input.format],
      "content-disposition": `attachment; filename="${exportFileName(input.format, null, input.tz, now, "inventory")}"`,
      "cache-control": "no-store",
    });
  })
  /** The tokens scripts use: names, scopes and when they were last used; never the token itself. */
  .get("/tokens", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const rows = await db
      .select({
        id: tok.id,
        label: tok.label,
        prefix: tok.prefix,
        scope: tok.scope,
        createdAt: tok.createdAt,
        lastUsedAt: tok.lastUsedAt,
        createdBy: schema.user.name,
      })
      .from(tok)
      .leftJoin(schema.user, eq(schema.user.id, tok.createdBy))
      .where(and(eq(tok.organizationId, actor.organizationId), isNull(tok.revokedAt)))
      .orderBy(desc(tok.createdAt));
    return c.json(rows);
  })
  /** A new token: in this answer once; GarnetOps keeps only its hash. Admins, with a recent sign-in. */
  .post("/tokens", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    await rateLimit(`inventory:tokens:${actor.userId}`, 20);
    const input = tokenBody.parse(await c.req.json());
    const { token, hash, prefix } = newInventoryToken();
    const id = newId("itok");
    await db.insert(tok).values({
      id,
      organizationId: actor.organizationId,
      tokenHash: hash,
      prefix,
      label: input.label,
      scope: input.scope,
      createdBy: actor.userId,
    });
    await audit(
      actor,
      "inventory.token_created",
      { type: "inventory_token", id },
      { label: input.label, scope: input.scope, prefix },
    );
    return c.json({ id, token, prefix, label: input.label, scope: input.scope }, 201);
  })
  .delete("/tokens/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const [row] = await db
      .update(tok)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(tok.id, c.req.param("id")),
          eq(tok.organizationId, actor.organizationId),
          isNull(tok.revokedAt),
        ),
      )
      .returning({ id: tok.id, label: tok.label, prefix: tok.prefix, scope: tok.scope });
    if (!row) throw notFound("Token");
    await audit(
      actor,
      "inventory.token_revoked",
      { type: "inventory_token", id: row.id },
      { label: row.label, scope: row.scope, prefix: row.prefix },
    );
    return c.body(null, 204);
  })
  /** A new system, added by hand (members and above). */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = inventorySystemSchema.parse(await c.req.json());
    const id = await createSystem(actor.organizationId, actor.userId, input);
    await audit(
      actor,
      "inventory.system_created",
      { type: "inventory_system", id },
      { key: input.key, name: input.name, software: input.software.length },
    );
    return c.json({ id }, 201);
  })
  /** One system with its whole software list. */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select(columns)
      .from(s)
      .where(and(eq(s.id, c.req.param("id")), eq(s.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw notFound("System");
    return c.json({ ...row, software: (await softwareOf([row.id])).get(row.id) ?? [] });
  })
  .put("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = inventorySystemSchema.parse(await c.req.json());
    const id = await updateSystem(actor.organizationId, c.req.param("id"), input);
    if (!id) throw notFound("System");
    await audit(
      actor,
      "inventory.system_updated",
      { type: "inventory_system", id },
      { key: input.key, name: input.name, software: input.software.length },
    );
    return c.json({ id });
  })
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const [row] = await db
      .delete(s)
      .where(and(eq(s.id, c.req.param("id")), eq(s.organizationId, actor.organizationId)))
      .returning({ id: s.id, key: s.key, name: s.name });
    if (!row) throw notFound("System");
    await audit(
      actor,
      "inventory.system_deleted",
      { type: "inventory_system", id: row.id },
      { key: row.key, name: row.name },
    );
    return c.body(null, 204);
  });
