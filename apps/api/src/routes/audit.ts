import { pageSizeSchema } from "@garnetops/core/pagination";
import { schema } from "@garnetops/db";
import { and, count, eq, isNull, like, or } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { type KeysetSpec, keysetQuery, parseInt10, toPage } from "../lib/paginate.ts";

const a = schema.auditLog;

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  /** Action prefix, e.g. "auth." or "repository.". */
  action: z
    .string()
    .regex(/^[a-z_.]{1,60}$/)
    .optional(),
});

type Row = {
  id: number;
  createdAt: Date;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  data: unknown;
  actorId: string | null;
  actorName: string | null;
  actorEmail: string | null;
};

// Newest first by sequence number: the order of events, independent of clock changes (ADR 0005).
const spec: KeysetSpec<Row> = { keys: [a.id], direction: "desc", keyOf: (r) => [r.id], parse: [parseInt10] };

/** Read-only audit log of the organisation, for owners and admins. */
export const auditRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  requireRole(actor, "admin");
  const input = listQuery.parse(c.req.query());
  const where = and(
    or(
      eq(a.organizationId, actor.organizationId),
      // Installation-wide entries of the update sidecar (system runs, journal gaps).
      and(isNull(a.organizationId), eq(a.source, "updater")),
    ),
    input.action ? like(a.action, `${input.action.replace(/[%_\\]/g, "\\$&")}%`) : undefined,
  );
  const q = keysetQuery(spec, input.cursor, input.pageSize);
  const [rows, totalRow] = await Promise.all([
    db
      .select({
        id: a.id,
        createdAt: a.createdAt,
        action: a.action,
        targetType: a.targetType,
        targetId: a.targetId,
        ip: a.ip,
        data: a.data,
        actorId: a.actorUserId,
        actorName: schema.user.name,
        actorEmail: schema.user.email,
      })
      .from(a)
      .leftJoin(schema.user, eq(schema.user.id, a.actorUserId))
      .where(and(where, q.where))
      .orderBy(...q.orderBy)
      .limit(q.limit),
    db.select({ n: count() }).from(a).where(where),
  ]);
  return c.json(
    toPage(spec, q, rows, totalRow[0]?.n ?? 0, input.pageSize, Boolean(input.cursor), (r) => ({
      id: r.id,
      createdAt: r.createdAt,
      action: r.action,
      target: r.targetType ? { type: r.targetType, id: r.targetId } : null,
      actor: r.actorId ? { id: r.actorId, name: r.actorName, email: r.actorEmail } : null,
      ip: r.ip,
      data: r.data,
    })),
  );
});
