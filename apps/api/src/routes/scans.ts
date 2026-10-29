import { SCAN_STATES } from "@garnetops/core";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { schema, visibleRepository } from "@garnetops/db";
import { and, count, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";
import { type KeysetSpec, keysetQuery, parseDate, parseText, toPage } from "../lib/paginate.ts";
import { notFound } from "../lib/problem.ts";

const s = schema.scan;

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  repositoryId: z.string().max(40).optional(),
  state: z.enum(SCAN_STATES).optional(),
});

const columns = {
  id: s.id,
  repositoryId: s.repositoryId,
  repositoryName: schema.repository.name,
  state: s.state,
  trigger: s.trigger,
  branch: s.branch,
  commitSha: s.commitSha,
  packageCount: s.packageCount,
  severityCounts: s.severityCounts,
  newFindings: s.newFindings,
  resolvedFindings: s.resolvedFindings,
  scannerVersions: s.scannerVersions,
  vulnDbBuiltAt: s.vulnDbBuiltAt,
  error: s.error,
  startedAt: s.startedAt,
  finishedAt: s.finishedAt,
  createdAt: s.createdAt,
};

type Row = { id: string; createdAt: Date } & Record<string, unknown>;

const spec: KeysetSpec<Row> = {
  keys: [s.createdAt, s.id],
  direction: "desc",
  keyOf: (row) => [row.createdAt, row.id],
  parse: [parseDate, parseText],
};

export const scanRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const where = and(
      eq(s.organizationId, actor.organizationId),
      visibleRepository(s.repositoryId, actor),
      input.repositoryId ? eq(s.repositoryId, input.repositoryId) : undefined,
      input.state ? eq(s.state, input.state) : undefined,
    );
    const q = keysetQuery(spec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select(columns)
        .from(s)
        .innerJoin(schema.repository, eq(schema.repository.id, s.repositoryId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(s).where(where),
    ]);
    return c.json(
      toPage(
        spec,
        q,
        rows as Row[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        (row) => row,
      ),
    );
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select(columns)
      .from(s)
      .innerJoin(schema.repository, eq(schema.repository.id, s.repositoryId))
      .where(
        and(
          eq(s.id, c.req.param("id")),
          eq(s.organizationId, actor.organizationId),
          visibleRepository(s.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!row) throw notFound("Scan");
    return c.json(row);
  });
