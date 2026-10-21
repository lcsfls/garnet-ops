import { pageSizeSchema } from "@garnetops/core/pagination";
import { schema } from "@garnetops/db";
import { and, count, eq, ilike, like, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";
import { type KeysetSpec, keysetQuery, parseText, toPage } from "../lib/paginate.ts";

const p = schema.repositoryPackage;
const f = schema.finding;

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  /** Package name (substring), optionally with a version prefix: "lodash" or "lodash@4.17". */
  q: z.string().trim().max(200).optional(),
  repositoryId: z.string().max(40).optional(),
  /** "1" = only packages with open findings. */
  vulnerable: z.enum(["1"]).optional(),
});

type Row = {
  id: string;
  name: string;
  version: string;
  type: string;
  purl: string | null;
  licenses: string[] | null;
  repositoryId: string;
  repositoryName: string;
  openFindings: number;
  worstSeverityRank: number | null;
};

const spec: KeysetSpec<Row> = {
  keys: [p.name, p.version, p.id],
  direction: "asc",
  keyOf: (r) => [r.name, r.version, r.id],
  parse: [parseText, parseText, parseText],
};

const escapeLike = (s: string) => s.replace(/[%_\\]/g, "\\$&");

/** Open findings of this package in this repository. */
const openFor = sql`${f.repositoryId} = ${p.repositoryId} and ${f.packageName} = ${p.name}
  and ${f.packageVersion} = ${p.version} and ${f.packageType} = ${p.type} and ${f.state} = 'open'`;

/** Package inventory across the organisation's repositories, from each one's latest scan. */
export const packageRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const input = listQuery.parse(c.req.query());
  // "name@version": the last "@" separates them, so scoped npm names (@scope/name) still work.
  const at = input.q ? input.q.lastIndexOf("@") : -1;
  const name = input.q && at > 0 ? input.q.slice(0, at) : input.q;
  const version = input.q && at > 0 ? input.q.slice(at + 1) : undefined;
  const where = and(
    eq(p.organizationId, actor.organizationId),
    name ? ilike(p.name, `%${escapeLike(name)}%`) : undefined,
    version ? like(p.version, `${escapeLike(version)}%`) : undefined,
    input.repositoryId ? eq(p.repositoryId, input.repositoryId) : undefined,
    input.vulnerable ? sql`exists (select 1 from ${f} where ${openFor})` : undefined,
  );
  const q = keysetQuery(spec, input.cursor, input.pageSize);
  const [rows, totalRow] = await Promise.all([
    db
      .select({
        id: p.id,
        name: p.name,
        version: p.version,
        type: p.type,
        purl: p.purl,
        licenses: p.licenses,
        repositoryId: p.repositoryId,
        repositoryName: schema.repository.name,
        openFindings: sql<number>`(select count(*)::int from ${f} where ${openFor})`,
        worstSeverityRank: sql<number | null>`(select max(${f.severityRank}) from ${f} where ${openFor})`,
      })
      .from(p)
      .innerJoin(schema.repository, eq(schema.repository.id, p.repositoryId))
      .where(and(where, q.where))
      .orderBy(...q.orderBy)
      .limit(q.limit),
    db.select({ n: count() }).from(p).where(where),
  ]);
  return c.json(toPage(spec, q, rows, totalRow[0]?.n ?? 0, input.pageSize, Boolean(input.cursor), (r) => r));
});
