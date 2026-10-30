import { schema, visibleRepository } from "@garnetops/db";
import { and, desc, eq, gte, ne, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

const w = schema.earlyWarning;
const MAX = 500;
/** Closed early warnings stay visible this long, so the outcome of a confirming scan can be seen. */
const CLOSED_DAYS = 30;

/** The worker's report of the last check (installation-wide, no organisation's data in it). */
const lastCheckSchema = z.object({
  checkedAt: z.string(),
  dbBuiltAt: z.string().nullable(),
  warnings: z.number(),
  packages: z.number().optional(),
  repositories: z.number().optional(),
});

const query = z.object({
  state: z.enum(["open", "closed"]).default("open"),
  repositoryId: z.string().min(1).max(40).optional(),
});

/**
 * Early warnings (ADR 0029): new advisories that match a repository's stored packages before a scan saw
 * them. Every member may read them, like findings. Open ones worst first; closed ones from the last 30
 * days, newest first, with what the confirming scan said.
 */
export const earlyWarningRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const input = query.parse(c.req.query());
  const where = and(
    eq(w.organizationId, actor.organizationId),
    visibleRepository(w.repositoryId, actor),
    input.state === "open"
      ? eq(w.state, "open")
      : and(ne(w.state, "open"), gte(w.closedAt, sql`now() - make_interval(days => ${CLOSED_DAYS})`)),
    input.repositoryId ? eq(w.repositoryId, input.repositoryId) : undefined,
  );
  const rows = await db
    .select({
      id: w.id,
      state: w.state,
      repositoryId: w.repositoryId,
      repositoryName: schema.repository.name,
      vulnerabilityId: w.vulnerabilityId,
      packageName: w.packageName,
      packageVersion: w.packageVersion,
      packageType: w.packageType,
      fixedIn: w.fixedIn,
      severity: w.severity,
      cvssScore: schema.vulnerability.cvssScore,
      knownExploited: schema.vulnerability.knownExploited,
      publishedAt: schema.vulnerability.publishedAt,
      detectedAt: w.detectedAt,
      closedAt: w.closedAt,
    })
    .from(w)
    .innerJoin(schema.repository, eq(schema.repository.id, w.repositoryId))
    .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, w.vulnerabilityId))
    .where(where)
    .orderBy(
      ...(input.state === "open"
        ? [desc(w.severityRank), desc(w.detectedAt), w.id]
        : [desc(w.closedAt), w.id]),
    )
    .limit(MAX + 1);
  // What the last check looked at and how many warnings scans closed lately, so an empty page explains itself.
  const [report] = await db
    .select({ data: schema.systemReport.data })
    .from(schema.systemReport)
    .where(eq(schema.systemReport.key, "early_warning"))
    .limit(1);
  const last = lastCheckSchema.safeParse(report?.data);
  const [closed] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(w)
    .where(
      and(
        eq(w.organizationId, actor.organizationId),
        visibleRepository(w.repositoryId, actor),
        ne(w.state, "open"),
        gte(w.closedAt, sql`now() - make_interval(days => ${CLOSED_DAYS})`),
      ),
    );
  // The counts are this organisation's own: the report counts the whole installation.
  const p = schema.repositoryPackage;
  const [stored] = await db
    .select({
      packages: sql<number>`count(distinct ${p.purl})::int`,
      repositories: sql<number>`count(distinct ${p.repositoryId})::int`,
    })
    .from(p)
    .innerJoin(schema.repository, eq(schema.repository.id, p.repositoryId))
    .where(
      and(
        eq(schema.repository.organizationId, actor.organizationId),
        visibleRepository(p.repositoryId, actor),
        sql`${p.purl} is not null`,
      ),
    );
  return c.json({
    items: rows.slice(0, MAX),
    truncated: rows.length > MAX,
    lastCheck: last.success ? { checkedAt: last.data.checkedAt, dbBuiltAt: last.data.dbBuiltAt } : null,
    packages: stored?.packages ?? 0,
    repositories: stored?.repositories ?? 0,
    closedRecently: closed?.n ?? 0,
  });
});
