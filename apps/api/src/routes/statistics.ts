import { isTimeZone, organizationStatistics, STATISTICS_RANGES, schema } from "@garnetops/db";
import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

const f = schema.finding;
const TOP = 8;

const query = z.object({
  days: z.coerce
    .number()
    .int()
    .refine((d) => (STATISTICS_RANGES as readonly number[]).includes(d), "Unknown range")
    .default(30),
  tz: z.string().refine(isTimeZone, "Unknown time zone").default("UTC"),
});

/** Open findings by severity, as columns for a ranking. */
const openBySeverity = {
  open: sql<number>`count(*)::int`,
  critical: sql<number>`count(*) filter (where ${f.severity} = 'critical')::int`,
  high: sql<number>`count(*) filter (where ${f.severity} = 'high')::int`,
  medium: sql<number>`count(*) filter (where ${f.severity} = 'medium')::int`,
  low: sql<number>`count(*) filter (where ${f.severity} = 'low')::int`,
};
const worstFirst = [
  desc(openBySeverity.critical),
  desc(openBySeverity.high),
  desc(openBySeverity.open),
] as const;
const counted = and(eq(f.state, "open"), inArray(f.severity, ["critical", "high", "medium", "low"]));

/**
 * The statistics page: what happened in the last 30, 90 or 365 days (found, resolved, gate
 * results, scans, fix pull requests, time to fix) and where the open findings are today.
 * Every member may read it, like the overview; it only counts what the findings list shows.
 */
export const statisticsRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const { organizationId } = c.get("actor");
  const { days, tz: timeZone } = query.parse(c.req.query());

  const [stats, repositories, packages, oldest] = await Promise.all([
    organizationStatistics(db, { organizationId, timeZone, days }),
    db
      .select({ id: schema.repository.id, name: schema.repository.name, ...openBySeverity })
      .from(f)
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(and(eq(f.organizationId, organizationId), counted))
      .groupBy(schema.repository.id, schema.repository.name)
      .orderBy(...worstFirst, asc(schema.repository.name))
      .limit(TOP),
    db
      .select({
        name: f.packageName,
        type: f.packageType,
        repositories: sql<number>`count(distinct ${f.repositoryId})::int`,
        ...openBySeverity,
      })
      .from(f)
      .where(and(eq(f.organizationId, organizationId), counted))
      .groupBy(f.packageName, f.packageType)
      .orderBy(...worstFirst, asc(f.packageName))
      .limit(TOP),
    db
      .select({
        id: f.id,
        severity: f.severity,
        vulnerabilityId: f.vulnerabilityId,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        repositoryId: f.repositoryId,
        repositoryName: schema.repository.name,
        firstSeenAt: f.firstSeenAt,
      })
      .from(f)
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(
        and(
          eq(f.organizationId, organizationId),
          eq(f.state, "open"),
          inArray(f.severity, ["critical", "high"]),
        ),
      )
      .orderBy(asc(f.firstSeenAt), asc(f.id))
      .limit(TOP),
  ]);

  return c.json({ ...stats, repositories, packages, oldest, generatedAt: new Date() });
});
