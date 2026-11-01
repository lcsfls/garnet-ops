import {
  activeRepository,
  isTimeZone,
  organizationStatistics,
  STATISTICS_RANGES,
  schema,
  visibleRepository,
} from "@garnetops/db";
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

/** How long the open findings have been open, by severity: up to 7 days, 8 to 30, 31 to 90, more than 90. */
const ageBuckets = {
  severity: f.severity,
  week: sql<number>`count(*) filter (where ${f.firstSeenAt} > now() - interval '7 days')::int`,
  month: sql<number>`count(*) filter (where ${f.firstSeenAt} <= now() - interval '7 days' and ${f.firstSeenAt} > now() - interval '30 days')::int`,
  quarter: sql<number>`count(*) filter (where ${f.firstSeenAt} <= now() - interval '30 days' and ${f.firstSeenAt} > now() - interval '90 days')::int`,
  older: sql<number>`count(*) filter (where ${f.firstSeenAt} <= now() - interval '90 days')::int`,
};

/**
 * The statistics page: what happened in the last 30, 90 or 365 days (found, resolved, gate
 * results, scans, fix pull requests, time to fix) and where the open findings are today.
 * Every member may read it, like the overview; it only counts what the findings list shows.
 */
export const statisticsRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const { organizationId } = actor;
  const { days, tz: timeZone } = query.parse(c.req.query());

  const [stats, repositories, packages, oldest, ages] = await Promise.all([
    organizationStatistics(db, { organizationId, userId: actor.userId, timeZone, days }),
    db
      .select({ id: schema.repository.id, name: schema.repository.name, ...openBySeverity })
      .from(f)
      .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
      .where(
        and(
          eq(f.organizationId, organizationId),
          visibleRepository(f.repositoryId, actor),
          activeRepository(f.repositoryId),
          counted,
        ),
      )
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
      .where(
        and(
          eq(f.organizationId, organizationId),
          visibleRepository(f.repositoryId, actor),
          activeRepository(f.repositoryId),
          counted,
        ),
      )
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
          visibleRepository(f.repositoryId, actor),
          activeRepository(f.repositoryId),
          eq(f.state, "open"),
          inArray(f.severity, ["critical", "high"]),
        ),
      )
      .orderBy(asc(f.firstSeenAt), asc(f.id))
      .limit(TOP),
    db
      .select(ageBuckets)
      .from(f)
      .where(
        and(
          eq(f.organizationId, organizationId),
          visibleRepository(f.repositoryId, actor),
          activeRepository(f.repositoryId),
          counted,
        ),
      )
      .groupBy(f.severity),
  ]);
  // Every severity has a row, also with nothing open, so the chart keeps its shape.
  const openAge = (["critical", "high", "medium", "low"] as const).map((severity) => {
    const row = ages.find((a) => a.severity === severity);
    return {
      severity,
      week: row?.week ?? 0,
      month: row?.month ?? 0,
      quarter: row?.quarter ?? 0,
      older: row?.older ?? 0,
    };
  });

  return c.json({ ...stats, repositories, packages, oldest, openAge, generatedAt: new Date() });
});
