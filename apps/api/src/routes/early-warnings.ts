import { schema } from "@garnetops/db";
import { and, desc, eq, gte, ne, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

const w = schema.earlyWarning;
const MAX = 500;
/** Closed early warnings stay visible this long, so the outcome of a confirming scan can be seen. */
const CLOSED_DAYS = 30;

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
  return c.json({ items: rows.slice(0, MAX), truncated: rows.length > MAX });
});
