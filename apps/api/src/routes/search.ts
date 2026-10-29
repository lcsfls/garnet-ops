import { repositoryVisibleTo, schema, visibleRepository } from "@garnetops/db";
import { and, asc, eq, ilike, min } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";
import { modulesOf } from "../lib/modules.ts";

const HITS = 5;
const query = z.object({ q: z.string().trim().min(2).max(100) });

/**
 * Quick search for the top bar (Ctrl K): a few repositories, vulnerabilities and packages of the
 * caller's organisation whose name contains the text. Every hit opens a list or page the caller can
 * already see; nothing here is new information.
 */
export const searchRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const { organizationId } = actor;
  const { q } = query.parse(c.req.query());
  const pattern = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
  const f = schema.finding;
  const p = schema.repositoryPackage;
  const [repositories, vulnerabilities, packages] = await Promise.all([
    db
      .select({ id: schema.repository.id, name: schema.repository.name })
      .from(schema.repository)
      .where(and(repositoryVisibleTo(actor), ilike(schema.repository.name, pattern)))
      .orderBy(asc(schema.repository.name))
      .limit(HITS),
    db
      .select({ id: f.vulnerabilityId })
      .from(f)
      .where(
        and(
          eq(f.organizationId, organizationId),
          visibleRepository(f.repositoryId, actor),
          ilike(f.vulnerabilityId, pattern),
        ),
      )
      .groupBy(f.vulnerabilityId)
      .orderBy(asc(f.vulnerabilityId))
      .limit(HITS),
    db
      .select({ name: p.name, type: min(p.type) })
      .from(p)
      .where(
        and(
          eq(p.organizationId, organizationId),
          visibleRepository(p.repositoryId, actor),
          ilike(p.name, pattern),
        ),
      )
      .groupBy(p.name)
      .orderBy(asc(p.name))
      .limit(HITS),
  ]);
  // Monitored websites (ADR 0033), only while the module is on.
  const websites = (await modulesOf(organizationId)).websites
    ? await db
        .select({ id: schema.exposureAsset.id, value: schema.exposureAsset.value })
        .from(schema.exposureAsset)
        .where(
          and(
            eq(schema.exposureAsset.organizationId, organizationId),
            ilike(schema.exposureAsset.value, pattern),
          ),
        )
        .orderBy(asc(schema.exposureAsset.value))
        .limit(HITS)
    : [];
  return c.json({ repositories, vulnerabilities, packages, websites });
});
