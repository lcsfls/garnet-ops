import { schema } from "@garnetops/db";
import { and, asc, eq, ilike, min, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

const HITS = 5;
const query = z.object({ q: z.string().trim().min(2).max(100) });

/**
 * Quick search for the top bar (Ctrl K): a few repositories, servers, Proxmox guests, vulnerabilities and
 * packages of the caller's organisation whose name contains the text. Every hit opens
 * a list or page the caller can already see; nothing here is new information.
 */
export const searchRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const { organizationId } = c.get("actor");
  const { q } = query.parse(c.req.query());
  const pattern = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
  const f = schema.finding;
  const p = schema.repositoryPackage;
  const [repositories, vulnerabilities, packages, servers, guests] = await Promise.all([
    db
      .select({ id: schema.repository.id, name: schema.repository.name })
      .from(schema.repository)
      .where(
        and(eq(schema.repository.organizationId, organizationId), ilike(schema.repository.name, pattern)),
      )
      .orderBy(asc(schema.repository.name))
      .limit(HITS),
    db
      .select({ id: f.vulnerabilityId })
      .from(f)
      .where(and(eq(f.organizationId, organizationId), ilike(f.vulnerabilityId, pattern)))
      .groupBy(f.vulnerabilityId)
      .orderBy(asc(f.vulnerabilityId))
      .limit(HITS),
    db
      .select({ name: p.name, type: min(p.type) })
      .from(p)
      .where(and(eq(p.organizationId, organizationId), ilike(p.name, pattern)))
      .groupBy(p.name)
      .orderBy(asc(p.name))
      .limit(HITS),
    db
      .select({ id: schema.host.id, name: schema.host.name })
      .from(schema.host)
      .where(
        and(
          eq(schema.host.organizationId, organizationId),
          or(ilike(schema.host.name, pattern), ilike(schema.host.address, pattern)),
        ),
      )
      .orderBy(asc(schema.host.name))
      .limit(HITS),
    db
      .select({ id: schema.proxmoxGuest.id, name: schema.proxmoxGuest.name, vmid: schema.proxmoxGuest.vmid })
      .from(schema.proxmoxGuest)
      .where(
        and(
          eq(schema.proxmoxGuest.organizationId, organizationId),
          or(
            ilike(schema.proxmoxGuest.name, pattern),
            sql`${schema.proxmoxGuest.vmid}::text like ${pattern}`,
            sql`${schema.proxmoxGuest.ips}::text ilike ${pattern}`,
          ),
        ),
      )
      .orderBy(asc(schema.proxmoxGuest.name))
      .limit(HITS),
  ]);
  return c.json({
    repositories,
    vulnerabilities,
    packages,
    servers,
    guests,
  });
});
