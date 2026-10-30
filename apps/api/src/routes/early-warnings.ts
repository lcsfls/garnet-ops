import { endsSoon, judgeDistribution } from "@garnetops/core/software";
import { schema, visibleRepository } from "@garnetops/db";
import { and, desc, eq, gte, isNotNull, ne, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";
import { modulesOf } from "../lib/modules.ts";
import { softwareOf } from "./exposure.ts";

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
const hostsQuery = z.object({ state: z.enum(["open", "closed"]).default("open") });

/**
 * Early warnings (ADR 0029): new advisories that match a repository's stored packages before a scan saw
 * them. Every member may read them, like findings. Open ones worst first; closed ones from the last 30
 * days, newest first, with what the confirming scan said.
 */
export const earlyWarningRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
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
  })
  /**
   * What runs (ADR 0041): advisories a newer database brought for running images, host kernels and host packages, and
   * distributions whose regular security support ended or ends within 90 days. Every member may read them, like hosts.
   */
  .get("/hosts", async (c) => {
    const actor = c.get("actor");
    const input = hostsQuery.parse(c.req.query());
    if (!(await modulesOf(actor.organizationId)).hosts) {
      return c.json({ enabled: false, items: [], truncated: false, distributions: [], closedRecently: 0 });
    }
    const r = schema.runtimeEarlyWarning;
    const img = schema.containerImage;
    const host = schema.agentHost;
    const recent = and(
      ne(r.state, "open"),
      gte(r.closedAt, sql`now() - make_interval(days => ${CLOSED_DAYS})`),
    );
    const rows = await db
      .select({
        id: r.id,
        state: r.state,
        kind: r.kind,
        subjectId: r.subjectId,
        hostName: host.name,
        imageTags: img.tags,
        vulnerabilityId: r.vulnerabilityId,
        packageName: r.packageName,
        packageVersion: r.packageVersion,
        packageType: r.packageType,
        fixedIn: r.fixedIn,
        severity: r.severity,
        cvssScore: schema.vulnerability.cvssScore,
        knownExploited: schema.vulnerability.knownExploited,
        publishedAt: schema.vulnerability.publishedAt,
        detectedAt: r.detectedAt,
        closedAt: r.closedAt,
      })
      .from(r)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, r.vulnerabilityId))
      .leftJoin(host, eq(host.id, r.hostId))
      .leftJoin(
        img,
        and(eq(r.kind, "image"), eq(img.organizationId, r.organizationId), eq(img.imageId, r.subjectId)),
      )
      .where(
        and(
          eq(r.organizationId, actor.organizationId),
          input.state === "open" ? eq(r.state, "open") : recent,
        ),
      )
      .orderBy(
        ...(input.state === "open"
          ? [desc(r.severityRank), desc(r.detectedAt), r.id]
          : [desc(r.closedAt), r.id]),
      )
      .limit(MAX + 1);
    const [closed] = await db
      .select({ n: sql<number>`count(*)::int` })
      .from(r)
      .where(and(eq(r.organizationId, actor.organizationId), recent));

    // Distributions, judged now against the end-of-life data that ships with GarnetOps.
    const now = new Date();
    const [hosts, images] = await Promise.all([
      db
        .select({
          id: host.id,
          name: host.name,
          packagesDistro: host.hostPackagesDistro,
          kernel: host.kernelPackage,
        })
        .from(host)
        .where(eq(host.organizationId, actor.organizationId)),
      db
        .select({ id: img.imageId, tags: img.tags, distro: img.distro })
        .from(img)
        .where(and(eq(img.organizationId, actor.organizationId), isNotNull(img.distro))),
    ]);
    const distributions = [
      ...hosts.map((h) => ({
        kind: "host" as const,
        id: h.id,
        name: h.name,
        distro: h.packagesDistro ?? h.kernel?.distro ?? null,
      })),
      ...images.map((i) => ({
        kind: "image" as const,
        id: i.id,
        name: i.tags[0] ?? i.id.slice(0, 19),
        distro: i.distro,
      })),
    ]
      .filter((x): x is typeof x & { distro: string } => Boolean(x.distro))
      .map((x) => ({ kind: x.kind, id: x.id, name: x.name, distribution: judgeDistribution(x.distro, now) }))
      .filter((x) => x.distribution.status === "endOfLife" || x.distribution.status === "endingSoon")
      .sort(
        (a, b) =>
          (a.distribution.daysLeft ?? -1e9) - (b.distribution.daysLeft ?? -1e9) ||
          a.name.localeCompare(b.name),
      );

    return c.json({
      enabled: true,
      items: rows.slice(0, MAX).map(({ hostName, imageTags, ...row }) => ({
        ...row,
        subjectName:
          row.kind === "image" ? (imageTags?.[0] ?? row.subjectId.slice(0, 19)) : (hostName ?? row.subjectId),
      })),
      truncated: rows.length > MAX,
      distributions,
      closedRecently: closed?.n ?? 0,
    });
  })
  /**
   * Websites (ADR 0041): software whose release line still gets fixes but ends within 90 days, from each website's last look.
   * The ones past their end are findings already.
   */
  .get("/websites", async (c) => {
    const actor = c.get("actor");
    if (!(await modulesOf(actor.organizationId)).websites) return c.json({ enabled: false, items: [] });
    const a = schema.exposureAsset;
    const assets = await db
      .select({ id: a.id, value: a.value, passive: a.passive })
      .from(a)
      .where(eq(a.organizationId, actor.organizationId));
    const now = new Date();
    const items = assets
      .flatMap((asset) =>
        softwareOf(asset.passive)
          .filter((j) => endsSoon(j, now))
          .map((j) => ({
            assetId: asset.id,
            asset: asset.value,
            name: j.name,
            version: j.version,
            cycle: j.cycle,
            eol: j.eol,
          })),
      )
      .sort((x, y) => (x.eol ?? "").localeCompare(y.eol ?? "") || x.asset.localeCompare(y.asset));
    return c.json({ enabled: true, items });
  });
