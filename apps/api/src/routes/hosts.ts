import { newId } from "@garnetops/core";
import {
  ENROLMENT_TTL_MS,
  hashEnrolmentCode,
  imageRefKey,
  newEnrolmentCode,
  sourceKey,
} from "@garnetops/core/agent";
import { repositoryVisibleTo, schema } from "@garnetops/db";
import { and, asc, desc, eq, gt, inArray, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, requireRole } from "../lib/context.ts";
import { requireModule } from "../lib/modules.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";
import { APP_VERSION } from "../version.ts";

/**
 * Hosts and containers (ADR 0034) for signed-in people: the hosts that run the agent, the containers they reported and the images
 * behind them with their vulnerabilities, linked to the monitored repository they were built from. Everyone in the organisation
 * reads; owners and admins add and remove hosts. Every route answers 409 `module-off` while the module is off.
 */

const h = schema.agentHost;
const hc = schema.hostContainer;
const ci = schema.containerImage;
const cf = schema.containerImageFinding;

/** The agent image of this release; the snippet in the web app names it. */
export const AGENT_IMAGE = `ghcr.io/lcsfls/garnetops-agent:${APP_VERSION}`;
/** A host that has not reported for this long is shown as "not reporting" (the agent reports every 6 hours by default). */
export const STALE_AFTER_MS = 25 * 3600_000;

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Counts = Record<(typeof SEVERITIES)[number], number>;
const emptyCounts = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

/** Open findings per severity for each image. */
async function countsByImage(organizationId: string, imageIds: string[]): Promise<Map<string, Counts>> {
  const map = new Map<string, Counts>();
  if (imageIds.length === 0) return map;
  const rows = await db
    .select({ imageId: cf.imageId, severity: cf.severity, n: sql<number>`count(*)::int` })
    .from(cf)
    .where(and(eq(cf.organizationId, organizationId), inArray(cf.imageId, imageIds)))
    .groupBy(cf.imageId, cf.severity);
  for (const row of rows) {
    const counts = map.get(row.imageId) ?? emptyCounts();
    if (row.severity in counts) counts[row.severity as keyof Counts] += row.n;
    map.set(row.imageId, counts);
  }
  return map;
}

/** Open vulnerabilities per severity of the running kernel of each host. */
async function kernelCounts(organizationId: string): Promise<Map<string, Counts & { total: number }>> {
  const k = schema.hostKernelFinding;
  const rows = await db
    .select({ hostId: k.hostId, severity: k.severity, n: sql<number>`count(*)::int` })
    .from(k)
    .where(eq(k.organizationId, organizationId))
    .groupBy(k.hostId, k.severity);
  const map = new Map<string, Counts & { total: number }>();
  for (const row of rows) {
    const counts = map.get(row.hostId) ?? { ...emptyCounts(), total: 0 };
    if (row.severity in counts && row.severity !== "total") counts[row.severity as keyof Counts] += row.n;
    // A flaw the distribution has not rated yet ("unknown") still makes the kernel affected.
    counts.total += row.n;
    map.set(row.hostId, counts);
  }
  return map;
}

/** Open vulnerabilities per severity of the packages installed on each host itself (systemd agent, ADR 0037). */
async function hostPackageCounts(organizationId: string): Promise<Map<string, Counts>> {
  const p = schema.hostPackageFinding;
  const rows = await db
    .select({ hostId: p.hostId, severity: p.severity, n: sql<number>`count(*)::int` })
    .from(p)
    .where(eq(p.organizationId, organizationId))
    .groupBy(p.hostId, p.severity);
  const map = new Map<string, Counts>();
  for (const row of rows) {
    const counts = map.get(row.hostId) ?? emptyCounts();
    if (row.severity in counts) counts[row.severity as keyof Counts] += row.n;
    map.set(row.hostId, counts);
  }
  return map;
}

/** What the page says about the packages of the host itself: how many, from which distribution, when matched. */
function hostPackagesSummary(host: typeof h.$inferSelect) {
  return {
    count: host.hostPackages?.length ?? null,
    distro: host.hostPackagesDistro,
    reportedAt: host.hostPackagesAt,
    matchedAt: host.hostPackagesMatchedAt,
    matchError: host.hostPackagesMatchError,
  };
}

/** What the page says about a host's kernel: what runs, whether it could be checked, and when. */
function kernelSummary(host: typeof h.$inferSelect) {
  return {
    release: host.kernelRelease,
    package: host.kernelPackage
      ? {
          name: host.kernelPackage.name,
          version: host.kernelPackage.version,
          distro: host.kernelPackage.distro,
        }
      : null,
    /** Why the kernel could not be named as a package (an older agent reports no kernel at all: both null). */
    problem: host.kernelProblem,
    matchedAt: host.kernelMatchedAt,
    matchError: host.kernelMatchError,
  };
}

/** The repositories the person sees, keyed by the address key images are linked with. */
async function visibleRepositoriesByKey(actor: Actor): Promise<Map<string, { id: string; name: string }>> {
  const rows = await db
    .select({ id: schema.repository.id, name: schema.repository.name, url: schema.repository.url })
    .from(schema.repository)
    .where(repositoryVisibleTo(actor));
  const map = new Map<string, { id: string; name: string }>();
  for (const row of rows) {
    const key = sourceKey(row.url);
    if (key && !map.has(key)) map.set(key, { id: row.id, name: row.name });
  }
  return map;
}

/** What the registry check said about a container's reference, if it was checked. */
async function updatesByRef(organizationId: string, refs: string[]) {
  const map = new Map<string, typeof schema.imageUpdateCheck.$inferSelect>();
  if (refs.length === 0) return map;
  const rows = await db
    .select()
    .from(schema.imageUpdateCheck)
    .where(
      and(
        eq(schema.imageUpdateCheck.organizationId, organizationId),
        inArray(schema.imageUpdateCheck.ref, refs),
      ),
    );
  for (const row of rows) map.set(row.ref, row);
  return map;
}

/** A container's update status from the stored check and the digests of the image it runs. */
function updateOf(
  check: typeof schema.imageUpdateCheck.$inferSelect | undefined,
  digests: string[],
): {
  state: "unchecked" | "current" | "newer-build" | "newer-version" | "failed";
  tag: string | null;
  kind: string | null;
} {
  if (!check) return { state: "unchecked", tag: null, kind: null };
  if (check.error) return { state: "failed", tag: null, kind: null };
  if (check.newerTag) return { state: "newer-version", tag: check.newerTag, kind: check.newerKind };
  const running = digests.map((d) => d.slice(d.indexOf("@") + 1));
  if (check.currentDigest && running.length > 0 && !running.includes(check.currentDigest)) {
    return { state: "newer-build", tag: null, kind: null };
  }
  return { state: "current", tag: null, kind: null };
}

const enrolmentBody = z.object({ label: z.string().trim().max(100).optional() });
const renameBody = z.object({ name: z.string().trim().min(1).max(100) });
const settingsBody = z.object({
  registryChecks: z.object({ enabled: z.boolean(), acknowledged: z.boolean().optional() }),
});

export const hostRoutes = new Hono<AppEnv>()
  .use("*", requireModule("hosts"))
  /** The hosts with their counts. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const hosts = await db
      .select()
      .from(h)
      .where(eq(h.organizationId, actor.organizationId))
      .orderBy(asc(h.name));
    const containers = await db
      .select({ hostId: hc.hostId, imageId: hc.imageId, imageRef: hc.imageRef })
      .from(hc)
      .where(eq(hc.organizationId, actor.organizationId));
    const imageIds = [...new Set(containers.map((x) => x.imageId))];
    const counts = await countsByImage(actor.organizationId, imageIds);
    const kernels = await kernelCounts(actor.organizationId);
    const ownPackages = await hostPackageCounts(actor.organizationId);
    const images = imageIds.length
      ? await db
          .select({ imageId: ci.imageId, digests: ci.digests })
          .from(ci)
          .where(and(eq(ci.organizationId, actor.organizationId), inArray(ci.imageId, imageIds)))
      : [];
    const digestsOf = new Map(images.map((i) => [i.imageId, i.digests]));
    const updates = await updatesByRef(
      actor.organizationId,
      containers.map((x) => imageRefKey(x.imageRef)).filter((r): r is string => Boolean(r)),
    );
    const now = Date.now();
    return c.json(
      hosts.map((host) => {
        const mine = containers.filter((x) => x.hostId === host.id);
        const open = emptyCounts();
        for (const imageId of new Set(mine.map((x) => x.imageId))) {
          const n = counts.get(imageId);
          if (n) for (const s of SEVERITIES) open[s] += n[s];
        }
        const updatesAvailable = mine.filter((x) => {
          const ref = imageRefKey(x.imageRef);
          const state = updateOf(ref ? updates.get(ref) : undefined, digestsOf.get(x.imageId) ?? []).state;
          return state === "newer-build" || state === "newer-version";
        }).length;
        return {
          id: host.id,
          name: host.name,
          hostname: host.hostname,
          agentVersion: host.agentVersion,
          dockerVersion: host.dockerVersion,
          os: host.os,
          enrolledAt: host.enrolledAt,
          lastSeenAt: host.lastSeenAt,
          lastInventoryAt: host.lastInventoryAt,
          reporting: Boolean(host.lastInventoryAt && now - host.lastInventoryAt.getTime() < STALE_AFTER_MS),
          runtime: host.runtime,
          containers: mine.length,
          images: new Set(mine.map((x) => x.imageId)).size,
          open,
          hostPackages: { ...hostPackagesSummary(host), open: ownPackages.get(host.id) ?? emptyCounts() },
          updatesAvailable,
          kernel: { ...kernelSummary(host), open: kernels.get(host.id) ?? { ...emptyCounts(), total: 0 } },
        };
      }),
    );
  })
  /** Settings of the module: the opt-in registry check. */
  .get("/settings", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select()
      .from(schema.hostSettings)
      .where(eq(schema.hostSettings.organizationId, actor.organizationId))
      .limit(1);
    let enabledBy: string | null = null;
    if (row?.registryChecksBy) {
      const [u] = await db
        .select({ name: schema.user.name })
        .from(schema.user)
        .where(eq(schema.user.id, row.registryChecksBy))
        .limit(1);
      enabledBy = u?.name ?? null;
    }
    return c.json({
      registryChecks: {
        enabled: row?.registryChecks ?? false,
        enabledAt: row?.registryChecksAt ?? null,
        enabledBy,
      },
      agent: { image: AGENT_IMAGE, serverUrl: env.PUBLIC_URL.replace(/\/+$/, "") },
    });
  })
  .put("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = settingsBody.parse(await c.req.json());
    const s = schema.hostSettings;
    const [row] = await db.select().from(s).where(eq(s.organizationId, actor.organizationId)).limit(1);
    if ((row?.registryChecks ?? false) === body.registryChecks.enabled) return c.json({ ok: true });
    if (body.registryChecks.enabled) {
      // Image names leave the network for the registries: an explicit acknowledgement and a recent sign-in.
      if (body.registryChecks.acknowledged !== true) {
        throw new ProblemError(422, "validation", "The request is not valid", undefined, {
          errors: [{ path: "registryChecks.acknowledged", message: "acknowledgement_required" }],
        });
      }
      requireRecentSignIn(actor);
    }
    const now = new Date();
    const set = {
      registryChecks: body.registryChecks.enabled,
      registryChecksBy: body.registryChecks.enabled ? actor.userId : null,
      registryChecksAt: body.registryChecks.enabled ? now : null,
      updatedAt: now,
    };
    await db
      .insert(s)
      .values({ organizationId: actor.organizationId, ...set })
      .onConflictDoUpdate({ target: s.organizationId, set });
    await audit(
      actor,
      body.registryChecks.enabled ? "host.registry_checks_enabled" : "host.registry_checks_disabled",
      { type: "organization", id: actor.organizationId },
    );
    return c.json({ ok: true });
  })
  /** Open enrolment codes (not used, not expired); the codes themselves are never shown again. */
  .get("/enrolments", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const e = schema.agentEnrolment;
    const rows = await db
      .select({ id: e.id, label: e.label, createdAt: e.createdAt, expiresAt: e.expiresAt })
      .from(e)
      .where(and(eq(e.organizationId, actor.organizationId), isNull(e.usedAt), gt(e.expiresAt, new Date())))
      .orderBy(desc(e.createdAt));
    return c.json(rows);
  })
  /** A new one-time code. It is in this answer only. */
  .post("/enrolments", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    await rateLimit(`host-enrolment:${actor.userId}`, 20, 3600_000);
    const body = enrolmentBody.parse(await c.req.json().catch(() => ({})));
    const code = newEnrolmentCode();
    const id = newId("hen");
    const expiresAt = new Date(Date.now() + ENROLMENT_TTL_MS);
    await db.insert(schema.agentEnrolment).values({
      id,
      organizationId: actor.organizationId,
      codeHash: hashEnrolmentCode(code),
      label: body.label || null,
      createdBy: actor.userId,
      expiresAt,
    });
    await audit(
      actor,
      "host.enrolment_created",
      { type: "host_enrolment", id },
      { label: body.label ?? null },
    );
    return c.json(
      { id, code, expiresAt, image: AGENT_IMAGE, serverUrl: env.PUBLIC_URL.replace(/\/+$/, "") },
      201,
    );
  })
  .delete("/enrolments/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const e = schema.agentEnrolment;
    const done = await db
      .delete(e)
      .where(and(eq(e.id, c.req.param("id")), eq(e.organizationId, actor.organizationId), isNull(e.usedAt)))
      .returning({ id: e.id });
    if (done.length === 0) throw notFound("Enrolment code");
    await audit(actor, "host.enrolment_revoked", { type: "host_enrolment", id: c.req.param("id") });
    return c.body(null, 204);
  })
  /** One image: where it runs, what it is, the repository it was built from and its vulnerabilities. */
  .get("/images/:imageId", async (c) => {
    const actor = c.get("actor");
    const imageId = c.req.param("imageId");
    const [image] = await db
      .select()
      .from(ci)
      .where(and(eq(ci.organizationId, actor.organizationId), eq(ci.imageId, imageId)))
      .limit(1);
    if (!image) throw notFound("Image");
    const running = await db
      .select({
        hostId: hc.hostId,
        hostName: h.name,
        containerId: hc.containerId,
        name: hc.name,
        imageRef: hc.imageRef,
        state: hc.state,
        startedAt: hc.startedAt,
      })
      .from(hc)
      .innerJoin(h, eq(h.id, hc.hostId))
      .where(and(eq(hc.organizationId, actor.organizationId), eq(hc.imageId, imageId)))
      .orderBy(asc(h.name), asc(hc.name));
    const findings = await db
      .select({
        id: cf.id,
        vulnerabilityId: cf.vulnerabilityId,
        packageName: cf.packageName,
        packageVersion: cf.packageVersion,
        packageType: cf.packageType,
        fixedIn: cf.fixedIn,
        fixState: cf.fixState,
        severity: cf.severity,
        severityRank: cf.severityRank,
        firstSeenAt: cf.firstSeenAt,
        cvssScore: schema.vulnerability.cvssScore,
        knownExploited: schema.vulnerability.knownExploited,
        epss: schema.vulnerability.epss,
        description: schema.vulnerability.description,
      })
      .from(cf)
      .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, cf.vulnerabilityId))
      .where(and(eq(cf.organizationId, actor.organizationId), eq(cf.imageId, imageId)))
      .orderBy(desc(cf.severityRank), asc(cf.vulnerabilityId))
      .limit(2000);
    const repository = image.sourceKey
      ? ((await visibleRepositoriesByKey(actor)).get(image.sourceKey) ?? null)
      : null;
    const refs = [
      ...new Set(running.map((r) => imageRefKey(r.imageRef)).filter((r): r is string => Boolean(r))),
    ];
    const updates = await updatesByRef(actor.organizationId, refs);
    return c.json({
      imageId: image.imageId,
      tags: image.tags,
      digests: image.digests,
      os: image.os,
      architecture: image.architecture,
      builtAt: image.builtAt,
      labels: image.labels,
      distro: image.distro,
      packageCount: image.packageCount,
      packagesAt: image.packagesAt,
      matchedAt: image.matchedAt,
      matchError: image.matchError,
      repository,
      running,
      findings,
      updates: refs.map((ref) => ({
        ref,
        ...updateOf(updates.get(ref), image.digests),
        checkedAt: updates.get(ref)?.checkedAt ?? null,
      })),
    });
  })
  /** The containers built from a repository, for its page: "where does this run?". */
  .get("/by-repository/:repositoryId", async (c) => {
    const actor = c.get("actor");
    const [repo] = await db
      .select({ id: schema.repository.id, url: schema.repository.url })
      .from(schema.repository)
      .where(and(eq(schema.repository.id, c.req.param("repositoryId")), repositoryVisibleTo(actor)))
      .limit(1);
    if (!repo) throw notFound("Repository");
    const key = sourceKey(repo.url);
    if (!key) return c.json([]);
    const rows = await db
      .select({
        hostId: hc.hostId,
        hostName: h.name,
        containerId: hc.containerId,
        name: hc.name,
        imageRef: hc.imageRef,
        imageId: hc.imageId,
        revision: sql<string | null>`${ci.labels} ->> 'org.opencontainers.image.revision'`,
        lastSeenAt: hc.lastSeenAt,
      })
      .from(hc)
      .innerJoin(h, eq(h.id, hc.hostId))
      .innerJoin(ci, and(eq(ci.organizationId, hc.organizationId), eq(ci.imageId, hc.imageId)))
      .where(and(eq(hc.organizationId, actor.organizationId), eq(ci.sourceKey, key)))
      .orderBy(asc(h.name), asc(hc.name));
    const counts = await countsByImage(actor.organizationId, [...new Set(rows.map((r) => r.imageId))]);
    return c.json(rows.map((r) => ({ ...r, open: counts.get(r.imageId) ?? emptyCounts() })));
  })
  /**
   * The number the navigation shows next to Agents: hosts that need a look because they stopped reporting or run an
   * image or a kernel with an open critical or high vulnerability, and the worst of those severities.
   */
  .get("/attention", async (c) => {
    const actor = c.get("actor");
    const org = actor.organizationId;
    const k = schema.hostKernelFinding;
    const serious = ["critical", "high"];
    const own = schema.hostPackageFinding;
    const [hosts, images, kernels, ownPackages] = await Promise.all([
      db.select({ id: h.id, lastInventoryAt: h.lastInventoryAt }).from(h).where(eq(h.organizationId, org)),
      db
        .selectDistinct({ hostId: hc.hostId, severity: cf.severity })
        .from(hc)
        .innerJoin(cf, and(eq(cf.organizationId, hc.organizationId), eq(cf.imageId, hc.imageId)))
        .where(and(eq(hc.organizationId, org), inArray(cf.severity, serious))),
      db
        .selectDistinct({ hostId: k.hostId, severity: k.severity })
        .from(k)
        .where(and(eq(k.organizationId, org), inArray(k.severity, serious))),
      db
        .selectDistinct({ hostId: own.hostId, severity: own.severity })
        .from(own)
        .where(and(eq(own.organizationId, org), inArray(own.severity, serious))),
    ]);
    const now = Date.now();
    const flagged = new Set(
      hosts
        .filter((x) => !x.lastInventoryAt || now - x.lastInventoryAt.getTime() >= STALE_AFTER_MS)
        .map((x) => x.id),
    );
    const known = new Set(hosts.map((x) => x.id));
    let worst: "critical" | "high" | null = null;
    for (const row of [...images, ...kernels, ...ownPackages]) {
      if (!known.has(row.hostId)) continue;
      flagged.add(row.hostId);
      if (row.severity === "critical") worst = "critical";
      else if (worst === null) worst = "high";
    }
    return c.json({ count: flagged.size, worst });
  })
  /** One host and its containers. */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [host] = await db
      .select()
      .from(h)
      .where(and(eq(h.id, c.req.param("id")), eq(h.organizationId, actor.organizationId)))
      .limit(1);
    if (!host) throw notFound("Host");
    const rows = await db
      .select({
        containerId: hc.containerId,
        name: hc.name,
        imageRef: hc.imageRef,
        imageId: hc.imageId,
        state: hc.state,
        startedAt: hc.startedAt,
        firstSeenAt: hc.firstSeenAt,
        lastSeenAt: hc.lastSeenAt,
        sourceKey: ci.sourceKey,
        digests: ci.digests,
        revision: sql<string | null>`${ci.labels} ->> 'org.opencontainers.image.revision'`,
        packagesAt: ci.packagesAt,
        matchedAt: ci.matchedAt,
        matchError: ci.matchError,
      })
      .from(hc)
      .leftJoin(ci, and(eq(ci.organizationId, hc.organizationId), eq(ci.imageId, hc.imageId)))
      .where(eq(hc.hostId, host.id))
      .orderBy(asc(hc.name));
    const counts = await countsByImage(actor.organizationId, [...new Set(rows.map((r) => r.imageId))]);
    const repos = await visibleRepositoriesByKey(actor);
    const updates = await updatesByRef(
      actor.organizationId,
      rows.map((r) => imageRefKey(r.imageRef)).filter((r): r is string => Boolean(r)),
    );
    return c.json({
      id: host.id,
      name: host.name,
      hostname: host.hostname,
      agentVersion: host.agentVersion,
      dockerVersion: host.dockerVersion,
      os: host.os,
      enrolledAt: host.enrolledAt,
      lastSeenAt: host.lastSeenAt,
      lastInventoryAt: host.lastInventoryAt,
      reporting: Boolean(
        host.lastInventoryAt && Date.now() - host.lastInventoryAt.getTime() < STALE_AFTER_MS,
      ),
      runtime: host.runtime,
      hostPackages: {
        ...hostPackagesSummary(host),
        findings: await db
          .select({
            id: schema.hostPackageFinding.id,
            vulnerabilityId: schema.hostPackageFinding.vulnerabilityId,
            packageName: schema.hostPackageFinding.packageName,
            packageVersion: schema.hostPackageFinding.packageVersion,
            packageType: schema.hostPackageFinding.packageType,
            fixedIn: schema.hostPackageFinding.fixedIn,
            fixState: schema.hostPackageFinding.fixState,
            severity: schema.hostPackageFinding.severity,
            severityRank: schema.hostPackageFinding.severityRank,
            firstSeenAt: schema.hostPackageFinding.firstSeenAt,
            cvssScore: schema.vulnerability.cvssScore,
            knownExploited: schema.vulnerability.knownExploited,
          })
          .from(schema.hostPackageFinding)
          .innerJoin(
            schema.vulnerability,
            eq(schema.vulnerability.id, schema.hostPackageFinding.vulnerabilityId),
          )
          .where(eq(schema.hostPackageFinding.hostId, host.id))
          .orderBy(
            desc(schema.hostPackageFinding.severityRank),
            asc(schema.hostPackageFinding.vulnerabilityId),
          )
          .limit(2000),
      },
      kernel: {
        ...kernelSummary(host),
        findings: await db
          .select({
            id: schema.hostKernelFinding.id,
            vulnerabilityId: schema.hostKernelFinding.vulnerabilityId,
            packageName: schema.hostKernelFinding.packageName,
            packageVersion: schema.hostKernelFinding.packageVersion,
            fixedIn: schema.hostKernelFinding.fixedIn,
            fixState: schema.hostKernelFinding.fixState,
            severity: schema.hostKernelFinding.severity,
            severityRank: schema.hostKernelFinding.severityRank,
            firstSeenAt: schema.hostKernelFinding.firstSeenAt,
            cvssScore: schema.vulnerability.cvssScore,
            knownExploited: schema.vulnerability.knownExploited,
          })
          .from(schema.hostKernelFinding)
          .innerJoin(
            schema.vulnerability,
            eq(schema.vulnerability.id, schema.hostKernelFinding.vulnerabilityId),
          )
          .where(eq(schema.hostKernelFinding.hostId, host.id))
          .orderBy(desc(schema.hostKernelFinding.severityRank), asc(schema.hostKernelFinding.vulnerabilityId))
          .limit(2000),
      },
      containers: rows.map(({ sourceKey: key, digests, ...r }) => {
        const ref = imageRefKey(r.imageRef);
        return {
          ...r,
          repository: key ? (repos.get(key) ?? null) : null,
          open: counts.get(r.imageId) ?? emptyCounts(),
          update: updateOf(ref ? updates.get(ref) : undefined, digests ?? []),
        };
      }),
    });
  })
  .patch("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = renameBody.parse(await c.req.json());
    const done = await db
      .update(h)
      .set({ name: body.name })
      .where(and(eq(h.id, c.req.param("id")), eq(h.organizationId, actor.organizationId)))
      .returning({ id: h.id });
    if (done.length === 0) throw notFound("Host");
    await audit(actor, "host.renamed", { type: "host", id: c.req.param("id") }, { name: body.name });
    return c.json({ ok: true });
  })
  /** Removes a host: its key no longer opens anything, its containers go, and images no host runs any more go with them. */
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const id = c.req.param("id");
    const removed = await db.transaction(async (tx) => {
      const [host] = await tx
        .delete(h)
        .where(and(eq(h.id, id), eq(h.organizationId, actor.organizationId)))
        .returning({ id: h.id, name: h.name });
      if (!host) return null;
      const orphan = sql`not exists (select 1 from ${hc} where ${hc.organizationId} = ${actor.organizationId} and ${hc.imageId} = ${ci.imageId})`;
      const gone = await tx
        .delete(ci)
        .where(and(eq(ci.organizationId, actor.organizationId), orphan))
        .returning({ imageId: ci.imageId });
      if (gone.length) {
        await tx.delete(cf).where(
          and(
            eq(cf.organizationId, actor.organizationId),
            inArray(
              cf.imageId,
              gone.map((g) => g.imageId),
            ),
          ),
        );
      }
      return host;
    });
    if (!removed) throw notFound("Host");
    await audit(actor, "host.removed", { type: "host", id }, { name: removed.name });
    return c.body(null, 204);
  });
