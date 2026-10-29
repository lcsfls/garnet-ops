/**
 * Hosts and containers in the worker (ADR 0034): matching the package list of an image a host runs, and the host's running kernel,
 * against the local vulnerability database (grype through the scanner service, as early warnings do), matching again after every
 * update of the database, the
 * opt-in check for newer images in public registries, and the clean-up of what no host reports any more. Nothing runs for an
 * organisation that has not switched the module on.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { newId } from "@garnetops/core";
import { NONCE_TTL_MS, newerTag, parseImageRef } from "@garnetops/core/agent";
import { vulnDbReportSchema } from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNotNull, isNull, lt, notInArray, or, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { matchPurls } from "./early-warning.ts";
import { env } from "./env.ts";
import { addAdvisoryDates, parseReport } from "./grype.ts";
import { RegistryClient, RegistryError, type RegistryTestHooks } from "./registry.ts";
import { readReport } from "./system-report.ts";
import { upsertVulnerabilities } from "./vulnerability-store.ts";

export const IMAGE_MATCH_QUEUE = "hosts.match";
export const HOSTS_TICK_QUEUE = "hosts.tick";
export const REGISTRY_CHECK_QUEUE = "hosts.registry";
export const KERNEL_MATCH_QUEUE = "hosts.kernel";

/** Images no container has used for this long are forgotten, with their findings. */
const ORPHAN_AFTER_MS = 7 * 24 * 3600_000;
/** A reference is asked about once a day; at most this many per organisation and run, one a second. */
export const REGISTRY_CHECK = { intervalMs: 24 * 3600_000, perOrganization: 300, gapMs: 1000 };

const ci = schema.containerImage;
const cf = schema.containerImageFinding;

const enabledOrganizations = () =>
  db
    .select({ id: schema.hostSettings.organizationId })
    .from(schema.hostSettings)
    .where(eq(schema.hostSettings.enabled, true));

async function moduleOn(organizationId: string): Promise<boolean> {
  const [row] = await db
    .select({ enabled: schema.hostSettings.enabled })
    .from(schema.hostSettings)
    .where(eq(schema.hostSettings.organizationId, organizationId))
    .limit(1);
  return row?.enabled === true;
}

/** Matches one image's packages and replaces its findings. The first time a finding was seen is kept. Never throws. */
export async function matchImage(job: { organizationId: string; imageId: string }): Promise<void> {
  if (!(await moduleOn(job.organizationId))) return;
  const [image] = await db
    .select({ packages: ci.packages })
    .from(ci)
    .where(and(eq(ci.organizationId, job.organizationId), eq(ci.imageId, job.imageId)))
    .limit(1);
  if (!image?.packages) return;
  const where = and(eq(ci.organizationId, job.organizationId), eq(ci.imageId, job.imageId));
  const purls = [...new Set(image.packages.map((p) => p.purl))];
  const now = new Date();
  if (purls.length === 0) {
    await db.delete(cf).where(and(eq(cf.organizationId, job.organizationId), eq(cf.imageId, job.imageId)));
    await db.update(ci).set({ matchedAt: now, matchError: null }).where(where);
    return;
  }
  const dir = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "image-"));
  try {
    const report = parseReport(await matchPurls(purls, dir), `${job.organizationId}:${job.imageId}`);
    addAdvisoryDates(report.vulnerabilities, env.GARNETOPS_GRYPE_DB_DIR);
    await db.transaction(async (tx) => {
      await upsertVulnerabilities(tx, report.vulnerabilities.values(), now);
      const findings = [...report.findings.values()];
      const keep = findings.map((f) => `${f.vulnerabilityId}|${f.packageType}|${f.packageName}`);
      await tx
        .delete(cf)
        .where(
          and(
            eq(cf.organizationId, job.organizationId),
            eq(cf.imageId, job.imageId),
            keep.length
              ? notInArray(
                  sql`${cf.vulnerabilityId} || '|' || ${cf.packageType} || '|' || ${cf.packageName}`,
                  keep,
                )
              : undefined,
          ),
        );
      for (const f of findings) {
        const values = {
          packageVersion: f.packageVersion,
          packagePurl: f.packagePurl,
          fixedIn: f.fixedIn,
          fixState: f.fixState,
          severity: f.severity,
          severityRank: f.severityRank,
          lastSeenAt: now,
        };
        await tx
          .insert(cf)
          .values({
            id: newId("cif"),
            organizationId: job.organizationId,
            imageId: job.imageId,
            vulnerabilityId: f.vulnerabilityId,
            packageName: f.packageName,
            packageType: f.packageType,
            firstSeenAt: now,
            ...values,
          })
          .onConflictDoUpdate({
            target: [cf.organizationId, cf.imageId, cf.vulnerabilityId, cf.packageType, cf.packageName],
            set: values,
          });
      }
      await tx
        .update(ci)
        .set({ matchedAt: now, matchedDbBuilt: report.dbBuiltAt, matchError: null })
        .where(where);
    });
  } catch (error) {
    console.error(`image match: ${(error as Error)?.name ?? "error"}`);
    await db.update(ci).set({ matchedAt: now, matchError: "scanner-failed" }).where(where);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Matches a host's running kernel, named as the distribution's package, and replaces the host's kernel findings. A finding says
 * the running kernel is affected according to the distribution's data; whether the flaw can be used depends on the host's
 * configuration, which the agent does not see. Never throws.
 */
export async function matchKernel(job: { hostId: string }): Promise<void> {
  const h = schema.agentHost;
  const k = schema.hostKernelFinding;
  const [host] = await db.select().from(h).where(eq(h.id, job.hostId)).limit(1);
  if (!host?.kernelPackage || !(await moduleOn(host.organizationId))) return;
  const now = new Date();
  const dir = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "kernel-"));
  try {
    const report = parseReport(await matchPurls([host.kernelPackage.purl], dir), `kernel:${host.id}`);
    addAdvisoryDates(report.vulnerabilities, env.GARNETOPS_GRYPE_DB_DIR);
    await db.transaction(async (tx) => {
      // The kernel may have changed while this ran: only the package that was matched is stored.
      const [current] = await tx
        .select({ kernelPackage: h.kernelPackage })
        .from(h)
        .where(eq(h.id, host.id))
        .for("update");
      if (current?.kernelPackage?.purl !== host.kernelPackage?.purl) return;
      await upsertVulnerabilities(tx, report.vulnerabilities.values(), now);
      const findings = [...report.findings.values()];
      const keep = findings.map((f) => f.vulnerabilityId);
      await tx
        .delete(k)
        .where(and(eq(k.hostId, host.id), keep.length ? notInArray(k.vulnerabilityId, keep) : undefined));
      for (const f of findings) {
        const values = {
          packageVersion: f.packageVersion,
          fixedIn: f.fixedIn,
          fixState: f.fixState,
          severity: f.severity,
          severityRank: f.severityRank,
          lastSeenAt: now,
        };
        await tx
          .insert(k)
          .values({
            id: newId("hkf"),
            organizationId: host.organizationId,
            hostId: host.id,
            vulnerabilityId: f.vulnerabilityId,
            packageName: f.packageName,
            firstSeenAt: now,
            ...values,
          })
          .onConflictDoUpdate({ target: [k.hostId, k.vulnerabilityId, k.packageName], set: values });
      }
      await tx
        .update(h)
        .set({ kernelMatchedAt: now, kernelMatchedDbBuilt: report.dbBuiltAt, kernelMatchError: null })
        .where(eq(h.id, host.id));
    });
  } catch (error) {
    console.error(`kernel match: ${(error as Error)?.name ?? "error"}`);
    await db
      .update(h)
      .set({ kernelMatchedAt: now, kernelMatchError: "scanner-failed" })
      .where(eq(h.id, host.id));
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * One tick (every hour): images whose last match used an older vulnerability database are matched again, nonces past their window
 * and images no host has run for a week are deleted, and organisations that switched the registry check on get it once a day.
 */
export async function hostsTick(boss: Pick<PgBoss, "send">): Promise<void> {
  await db.delete(schema.agentNonce).where(lt(schema.agentNonce.seenAt, new Date(Date.now() - NONCE_TTL_MS)));
  const orphan = sql`not exists (select 1 from ${schema.hostContainer} hc where hc.organization_id = ${ci.organizationId} and hc.image_id = ${ci.imageId})`;
  const gone = await db
    .delete(ci)
    .where(and(orphan, lt(ci.lastSeenAt, new Date(Date.now() - ORPHAN_AFTER_MS))))
    .returning({ organizationId: ci.organizationId, imageId: ci.imageId });
  for (const g of gone) {
    await db.delete(cf).where(and(eq(cf.organizationId, g.organizationId), eq(cf.imageId, g.imageId)));
  }

  const vulndb = vulnDbReportSchema.safeParse(await readReport("vulndb"));
  const builtAt =
    vulndb.success && vulndb.data.valid && vulndb.data.builtAt ? new Date(vulndb.data.builtAt) : null;
  if (builtAt) {
    const stale = await db
      .select({ organizationId: ci.organizationId, imageId: ci.imageId })
      .from(ci)
      .where(
        and(
          isNotNull(ci.packagesAt),
          inArray(ci.organizationId, enabledOrganizations()),
          or(isNull(ci.matchedDbBuilt), lt(ci.matchedDbBuilt, builtAt)),
        ),
      )
      .limit(200);
    for (const image of stale) {
      await boss.send(IMAGE_MATCH_QUEUE, image, {
        retryLimit: 1,
        expireInSeconds: 1800,
        singletonKey: `${image.organizationId}:${image.imageId}`,
      });
    }
    const h = schema.agentHost;
    const kernels = await db
      .select({ hostId: h.id })
      .from(h)
      .where(
        and(
          isNotNull(h.kernelPackage),
          inArray(h.organizationId, enabledOrganizations()),
          or(isNull(h.kernelMatchedDbBuilt), lt(h.kernelMatchedDbBuilt, builtAt)),
        ),
      )
      .limit(200);
    for (const kernel of kernels) {
      await boss.send(KERNEL_MATCH_QUEUE, kernel, {
        retryLimit: 1,
        expireInSeconds: 1800,
        singletonKey: kernel.hostId,
      });
    }
  }

  const checking = await db
    .select({ organizationId: schema.hostSettings.organizationId })
    .from(schema.hostSettings)
    .where(and(eq(schema.hostSettings.enabled, true), eq(schema.hostSettings.registryChecks, true)));
  for (const org of checking) {
    await boss.send(REGISTRY_CHECK_QUEUE, org, {
      retryLimit: 0,
      expireInSeconds: 3600,
      singletonKey: org.organizationId,
    });
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Tests only: a local registry, and no pause between requests. */
let registryTest: { hooks: RegistryTestHooks; gapMs: number } | null = null;
export function setRegistryTestHooks(value: { hooks: RegistryTestHooks; gapMs: number } | null): void {
  registryTest = value;
}

/**
 * Asks the registries about the references the organisation's containers run that were not asked about for a day: the digest of
 * the tag now, and a newer version tag of the same shape. Only while the module and the registry check are on.
 */
export async function checkRegistries(organizationId: string, now = new Date()): Promise<number> {
  const [settings] = await db
    .select()
    .from(schema.hostSettings)
    .where(eq(schema.hostSettings.organizationId, organizationId))
    .limit(1);
  if (!settings?.enabled || !settings.registryChecks) return 0;
  const refs = await db
    .selectDistinct({ ref: schema.hostContainer.imageRef })
    .from(schema.hostContainer)
    .where(eq(schema.hostContainer.organizationId, organizationId));
  const checked = new Map(
    (
      await db
        .select({ ref: schema.imageUpdateCheck.ref, checkedAt: schema.imageUpdateCheck.checkedAt })
        .from(schema.imageUpdateCheck)
        .where(eq(schema.imageUpdateCheck.organizationId, organizationId))
    ).map((r) => [r.ref, r.checkedAt]),
  );
  const due = new Map<string, NonNullable<ReturnType<typeof parseImageRef>>>();
  for (const { ref } of refs) {
    const parsed = parseImageRef(ref);
    if (!parsed?.tag) continue;
    const key = `${parsed.registry}/${parsed.repository}:${parsed.tag}`;
    const last = checked.get(key);
    if (last && now.getTime() - last.getTime() < REGISTRY_CHECK.intervalMs) continue;
    due.set(key, parsed);
    if (due.size >= REGISTRY_CHECK.perOrganization) break;
  }
  const client = new RegistryClient(registryTest?.hooks);
  const gap = registryTest?.gapMs ?? REGISTRY_CHECK.gapMs;
  let first = true;
  for (const [key, ref] of due) {
    if (!first) await sleep(gap);
    first = false;
    let result: {
      currentDigest: string | null;
      newerTag: string | null;
      newerKind: "major" | "minor" | "patch" | null;
      error: string | null;
    };
    try {
      const currentDigest = await client.digest(ref.registry, ref.repository, ref.tag as string);
      const newer = /\d/.test(ref.tag as string)
        ? newerTag(ref.tag as string, await client.tags(ref.registry, ref.repository))
        : null;
      result = { currentDigest, newerTag: newer?.tag ?? null, newerKind: newer?.kind ?? null, error: null };
    } catch (error) {
      result = {
        currentDigest: null,
        newerTag: null,
        newerKind: null,
        error: error instanceof RegistryError ? error.code : "unreachable",
      };
    }
    const values = { checkedAt: new Date(), ...result };
    await db
      .insert(schema.imageUpdateCheck)
      .values({ organizationId, ref: key, ...values })
      .onConflictDoUpdate({
        target: [schema.imageUpdateCheck.organizationId, schema.imageUpdateCheck.ref],
        set: values,
      });
  }
  return due.size;
}

/** The queues and the hourly tick. */
export async function startHosts(boss: PgBoss): Promise<void> {
  await boss.createQueue(IMAGE_MATCH_QUEUE);
  await boss.createQueue(HOSTS_TICK_QUEUE);
  await boss.createQueue(REGISTRY_CHECK_QUEUE);
  await boss.createQueue(KERNEL_MATCH_QUEUE);
  await boss.schedule(HOSTS_TICK_QUEUE, "17 * * * *", null, { tz: "UTC" });
  await boss.work(HOSTS_TICK_QUEUE, { batchSize: 1 }, async () => {
    await hostsTick(boss).catch((error: Error) => console.error("hosts tick:", error.name));
  });
  await boss.work<{ organizationId: string; imageId: string }>(
    IMAGE_MATCH_QUEUE,
    { batchSize: 1 },
    async ([job]) => {
      if (job) await matchImage(job.data);
    },
  );
  await boss.work<{ hostId: string }>(KERNEL_MATCH_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job) await matchKernel(job.data);
  });
  await boss.work<{ organizationId: string }>(REGISTRY_CHECK_QUEUE, { batchSize: 1 }, async ([job]) => {
    if (job)
      await checkRegistries(job.data.organizationId).catch((error: Error) =>
        console.error("registry check:", error.name),
      );
  });
}
