/**
 * Deprecated and yanked packages (ADR 0051): for organisations that switched the module on, the worker asks the package registries
 * about the names in their repositories' inventories, at most once a day per name, and keeps the answers. Only the package name
 * (and for PyPI the version) is sent; excluded names never. Errors are "not checked", never "fine".
 */
import {
  DEFAULT_REGISTRIES,
  DEPRECATION_LIMITS,
  type DeprecationEcosystem,
  deprecationEcosystemOf,
  isExcluded,
  parseCrates,
  parseNpm,
  parsePypi,
  registryPath,
  type VersionState,
  validPackageName,
  validPackageVersion,
} from "@garnetops/core/deprecated";
import { schema } from "@garnetops/db";
import { and, eq, gt, inArray, isNull, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { httpsGet, type Lookup, OutboundError, readCapped } from "./outbound.ts";

export const DEPRECATED_QUEUE = "deprecated.check";
const s = schema.deprecationSettings;
const ps = schema.packageStatus;

/** One request to a registry: the body as text, or "missing" for a 404 (a name the registry does not have). */
export type RegistryFetch = (
  base: string,
  path: string,
  ecosystem: DeprecationEcosystem,
  own: boolean,
) => Promise<string | "missing">;

/** The real request. `test` points it at a local server (tests only). */
export function registryFetch(test?: { lookup?: Lookup; ca?: string; port?: number }): RegistryFetch {
  return async (base, path, ecosystem, own) => {
    const url = new URL(base);
    try {
      const response = await httpsGet({
        host: url.hostname,
        ...(url.port ? { port: Number(url.port) } : {}),
        path: `${url.pathname.replace(/\/+$/, "")}${path}`,
        timeoutMs: DEPRECATION_LIMITS.timeoutMs,
        allowPrivate: own,
        headers: {
          accept:
            ecosystem === "npm"
              ? "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"
              : "application/json",
          "user-agent": "GarnetOps-Package-Status/1",
        },
        ...(test ? { test } : {}),
      });
      return (await readCapped(response, DEPRECATION_LIMITS.maxBytes)).toString("utf8");
    } catch (error) {
      if (error instanceof OutboundError && error.code === "httpStatus" && error.status === 404)
        return "missing";
      throw error;
    }
  };
}

interface Unit {
  ecosystem: DeprecationEcosystem;
  name: string;
  /** The versions this request answers (npm and crates: all of the name's; PyPI: one). */
  versions: string[];
}

/** Runs `work` over `items`, `limit` at a time. */
async function pool<T>(items: T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const item = items[next++] as T;
        await work(item);
      }
    }),
  );
}

/** Asks the registries about one organisation's packages that are not known or older than a day. */
export async function checkOrganization(
  organizationId: string,
  fetch: RegistryFetch = registryFetch(),
  now = new Date(),
): Promise<void> {
  const [settings] = await db.select().from(s).where(eq(s.organizationId, organizationId)).limit(1);
  if (!settings?.enabled) return;

  const rows = await db
    .selectDistinct({
      type: schema.repositoryPackage.type,
      name: schema.repositoryPackage.name,
      version: schema.repositoryPackage.version,
    })
    .from(schema.repositoryPackage)
    .innerJoin(schema.repository, eq(schema.repository.id, schema.repositoryPackage.repositoryId))
    .where(
      and(eq(schema.repositoryPackage.organizationId, organizationId), isNull(schema.repository.inactiveAt)),
    );

  const own = (e: DeprecationEcosystem) => Boolean(settings.registries[e]);
  const scopeOf = (e: DeprecationEcosystem) => (own(e) ? organizationId : "public");
  const wanted = new Map<string, Unit>();
  let skipped = 0;
  for (const row of rows) {
    const ecosystem = deprecationEcosystemOf(row.type);
    if (!ecosystem) continue;
    if (
      !validPackageName(ecosystem, row.name) ||
      !validPackageVersion(row.version) ||
      isExcluded(row.name, settings.excluded)
    ) {
      skipped += 1;
      continue;
    }
    const key =
      ecosystem === "pypi"
        ? `${ecosystem}\u0000${row.name}\u0000${row.version}`
        : `${ecosystem}\u0000${row.name}`;
    const unit = wanted.get(key) ?? { ecosystem, name: row.name, versions: [] };
    unit.versions.push(row.version);
    wanted.set(key, unit);
  }

  // What is known and younger than a day is not asked again.
  const fresh = new Set(
    (
      await db
        .select({ scope: ps.scope, ecosystem: ps.ecosystem, name: ps.name, version: ps.version })
        .from(ps)
        .where(
          and(
            inArray(ps.scope, ["public", organizationId]),
            gt(ps.checkedAt, new Date(now.getTime() - DEPRECATION_LIMITS.maxAgeMs)),
          ),
        )
    ).map((r) => `${r.scope}\u0000${r.ecosystem}\u0000${r.name}\u0000${r.version}`),
  );
  const units = [...wanted.values()]
    .map((u) => ({
      ...u,
      versions: u.versions.filter(
        (v) => !fresh.has(`${scopeOf(u.ecosystem)}\u0000${u.ecosystem}\u0000${u.name}\u0000${v}`),
      ),
    }))
    .filter((u) => u.versions.length > 0)
    .slice(0, DEPRECATION_LIMITS.maxLookups);

  let failed = 0;
  const problems: Record<string, string> = {};
  await pool(units, DEPRECATION_LIMITS.concurrency, async (unit) => {
    const base = settings.registries[unit.ecosystem] || DEFAULT_REGISTRIES[unit.ecosystem];
    let states: Map<string, VersionState>;
    try {
      const body = await fetch(
        base,
        registryPath(unit.ecosystem, unit.name, unit.versions[0] ?? ""),
        unit.ecosystem,
        own(unit.ecosystem),
      );
      if (body === "missing") {
        states = new Map(unit.versions.map((v) => [v, { state: "unknown" as const, message: null }]));
      } else if (unit.ecosystem === "npm") states = parseNpm(body, unit.versions);
      else if (unit.ecosystem === "crates") states = parseCrates(body, unit.versions);
      else states = new Map([[unit.versions[0] as string, parsePypi(body)]]);
    } catch (error) {
      failed += 1;
      problems[unit.ecosystem] = error instanceof OutboundError ? error.code : "failed";
      return;
    }
    const values = [...states].map(([version, st]) => ({
      scope: scopeOf(unit.ecosystem),
      ecosystem: unit.ecosystem,
      name: unit.name,
      version,
      state: st.state,
      message: st.message,
      checkedAt: now,
    }));
    if (values.length === 0) return;
    await db
      .insert(ps)
      .values(values)
      .onConflictDoUpdate({
        target: [ps.scope, ps.ecosystem, ps.name, ps.version],
        set: {
          state: sql`excluded.state`,
          message: sql`excluded.message`,
          checkedAt: sql`excluded.checked_at`,
        },
      });
  });

  await db
    .update(s)
    .set({ lastRun: { at: now.toISOString(), asked: units.length, failed, skipped, problems } })
    .where(eq(s.organizationId, organizationId));
}

/** The hourly tick: organisations whose last run is more than a day old (or never ran). */
export async function dueOrganizations(now = new Date()): Promise<string[]> {
  const rows = await db
    .select({ id: s.organizationId, lastRun: s.lastRun })
    .from(s)
    .where(eq(s.enabled, true));
  return rows
    .filter((r) => !r.lastRun || now.getTime() - Date.parse(r.lastRun.at) >= DEPRECATION_LIMITS.maxAgeMs)
    .map((r) => r.id);
}

/** Answers older than a week go; an organisation's own registry's answers go with the organisation (no foreign key). */
export async function sweepPackageStatus(now = new Date()): Promise<void> {
  await db
    .delete(ps)
    .where(sql`${ps.checkedAt} < ${new Date(now.getTime() - 7 * DEPRECATION_LIMITS.maxAgeMs)}`);
  await db
    .delete(ps)
    .where(
      sql`${ps.scope} <> 'public' and ${ps.scope} not in (select ${schema.organization.id} from ${schema.organization})`,
    );
}

/** After a branch scan that succeeded: the organisation's new names, if the module is on. One job per organisation at a time. */
export async function queueAfterScan(boss: PgBoss, scanId: string): Promise<void> {
  const [row] = await db
    .select({ organizationId: schema.scan.organizationId })
    .from(schema.scan)
    .innerJoin(s, eq(s.organizationId, schema.scan.organizationId))
    .where(
      and(
        eq(schema.scan.id, scanId),
        eq(schema.scan.state, "succeeded"),
        isNull(schema.scan.ref),
        eq(s.enabled, true),
      ),
    )
    .limit(1);
  if (!row) return;
  const { organizationId } = row;
  await boss.send(
    DEPRECATED_QUEUE,
    { organizationId },
    { retryLimit: 0, expireInSeconds: 1800, singletonKey: organizationId },
  );
}

export async function startDeprecatedChecks(boss: PgBoss): Promise<void> {
  await boss.createQueue(DEPRECATED_QUEUE);
  // Hourly; the ticks without an organisation id pick the ones that are due.
  await boss.schedule(DEPRECATED_QUEUE, "23 * * * *", null, { tz: "UTC" });
  await boss.work<{ organizationId?: string } | null>(DEPRECATED_QUEUE, { batchSize: 1 }, async ([job]) => {
    const orgs = job?.data?.organizationId ? [job.data.organizationId] : await dueOrganizations();
    if (!job?.data?.organizationId) await sweepPackageStatus().catch(() => {});
    for (const org of orgs) {
      await checkOrganization(org).catch((error: Error) =>
        console.error(`deprecated packages ${org}:`, error.name),
      );
    }
  });
}
