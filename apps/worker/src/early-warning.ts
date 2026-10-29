/**
 * Early warnings (ADR 0029): when a newer vulnerability database arrives, the stored package inventories
 * of all repositories are matched against it again, without a clone, by giving grype their package URLs.
 * A match becomes an early warning when it is not a finding of that repository yet and its advisory was
 * published or changed after the database of the repository's last scan: the new database brought it.
 *
 * Early warnings never change findings, grades or gates; the next scan of the repository confirms or
 * clears them (scan.ts). grype runs in the scanner service when there is one (ADR 0028), like a scan.
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { newId } from "@garnetops/core";
import type { NotifyPayload, SeverityCounts } from "@garnetops/core/notifications";
import { VULNDB_PROBE_INTERVAL_MINUTES, vulnDbReportSchema } from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNotNull } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { z } from "zod";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { addAdvisoryDates, type ParsedFinding, parseReport } from "./grype.ts";
import { runGrype } from "./grype-run.ts";
import { queueNotifications } from "./notify.ts";
import { requestMatchPurls } from "./scanner-client.ts";
import { readReport, writeReport } from "./system-report.ts";
import { upsertVulnerabilities } from "./vulnerability-store.ts";

/** Upper bound of distinct package URLs per check; a larger estate is checked in part, never unbounded. */
const MAX_PURLS = 100_000;

const reportSchema = z.object({
  checkedAt: z.string(),
  /** The build time of the database the last check used; a check runs again only for a newer one. */
  dbBuiltAt: z.string().nullable(),
  warnings: z.number().int().min(0),
});

type InventoryRow = {
  organizationId: string;
  organization: string;
  repositoryId: string;
  repositoryName: string;
  name: string;
  version: string;
  type: string;
  purl: string;
  /** The database build time of the repository's last scan. */
  scannedWith: Date | null;
};

/** grype's JSON report for a list of package URLs, from the scanner service or from this container. */
export async function matchPurls(purls: string[], dir: string): Promise<unknown> {
  const list = join(dir, "inventory.purls");
  await writeFile(list, `${purls.join("\n")}\n`, { mode: 0o600 });
  const socket = env.GARNETOPS_SCANNER_SOCKET;
  if (socket) {
    const out = join(dir, "grype.json");
    await requestMatchPurls(socket, list, out);
    return JSON.parse(await readFile(out, "utf8"));
  }
  const out = await runGrype(env.GARNETOPS_GRYPE_BIN, env.GARNETOPS_GRYPE_DB_DIR, `purl:${list}`, dir);
  return JSON.parse(await readFile(out, "utf8"));
}

/** The inventory rows a match is about: the same package URL, or the same name, version and type. */
function rowsFor(
  finding: ParsedFinding,
  byPurl: Map<string, InventoryRow[]>,
  byName: Map<string, InventoryRow[]>,
) {
  const exact = finding.packagePurl ? byPurl.get(finding.packagePurl) : undefined;
  if (exact?.length) return exact;
  return byName.get(`${finding.packageType}|${finding.packageName}@${finding.packageVersion}`) ?? [];
}

/**
 * Checks the stored inventories against the current database once per database build. Returns how many
 * early warnings it added, or null when there was nothing to check.
 */
export async function checkEarlyWarnings(boss: Pick<PgBoss, "send"> | null): Promise<number | null> {
  const vulndb = vulnDbReportSchema.safeParse(await readReport("vulndb"));
  if (!vulndb.success || !vulndb.data.valid || !vulndb.data.builtAt) return null;
  const builtAt = vulndb.data.builtAt;
  const last = reportSchema.safeParse(await readReport("early_warning"));
  if (last.success && last.data.dbBuiltAt === builtAt) return null;

  const rows: InventoryRow[] = await db
    .select({
      organizationId: schema.repository.organizationId,
      organization: schema.organization.name,
      repositoryId: schema.repository.id,
      repositoryName: schema.repository.name,
      name: schema.repositoryPackage.name,
      version: schema.repositoryPackage.version,
      type: schema.repositoryPackage.type,
      purl: schema.repositoryPackage.purl,
      scannedWith: schema.scan.vulnDbBuiltAt,
    })
    .from(schema.repositoryPackage)
    .innerJoin(schema.repository, eq(schema.repository.id, schema.repositoryPackage.repositoryId))
    .innerJoin(schema.organization, eq(schema.organization.id, schema.repository.organizationId))
    .innerJoin(schema.scan, eq(schema.scan.id, schema.repository.lastScanId))
    .where(isNotNull(schema.repositoryPackage.purl))
    .then((list) => list.filter((r): r is InventoryRow => Boolean(r.purl)));

  let created: (typeof schema.earlyWarning.$inferSelect)[] = [];
  const purls = [...new Set(rows.map((r) => r.purl))].slice(0, MAX_PURLS);
  if (purls.length > 0) {
    const dir = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "early-"));
    try {
      const parsed = parseReport(await matchPurls(purls, dir), "early-warning");
      addAdvisoryDates(parsed.vulnerabilities, env.GARNETOPS_GRYPE_DB_DIR);
      created = await store(rows, parsed, new Date(builtAt));
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }
  await writeReport("early_warning", {
    checkedAt: new Date().toISOString(),
    dbBuiltAt: builtAt,
    warnings: created.length,
  } satisfies z.infer<typeof reportSchema>);
  if (boss && created.length > 0) await notify(boss, rows, created);
  return created.length;
}

/** Stores the matches that are new to their repository as early warnings; returns the ones it added. */
async function store(
  rows: InventoryRow[],
  parsed: ReturnType<typeof parseReport>,
  dbBuiltAt: Date,
): Promise<(typeof schema.earlyWarning.$inferSelect)[]> {
  const byPurl = new Map<string, InventoryRow[]>();
  const byName = new Map<string, InventoryRow[]>();
  for (const row of rows) {
    byPurl.set(row.purl, [...(byPurl.get(row.purl) ?? []), row]);
    const key = `${row.type}|${row.name}@${row.version}`;
    byName.set(key, [...(byName.get(key) ?? []), row]);
  }

  const candidates: (typeof schema.earlyWarning.$inferInsert)[] = [];
  for (const finding of parsed.findings.values()) {
    const vulnerability = parsed.vulnerabilities.get(finding.vulnerabilityId);
    const changed = [vulnerability?.publishedAt, vulnerability?.modifiedAt]
      .filter((d): d is Date => d instanceof Date)
      .sort((a, b) => b.getTime() - a.getTime())[0];
    // Without a date it is not provably new; the next scan finds it anyway.
    if (!changed) continue;
    for (const row of rowsFor(finding, byPurl, byName)) {
      if (!row.scannedWith || changed <= row.scannedWith) continue;
      candidates.push({
        id: newId("ewn"),
        organizationId: row.organizationId,
        repositoryId: row.repositoryId,
        vulnerabilityId: finding.vulnerabilityId,
        packageName: finding.packageName,
        packageVersion: finding.packageVersion,
        packageType: finding.packageType,
        fixedIn: finding.fixedIn,
        severity: finding.severity,
        severityRank: finding.severityRank,
        dbBuiltAt,
      });
    }
  }
  if (candidates.length === 0) return [];

  // What a repository already has as a finding, in any state, is no early warning.
  const repositoryIds = [...new Set(candidates.map((c) => c.repositoryId))];
  const known = new Set<string>();
  for (let i = 0; i < repositoryIds.length; i += 500) {
    const found = await db
      .select({
        repositoryId: schema.finding.repositoryId,
        vulnerabilityId: schema.finding.vulnerabilityId,
        packageType: schema.finding.packageType,
        packageName: schema.finding.packageName,
      })
      .from(schema.finding)
      .where(
        and(
          inArray(schema.finding.repositoryId, repositoryIds.slice(i, i + 500)),
          inArray(schema.finding.vulnerabilityId, [...new Set(candidates.map((c) => c.vulnerabilityId))]),
        ),
      );
    for (const f of found)
      known.add(`${f.repositoryId}|${f.vulnerabilityId}|${f.packageType}|${f.packageName}`);
  }
  const fresh = candidates.filter(
    (c) => !known.has(`${c.repositoryId}|${c.vulnerabilityId}|${c.packageType}|${c.packageName}`),
  );
  if (fresh.length === 0) return [];

  const used = new Set(fresh.map((c) => c.vulnerabilityId));
  return db.transaction(async (tx) => {
    await upsertVulnerabilities(
      tx,
      [...parsed.vulnerabilities.values()].filter((v) => used.has(v.id)),
      new Date(),
    );
    const added: (typeof schema.earlyWarning.$inferSelect)[] = [];
    for (let i = 0; i < fresh.length; i += 500) {
      // One per repository, advisory and package version: a warning that exists (open or closed) stays as it is.
      added.push(
        ...(await tx
          .insert(schema.earlyWarning)
          .values(fresh.slice(i, i + 500))
          .onConflictDoNothing()
          .returning()),
      );
    }
    return added;
  });
}

/** One `advisory.new` notification per repository, with its new early warnings per severity. */
async function notify(
  boss: Pick<PgBoss, "send">,
  rows: InventoryRow[],
  created: (typeof schema.earlyWarning.$inferSelect)[],
) {
  const repos = new Map(rows.map((r) => [r.repositoryId, r]));
  const byOrganization = new Map<string, NotifyPayload[]>();
  const origin = env.PUBLIC_URL ? new URL(env.PUBLIC_URL).origin : "";
  for (const repositoryId of new Set(created.map((w) => w.repositoryId))) {
    const repo = repos.get(repositoryId);
    if (!repo) continue;
    const findings: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const w of created.filter((x) => x.repositoryId === repositoryId)) {
      if (w.severity in findings) findings[w.severity as keyof SeverityCounts]++;
    }
    const payload: NotifyPayload = {
      event: "advisory.new",
      organization: repo.organization,
      repository: { id: repositoryId, name: repo.repositoryName },
      findings,
      link: `${origin}/early-warnings?repositoryId=${encodeURIComponent(repositoryId)}`,
      at: new Date().toISOString(),
    };
    byOrganization.set(repo.organizationId, [...(byOrganization.get(repo.organizationId) ?? []), payload]);
  }
  for (const [organizationId, payloads] of byOrganization) {
    await queueNotifications(boss as PgBoss, organizationId, payloads).catch((error: Error) =>
      console.error("early warnings: notify:", error.message),
    );
  }
}

/** Checks after every database probe (ADR 0024); a check that is still running is not started twice. */
export function startEarlyWarnings(boss: PgBoss): () => void {
  let running = false;
  const run = async () => {
    if (running) return;
    running = true;
    try {
      const added = await checkEarlyWarnings(boss);
      if (added !== null) console.log(`early warnings: ${added} new`);
    } catch (error) {
      console.error(`early warnings: ${(error as Error)?.name ?? "error"}: ${(error as Error)?.message}`);
    } finally {
      running = false;
    }
  };
  // The first probe of the database runs when the worker starts; check a little after it.
  const first = setTimeout(run, 2 * 60_000);
  const timer = setInterval(run, VULNDB_PROBE_INTERVAL_MINUTES * 60_000);
  first.unref();
  timer.unref();
  return () => {
    clearTimeout(first);
    clearInterval(timer);
  };
}
