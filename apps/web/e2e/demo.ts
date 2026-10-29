/**
 * Demo data for the screenshots in the README (e2e/screenshots.spec.ts). Neutral names only
 * (example.com, invented repositories, a fictional person; AGENTS.md rule 7). The advisories are real:
 * they come from the recorded grype report of the worker's test fixture (lodash 4.17.15, minimist 1.2.0),
 * so nothing shown is invented.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { E2E } from "./env.ts";

const require = createRequire(new URL("../../../packages/db/package.json", import.meta.url));
// The pg driver comes from packages/db; only the calls used here are typed (as in seed.ts).
type Client = {
  connect(): Promise<void>;
  query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
  end(): Promise<void>;
};
const pg = require("pg") as { Client: new (options: { connectionString: string }) => Client };

interface Advisory {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  cvss: number | null;
  description: string;
  aliases: string[];
  epss: number | null;
  fixedIn: string[];
  packageName: string;
  packageVersion: string;
}

const RANK = { critical: 5, high: 4, medium: 3, low: 2 } as const;
const DAY = 24 * 3600 * 1000;

/** The advisories of the recorded report, as grype wrote them. */
function advisories(): Advisory[] {
  const report = JSON.parse(
    readFileSync(new URL("../../worker/test/fixtures/grype-npm-vulnerable.json", import.meta.url), "utf8"),
  ) as {
    matches: {
      vulnerability: {
        id: string;
        severity: string;
        description?: string;
        cvss?: { metrics?: { baseScore?: number } }[];
        epss?: { epss?: number }[];
        fix?: { versions?: string[] };
      };
      relatedVulnerabilities?: { id: string }[];
      artifact: { name: string; version: string };
    }[];
  };
  return report.matches.map((m) => ({
    id: m.vulnerability.id,
    severity: m.vulnerability.severity.toLowerCase() as Advisory["severity"],
    cvss: m.vulnerability.cvss?.[0]?.metrics?.baseScore ?? null,
    description: m.vulnerability.description ?? "",
    aliases: (m.relatedVulnerabilities ?? []).map((r) => r.id).filter((id) => id !== m.vulnerability.id),
    epss: m.vulnerability.epss?.[0]?.epss ?? null,
    fixedIn: m.vulnerability.fix?.versions ?? [],
    packageName: m.artifact.name,
    packageVersion: m.artifact.version,
  }));
}

interface DemoRepository {
  id: string;
  name: string;
  /** Which advisories are open (by package), resolved or accepted, and how many days ago they were first seen. */
  open: { packageName: string; daysAgo: number }[];
  resolvedDaysAgo?: number;
  gate: "passed" | "notes" | "blocked";
  packages: [string, string][];
}

const REPOSITORIES: DemoRepository[] = [
  {
    id: "repo_demo000000000000001",
    name: "billing-portal",
    open: [
      { packageName: "minimist", daysAgo: 21 },
      { packageName: "lodash", daysAgo: 44 },
    ],
    gate: "blocked",
    packages: [
      ["lodash", "4.17.15"],
      ["minimist", "1.2.0"],
      ["express", "4.21.2"],
      ["pg", "8.16.3"],
    ],
  },
  {
    id: "repo_demo000000000000002",
    name: "booking-app",
    open: [{ packageName: "minimist", daysAgo: 9 }],
    gate: "notes",
    packages: [
      ["minimist", "1.2.0"],
      ["react", "19.2.0"],
      ["vite", "8.3.5"],
    ],
  },
  {
    id: "repo_demo000000000000003",
    name: "payments-api",
    open: [{ packageName: "lodash", daysAgo: 30 }],
    resolvedDaysAgo: 6,
    gate: "notes",
    packages: [
      ["lodash", "4.17.15"],
      ["fastify", "5.6.1"],
    ],
  },
  {
    id: "repo_demo000000000000004",
    name: "website",
    open: [],
    gate: "passed",
    packages: [
      ["lodash", "4.17.21"],
      ["astro", "5.14.1"],
    ],
  },
  {
    id: "repo_demo000000000000005",
    name: "docs-site",
    open: [],
    gate: "passed",
    packages: [["vitepress", "1.6.4"]],
  },
];

export async function seedDemo(): Promise<void> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    const [org] = (await client.query<{ id: string }>("select id from organization limit 1")).rows;
    if (!org) throw new Error("Run the auth flow first: no organisation in the e2e database");
    await client.query("begin");
    await client.query("update organization set name = 'Example Org' where id = $1", [org.id]);
    await client.query(`update "user" set name = 'Alex Example'`);
    const now = new Date();
    const list = advisories();
    for (const a of list) {
      await client.query(
        `insert into vulnerability (id, severity, cvss_score, description, urls, aliases, known_exploited, epss)
         values ($1, $2, $3, $4, $5, $6, false, $7) on conflict (id) do nothing`,
        [
          a.id,
          a.severity,
          a.cvss,
          a.description,
          JSON.stringify([`https://github.com/advisories/${a.id}`]),
          JSON.stringify(a.aliases),
          a.epss,
        ],
      );
    }
    for (const [i, repo] of REPOSITORIES.entries()) await seedRepository(client, org.id, repo, list, now, i);
    await seedEarlyWarnings(client, org.id, list, now);
    await seedSystem(client, now);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

async function seedRepository(
  client: Client,
  orgId: string,
  repo: DemoRepository,
  list: Advisory[],
  now: Date,
  index: number,
) {
  const at = (days: number, hours = 0) => new Date(now.getTime() - days * DAY - hours * 3_600_000);
  const lastScan = `scan_demo${String(index).padStart(2, "0")}00000000000000`;
  const open = list.filter((a) => repo.open.some((o) => o.packageName === a.packageName));
  const counts: Record<string, number> = {};
  for (const a of open) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
  await client.query(
    `insert into repository (id, organization_id, name, url, auth_kind, branch, last_scan_id, last_scan_at)
     values ($1, $2, $3, $4, 'none', 'main', $5, $6)`,
    [
      repo.id,
      orgId,
      repo.name,
      `https://git.example.com/example-org/${repo.name}.git`,
      lastScan,
      at(0, index + 1),
    ],
  );
  // A scan a day for two weeks, the last one today; one failed run on a single repository.
  for (let day = 13; day >= 0; day--) {
    const id =
      day === 0 ? lastScan : `scan_demo${String(index).padStart(2, "0")}${String(day).padStart(14, "0")}`;
    const failed = index === 2 && day === 4;
    await client.query(
      `insert into scan (id, organization_id, repository_id, state, trigger, branch, commit_sha, package_count,
         severity_counts, new_findings, resolved_findings, scanner_versions, vuln_db_built_at, error, started_at,
         finished_at, created_at)
       values ($1, $2, $3, $4, $5, 'main', $6, $7, $8, 0, 0, $9, $10, $11, $12, $13, $12)`,
      [
        id,
        orgId,
        repo.id,
        failed ? "failed" : "succeeded",
        day === 0 ? "manual" : "schedule",
        failed ? null : `${(index + 1).toString(16)}${"0".repeat(32)}${day.toString(16).padStart(7, "0")}`,
        failed ? null : repo.packages.length * 37,
        failed ? null : JSON.stringify(counts),
        failed ? null : JSON.stringify({ grype: "0.120.1", syft: "1.55.0" }),
        failed ? null : at(day, 6),
        failed ? "The repository host could not be reached." : null,
        at(day, index + 1),
        new Date(at(day, index + 1).getTime() + 40_000),
      ],
    );
    if (!failed) {
      const result = day === 0 ? repo.gate : repo.gate === "blocked" && day > 3 ? "notes" : repo.gate;
      const matches =
        result === "passed"
          ? {}
          : result === "blocked"
            ? { "critical-fixable": { count: counts.critical ?? 0, mode: "block" } }
            : { "high-fixable": { count: counts.high ?? 0, mode: "report" } };
      await client.query(
        `insert into gate_run (id, organization_id, repository_id, scan_id, result, matches, created_at)
         values ($1, $2, $3, $4, $5, $6, $7)`,
        [`gate_${id.slice(5)}`, orgId, repo.id, id, result, JSON.stringify(matches), at(day, index + 1)],
      );
    }
  }
  for (const [n, a] of open.entries()) {
    const first = repo.open.find((o) => o.packageName === a.packageName)?.daysAgo ?? 1;
    await insertFinding(client, orgId, repo, a, n, "open", at(first + (n % 3)), lastScan, null);
  }
  if (repo.resolvedDaysAgo !== undefined) {
    const gone = list.filter((a) => a.packageName === "minimist");
    for (const [n, a] of gone.entries()) {
      await insertFinding(
        client,
        orgId,
        repo,
        a,
        100 + n,
        "resolved",
        at(40),
        lastScan,
        at(repo.resolvedDaysAgo),
      );
    }
  }
  for (const [n, [name, version]] of repo.packages.entries()) {
    await client.query(
      `insert into repository_package (id, organization_id, repository_id, scan_id, name, version, type, purl, licenses)
       values ($1, $2, $3, $4, $5, $6, 'npm', $7, '["MIT"]')`,
      [
        `pkg_demo${index}${String(n).padStart(15, "0")}`,
        orgId,
        repo.id,
        lastScan,
        name,
        version,
        `pkg:npm/${name}@${version}`,
      ],
    );
  }
}

async function insertFinding(
  client: Client,
  orgId: string,
  repo: DemoRepository,
  a: Advisory,
  n: number,
  state: "open" | "resolved",
  firstSeen: Date,
  scanId: string,
  resolvedAt: Date | null,
) {
  await client.query(
    `insert into finding (id, organization_id, repository_id, vulnerability_id, dedup_key, package_name,
       package_version, package_type, package_purl, fixed_in, fix_state, locations, severity, severity_rank, state,
       first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at, resolved_at)
     values ($1, $2, $3, $4, $5, $6, $7, 'npm', $8, $9, 'fixed', $10, $11, $12, $13, $14, $14, $15, $16, $17)`,
    [
      `fnd_demo${repo.id.slice(-2)}${String(n).padStart(14, "0")}`,
      orgId,
      repo.id,
      a.id,
      `${repo.id}|${a.id}|npm|${a.packageName}`,
      a.packageName,
      a.packageVersion,
      `pkg:npm/${a.packageName}@${a.packageVersion}`,
      JSON.stringify(a.fixedIn),
      JSON.stringify(["/package-lock.json"]),
      a.severity,
      RANK[a.severity],
      state,
      scanId,
      firstSeen,
      resolvedAt ?? new Date(),
      resolvedAt,
    ],
  );
}

/** website uses lodash 4.17.21, which two of the recorded advisories still affect (fixed in 4.18.0). */
async function seedEarlyWarnings(client: Client, _orgId: string, list: Advisory[], now: Date) {
  const [org] = (await client.query<{ id: string }>("select id from organization limit 1")).rows;
  const later = list.filter((a) => a.packageName === "lodash" && a.fixedIn.includes("4.18.0"));
  for (const [n, a] of later.entries()) {
    await client.query(
      `insert into early_warning (id, organization_id, repository_id, vulnerability_id, package_name, package_version,
         package_type, fixed_in, severity, severity_rank, detected_at)
       values ($1, $2, 'repo_demo000000000000004', $3, 'lodash', '4.17.21', 'npm', $4, $5, $6, $7)`,
      [
        `ewn_demo${n}`,
        org?.id,
        a.id,
        JSON.stringify(a.fixedIn),
        a.severity,
        RANK[a.severity],
        new Date(now.getTime() - (n + 2) * 3_600_000),
      ],
    );
  }
}

/** A healthy installation: worker running, scanners as pinned and isolated, a current database. */
async function seedSystem(client: Client, now: Date) {
  const ago = (ms: number) => new Date(now.getTime() - ms).toISOString();
  const version = process.env.APP_VERSION ?? "0.0.10";
  await client.query(
    `insert into worker_heartbeat (instance_id, version, started_at, beat_at) values ('wrk_demo00000000000000001', $1, $2, $3)`,
    [version, ago(5 * 3_600_000), ago(0)],
  );
  const reports: Record<string, unknown> = {
    scanners: {
      grype: { version: "0.120.1", reportedAt: ago(3_600_000), problem: null },
      syft: { version: "1.55.0", reportedAt: ago(3_600_000), problem: null },
      isolation: { mode: "service", reachable: true, version, reportedAt: ago(60_000) },
    },
    vulndb: {
      checkedAt: ago(60_000),
      valid: true,
      problem: null,
      schemaVersion: "6.1.5",
      builtAt: ago(7 * 3_600_000),
      source: "anchore",
      providers: {
        available: true,
        items: [
          { name: "nvd", version: "6", capturedAt: ago(8 * 3_600_000), records: 312_400 },
          { name: "github", version: "6", capturedAt: ago(8 * 3_600_000), records: 47_900 },
          { name: "kev", version: "6", capturedAt: ago(8 * 3_600_000), records: 1_480 },
        ],
      },
    },
    vulndb_update: {
      mode: "auto",
      lastAttemptAt: ago(6 * 3_600_000),
      lastSuccessAt: ago(6 * 3_600_000),
      lastResult: "ok",
      reason: null,
      nextAt: new Date(now.getTime() + 18 * 3_600_000).toISOString(),
    },
  };
  for (const [key, data] of Object.entries(reports)) {
    await client.query(
      `insert into system_report (key, data, reported_at) values ($1, $2, now())
       on conflict (key) do update set data = excluded.data, reported_at = now()`,
      [key, JSON.stringify(data)],
    );
  }
}
