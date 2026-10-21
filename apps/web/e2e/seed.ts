/**
 * Recorded fixture data for the end-to-end database: one repository with one
 * finished scan and 30 findings. Some fields carry hostile content on purpose,
 * as scanned data can (AGENTS.md: scanned content is hostile input).
 */
import { createRequire } from "node:module";
import { E2E } from "./env.ts";

const require = createRequire(new URL("../../../packages/db/package.json", import.meta.url));
// The pg driver comes from packages/db; only the calls used here are typed.
const pg = require("pg") as {
  Client: new (options: {
    connectionString: string;
  }) => {
    connect(): Promise<void>;
    query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
    end(): Promise<void>;
  };
};

export const SEEDED = {
  repositoryName: "seeded-app",
  total: 30,
  critical: 2,
  high: 5,
  knownExploited: 1,
  hostileId: "CVE-2099-0001",
  /** Fixed three days ago by an upgrade from 2.0.0 to 2.0.1 (patch history). */
  fixedId: "CVE-2099-0100",
  /** Inventory: one package per open finding, left-pad (clean) and the upgraded pkg-fixed. */
  packages: 32,
};

const RANK = { critical: 5, high: 4, medium: 3, low: 2 } as const;

export async function seed(): Promise<void> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    const [org] = (await client.query<{ id: string }>("select id from organization limit 1")).rows;
    if (!org) throw new Error("Run the auth flow first: no organisation in the e2e database");
    const now = new Date();
    const repoId = "repo_e2eseeded000000001";
    const scanId = "scan_e2eseeded000000001";

    await client.query("begin");
    await client.query(
      `insert into repository (id, organization_id, name, url, auth_kind, last_scan_id, last_scan_at)
       values ($1, $2, $3, 'https://git.example.test/team/seeded-app.git', 'none', $4, $5)`,
      [repoId, org.id, SEEDED.repositoryName, scanId, now],
    );
    await client.query(
      `insert into scan (id, organization_id, repository_id, state, trigger, package_count, new_findings,
         resolved_findings, started_at, finished_at, created_at)
       values ($1, $2, $3, 'succeeded', 'manual', 120, $4, 0, $5, $5, $5)`,
      [scanId, org.id, repoId, SEEDED.total, now],
    );
    // Its gate result with the default modes: two critical findings with a fix, reported only.
    await client.query(
      `insert into gate_run (id, organization_id, repository_id, scan_id, result, matches, created_at)
       values ('gate_e2eseeded00000001', $1, $2, $3, 'notes', $4, $5)`,
      [org.id, repoId, scanId, JSON.stringify({ "critical-fixable": { count: 2, mode: "report" } }), now],
    );

    for (let i = 1; i <= SEEDED.total; i++) {
      const severity =
        i <= SEEDED.critical
          ? "critical"
          : i <= SEEDED.critical + SEEDED.high
            ? "high"
            : i % 2
              ? "medium"
              : "low";
      const id = `CVE-2099-${String(i).padStart(4, "0")}`;
      const hostile = id === SEEDED.hostileId;
      await client.query(
        `insert into vulnerability (id, severity, cvss_score, description, urls, aliases, known_exploited,
           epss, published_at)
         values ($1, $2, $3, $4, $5, '[]', $6, $7, $8)`,
        [
          id,
          severity,
          hostile ? 9.8 : 5,
          hostile
            ? `Remote code execution. <img src=x onerror="document.title='pwned'"> <script>document.title='pwned'</script>`
            : `Test vulnerability ${i}.`,
          JSON.stringify(
            hostile
              ? ["javascript:document.title='pwned'", "https://advisories.example.test/CVE-2099-0001"]
              : [`https://advisories.example.test/${id}`],
          ),
          i === 1,
          hostile ? 0.2133 : null,
          hostile ? "2021-02-15T13:15:12Z" : null,
        ],
      );
      await client.query(
        `insert into finding (id, organization_id, repository_id, vulnerability_id, dedup_key, package_name,
           package_version, package_type, fixed_in, locations, severity, severity_rank, state,
           first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at)
         values ($1, $2, $3, $4, $5, $6, '1.0.0', 'npm', $7, $8, $9, $10, 'open', $11, $11, $12, $12)`,
        [
          `fnd_e2e${String(i).padStart(16, "0")}`,
          org.id,
          repoId,
          id,
          `${repoId}|${id}|npm|pkg-${i}`,
          `pkg-${i}`,
          JSON.stringify(i <= 3 ? ["1.0.1"] : []),
          JSON.stringify(["/package-lock.json"]),
          severity,
          RANK[severity],
          scanId,
          new Date(now.getTime() - i * 1000),
        ],
      );
    }
    // A finding that an upgrade fixed: seen ten days ago, resolved three days ago.
    const day = 24 * 3600 * 1000;
    await client.query(
      `insert into vulnerability (id, severity, cvss_score, description, urls, aliases, known_exploited)
       values ($1, 'high', 7.5, 'Fixed test vulnerability.', '[]', '[]', false)`,
      [SEEDED.fixedId],
    );
    await client.query(
      `insert into finding (id, organization_id, repository_id, vulnerability_id, dedup_key, package_name,
         package_version, package_type, fixed_in, locations, severity, severity_rank, state,
         first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at, resolved_at)
       values ('fnd_e2e_fixed', $1, $2, $3, $4, 'pkg-fixed', '2.0.0', 'npm', '["2.0.1"]', '[]', 'high', 4,
         'resolved', $5, $5, $6, $7, $8)`,
      [
        org.id,
        repoId,
        SEEDED.fixedId,
        `${repoId}|${SEEDED.fixedId}|npm|pkg-fixed`,
        scanId,
        new Date(now.getTime() - 10 * day),
        new Date(now.getTime() - 4 * day),
        new Date(now.getTime() - 3 * day),
      ],
    );
    // Inventory: every vulnerable package plus one without findings and the upgraded one.
    await client.query(
      `insert into repository_package (id, organization_id, repository_id, scan_id, name, version, type, purl, licenses)
       select 'pkg_e2e' || lpad(i::text, 16, '0'), $1, $2, $3, 'pkg-' || i, '1.0.0', 'npm',
              'pkg:npm/pkg-' || i || '@1.0.0', '[]'::jsonb
         from generate_series(1, ${SEEDED.total}) as i
       union all
       select 'pkg_e2e_clean', $1, $2, $3, 'left-pad', '1.3.0', 'npm', 'pkg:npm/left-pad@1.3.0', '["MIT"]'::jsonb
       union all
       select 'pkg_e2e_fixed', $1, $2, $3, 'pkg-fixed', '2.0.1', 'npm', 'pkg:npm/pkg-fixed@2.0.1', '["MIT"]'::jsonb`,
      [org.id, repoId, scanId],
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}
