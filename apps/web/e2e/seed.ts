/**
 * Recorded fixture data for the end-to-end database: one repository with one
 * finished scan and 30 findings. Some fields carry hostile content on purpose,
 * as scanned data can (AGENTS.md: scanned content is hostile input).
 */
import { createHash } from "node:crypto";
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

/** Fix proposals (ADR 0014): the manifest of the seeded repository as its last scan recorded it. */
export const FIXES = {
  /** The same text the fake forge serves (apps/worker/test/e2e-forge-worker.ts). */
  manifest: '{"name":"seeded-app","dependencies":{"pkg-1":"^1.0.0","pkg-2":"1.0.0"}}\n',
  /** The write token the tests enter; the fake forge accepts exactly this one. */
  token: "e2e-write-token-0123456789",
  /** The key of the proposal for pkg-1 (see proposalKey in packages/core/src/fix-prs.ts). */
  key: (name: string) =>
    createHash("sha256")
      .update(["repo_e2eseeded000000001", "npm", "package.json", name, "1.0.1"].join("\u001f"))
      .digest("hex")
      .slice(0, 24),
  /** pkg-1 and pkg-2 are declared (pkg-2 has an AI suggestion), pkg-3 is not: it is transitive. */
  proposals: 3,
  editable: 2,
};

/**
 * What the worker reports for the System status page (ADR 0024). No real worker runs here: its part is played by
 * these rows. The scanners and the database are in states that need a look on purpose (syft differs from the pin,
 * the database is four days old and the last update failed); tests change them with `reportStatus`.
 */
export const SYSTEM = {
  workerVersion: "0.0.10",
  /** Advisories per provider in the seeded database report. */
  providers: { nvd: 250_000, github: 41_000 },
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
    // A finding that an upgrade fixed: seen ten days ago, resolved three days ago. At noon UTC, which is
    // the same calendar day in Berlin all year, so the patch history counts 7 days also across a DST change.
    const day = 24 * 3600 * 1000;
    const noonUtc = (daysAgo: number) => {
      const at = new Date(now.getTime() - daysAgo * day);
      at.setUTCHours(12, 0, 0, 0);
      return at;
    };
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
        noonUtc(10),
        noonUtc(4),
        noonUtc(3),
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
    await seedFixes(client, org.id, repoId, scanId, now);
    await seedEarlyWarnings(client, org.id, repoId, now);
    await seedSystemStatusRows(client, now);
    await seedAi(client, org.id, now);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

type Client = InstanceType<typeof pg.Client>;

/** The manifest of the last scan, and two pull requests from the past (one merged, one failed). */
/**
 * Early warnings (ADR 0029): two open ones (a known exploited critical and a medium) and one that a scan
 * confirmed two days ago.
 */
async function seedEarlyWarnings(client: Client, orgId: string, repoId: string, now: Date) {
  const day = 24 * 3600 * 1000;
  await client.query(
    `insert into vulnerability (id, severity, cvss_score, description, urls, aliases, known_exploited)
     values ('GHSA-e2e0-warn-0001', 'critical', 9.8, 'Early warning test.', '[]', '[]', true),
            ('GHSA-e2e0-warn-0002', 'medium', 5.3, 'Early warning test.', '[]', '[]', false),
            ('GHSA-e2e0-warn-0003', 'high', 7.5, 'Early warning test.', '[]', '[]', false)`,
  );
  const insert = (id: string, vuln: string, pkg: string, severity: string, rank: number, extra: string) =>
    client.query(
      `insert into early_warning (id, organization_id, repository_id, vulnerability_id, package_name,
         package_version, package_type, fixed_in, severity, severity_rank, detected_at, state, closed_at)
       values ($1, $2, $3, $4, $5, '1.0.0', 'npm', $6, $7, $8, $9, ${extra})`,
      [
        id,
        orgId,
        repoId,
        vuln,
        pkg,
        JSON.stringify(["1.0.1"]),
        severity,
        rank,
        new Date(now.getTime() - day),
      ],
    );
  await insert("ewn_e2e_crit", "GHSA-e2e0-warn-0001", "pkg-1", "critical", 5, "'open', null");
  await insert("ewn_e2e_medium", "GHSA-e2e0-warn-0002", "pkg-2", "medium", 3, "'open', null");
  await insert(
    "ewn_e2e_done",
    "GHSA-e2e0-warn-0003",
    "pkg-3",
    "high",
    4,
    `'confirmed', now() - interval '2 days'`,
  );
}

async function seedFixes(client: Client, orgId: string, repoId: string, scanId: string, now: Date) {
  const blob = createHash("sha1")
    .update(`blob ${Buffer.byteLength(FIXES.manifest)}\0`)
    .update(FIXES.manifest)
    .digest("hex");
  const dependency = (name: string, spec: string) => ({
    name,
    section: "dependencies",
    spec,
    indirect: false,
    dev: false,
  });
  await client.query(
    `insert into repository_manifest (id, organization_id, repository_id, scan_id, path, kind, blob_sha, size, dependencies)
     values ('mf_e2eseeded0000000001', $1, $2, $3, 'package.json', 'npm', $4, $5, $6)`,
    [
      orgId,
      repoId,
      scanId,
      blob,
      Buffer.byteLength(FIXES.manifest),
      JSON.stringify([dependency("pkg-1", "^1.0.0"), dependency("pkg-2", "1.0.0")]),
    ],
  );
  const [owner] = (
    await client.query<{ user_id: string }>("select user_id from membership where role = 'owner' limit 1")
  ).rows;
  const past = (state: string, name: string, n: number, reason: string | null) =>
    client.query(
      `insert into fix_pr (id, organization_id, repository_id, proposal_key, ecosystem, package_name, from_version,
         to_version, manifest_path, expected_blob_sha, severity, vulnerability_ids, state, reason, branch, base_branch,
         pr_number, pr_url, requested_by, created_at, updated_at, opened_at, closed_at, last_checked_at)
       values ($1, $2, $3, $4, 'npm', $5, '1.0.0', '1.0.1', 'package.json', $6, 'high', '["CVE-2099-0200"]', $7, $8,
         $9, 'main', $10, $11, $12, $13, $13, $13, $14, $13)`,
      [
        `fpr_e2eseeded000000000${n}`,
        orgId,
        repoId,
        `${String(n).repeat(24)}`,
        name,
        blob,
        state,
        reason,
        state === "failed" ? null : `garnetops/fix-${name}-1.0.1`,
        state === "failed" ? null : 20 + n,
        state === "failed" ? null : `https://git.example.test/team/seeded-app/pulls/${20 + n}`,
        owner?.user_id ?? null,
        new Date(now.getTime() - n * 86_400_000),
        state === "merged" ? new Date(now.getTime() - (n - 0.5) * 86_400_000) : null,
      ],
    );
  await past("merged", "old-dep", 1, null);
  await past("failed", "older-dep", 2, "manifest-changed");
}

/** AI triage (ADR 0013). */
export const AI = {
  /** A finding with a finished conversation: triage, a question and an answer with hostile Markdown. */
  talked: { findingId: "fnd_e2e0000000000000002", vulnerabilityId: "CVE-2099-0002" },
  /** The fake model server answers for this VPN overlay address (plain http is only accepted there, on the worker's own networks, or with https) (see apps/worker/test/e2e-ai-worker.ts). */
  baseUrl: "http://100.64.0.20:8092/v1",
  apiKey: "e2e-secret-key",
};

/** A conversation as the worker would have left it, for the screens that show one. */
async function seedAi(client: Client, orgId: string, now: Date) {
  const [owner] = (
    await client.query<{ user_id: string }>("select user_id from membership where role = 'owner' limit 1")
  ).rows;
  const ownerId = owner?.user_id ?? null;
  const thread = "thr_e2eseeded00000000001";
  await client.query(
    "insert into chat_thread (id, organization_id, finding_id, created_by, created_at) values ($1, $2, $3, $4, $5)",
    [thread, orgId, AI.talked.findingId, ownerId, now],
  );
  const triage = {
    exploitability: "likely",
    reachable: "unknown",
    confidence: "medium",
    summary: "pkg-2 is only reachable through the build step, so an attack needs a hostile package.json.",
    recommendation: "Update pkg-2 to 1.0.1 and rebuild. Then check the lockfile.",
    upgradeTo: "1.0.1",
    references: [`https://advisories.example.test/${AI.talked.vulnerabilityId}`],
  };
  const message = (
    id: string,
    role: "user" | "assistant",
    kind: "triage" | "chat",
    content: string,
    extra: { structured?: unknown; context?: unknown } = {},
  ) =>
    client.query(
      `insert into chat_message (id, thread_id, role, kind, content, status, structured, model, prompt_tokens,
         completion_tokens, latency_ms, context, created_by, created_at)
       values ($1, $2, $3, $4, $5, 'complete', $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        id,
        thread,
        role,
        kind,
        content,
        extra.structured ? JSON.stringify(extra.structured) : null,
        role === "assistant" ? "e2e-model" : null,
        role === "assistant" ? 321 : null,
        role === "assistant" ? 54 : null,
        role === "assistant" ? 2300 : null,
        extra.context ? JSON.stringify(extra.context) : null,
        ownerId,
        now,
      ],
    );
  await message("msg_e2eseeded000000001", "assistant", "triage", JSON.stringify(triage), {
    structured: triage,
    context: { prompt: "SEEDED PROMPT: the finding as the model saw it", language: "en" },
  });
  await message("msg_e2eseeded000000002", "user", "chat", "Does the update break anything?");
  await message(
    "msg_e2eseeded000000003",
    "assistant",
    "chat",
    [
      "It is a **patch release**, so nothing should break.",
      "",
      "- run the tests",
      "- read the [changelog](https://advisories.example.test/CVE-2099-0002)",
      "",
      "<script>document.title='pwned'</script> and [click me](javascript:document.title='pwned')",
      "",
      "```sh",
      "npm install pkg-2@1.0.1",
      "```",
    ].join("\n"),
  );
}

async function seedSystemStatusRows(client: Client, now: Date) {
  const ago = (ms: number) => new Date(now.getTime() - ms).toISOString();
  const hours = (n: number) => n * 3_600_000;
  const days = (n: number) => n * 86_400_000;
  await client.query(
    `insert into worker_heartbeat (instance_id, version, started_at, beat_at) values ('wrk_e2eseeded0000000001', $1, $2, $3)`,
    [SYSTEM.workerVersion, ago(hours(2)), ago(0)],
  );
  const reports: Record<string, unknown> = {
    scanners: {
      grype: { version: "0.120.1", reportedAt: ago(hours(2)), problem: null },
      syft: { version: "1.54.0", reportedAt: ago(hours(2)), problem: null },
      isolation: { mode: "service", reachable: true, version: SYSTEM.workerVersion, reportedAt: ago(60_000) },
    },
    vulndb: {
      checkedAt: ago(60_000),
      valid: true,
      problem: null,
      schemaVersion: "6.1.5",
      builtAt: ago(days(4)),
      source: "anchore",
      providers: {
        available: true,
        items: [
          { name: "nvd", version: "6", capturedAt: ago(days(4)), records: SYSTEM.providers.nvd },
          { name: "github", version: "6", capturedAt: ago(days(4)), records: SYSTEM.providers.github },
          { name: "debian", version: "6", capturedAt: null, records: null },
        ],
      },
    },
    vulndb_update: {
      mode: "auto",
      lastAttemptAt: ago(hours(2)),
      lastSuccessAt: ago(days(4)),
      lastResult: "failed",
      reason: "network",
      nextAt: new Date(now.getTime() + hours(22)).toISOString(),
    },
  };
  for (const [key, data] of Object.entries(reports)) {
    await client.query("insert into system_report (key, data) values ($1, $2)", [key, JSON.stringify(data)]);
  }
}

/** One statement on the end-to-end database, for tests that stand in for the worker or age a session. */
export async function sql<R = Record<string, unknown>>(query: string, params: unknown[] = []): Promise<R[]> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    return (await client.query<R>(query, params)).rows;
  } finally {
    await client.end();
  }
}

/** Puts the seeded reports and heartbeat back (after a test changed them). */
export async function resetSystemStatus(): Promise<void> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    await client.query("begin");
    await client.query("delete from system_report");
    await client.query("delete from worker_heartbeat");
    await seedSystemStatusRows(client, new Date());
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

/** Replaces one report of the worker (`scanners`, `vulndb`, `vulndb_update` or `vulndb_build`), as the worker would. */
export async function reportStatus(key: string, data: unknown): Promise<void> {
  await sql(
    `insert into system_report (key, data) values ($1, $2)
     on conflict (key) do update set data = excluded.data, reported_at = now()`,
    [key, JSON.stringify(data)],
  );
}

/** Takes one report away again, as if the worker had not reported it. */
export async function clearStatus(key: string): Promise<void> {
  await sql("delete from system_report where key = $1", [key]);
}

/** The database report as the seed left it, with another build time (days ago) and validity. */
export async function setVulnDb(options: { builtDaysAgo: number | null; valid?: boolean }): Promise<void> {
  const built =
    options.builtDaysAgo === null ? null : new Date(Date.now() - options.builtDaysAgo * 86_400_000);
  const valid = options.valid ?? true;
  await reportStatus("vulndb", {
    checkedAt: new Date().toISOString(),
    valid,
    problem: valid ? null : "missing",
    schemaVersion: valid ? "6.1.5" : null,
    builtAt: built ? built.toISOString() : null,
    source: "anchore",
    providers: valid
      ? {
          available: true,
          items: [
            {
              name: "nvd",
              version: "6",
              capturedAt: built?.toISOString() ?? null,
              records: SYSTEM.providers.nvd,
            },
            {
              name: "github",
              version: "6",
              capturedAt: built?.toISOString() ?? null,
              records: SYSTEM.providers.github,
            },
            { name: "debian", version: "6", capturedAt: null, records: null },
          ],
        }
      : { available: false, items: [] },
  });
}

/** Makes the worker's last heartbeat this many seconds old (a running worker beats every 30 seconds). */
export async function setWorkerBeat(secondsAgo: number): Promise<void> {
  await sql(`update worker_heartbeat set beat_at = now() - ($1 || ' seconds')::interval`, [
    String(secondsAgo),
  ]);
}

/** Makes every session count as signed in just now (or an hour ago), for the step-up rules. */
export async function signedInAt(when: "now" | "an hour ago") {
  await sql(
    when === "now"
      ? "update session set created_at = now()"
      : "update session set created_at = now() - interval '1 hour'",
  );
}
