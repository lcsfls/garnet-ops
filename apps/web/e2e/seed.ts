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

/** Servers seeded for the Servers screens (ADR 0011). */
export const SERVERS = {
  /** Read, Debian 12: 1 critical, 2 high and 1 medium open finding, one resolved, four updates (two security). */
  vulnerable: { id: "host_e2eseeded000000001", name: "web-01", address: "192.0.2.21" },
  /** Read, Ubuntu 24.04: nothing open, nothing pending. */
  clean: { id: "host_e2eseeded000000002", name: "hv-01", address: "192.0.2.2" },
  /** The server presents another host key than the pinned one. */
  changed: { id: "host_e2eseeded000000003", name: "mail-01", address: "192.0.2.25" },
  /** First contact done: the worker read a key that waits for confirmation. */
  pending: {
    id: "host_e2eseeded000000004",
    name: "new-01",
    address: "192.0.2.30",
    fingerprint: fingerprintOf("pending"),
  },
  /** Pinned key, but the last inventory failed. */
  failed: { id: "host_e2eseeded000000005", name: "db-01", address: "192.0.2.31" },
  total: 5,
  /** The fictional installation access key (a throw-away public key; no private half exists). */
  accessFingerprint: fingerprintOf("access"),
};

/** Proxmox VE as the sync would have left it (ADR 0012). No worker runs here: its part is played by these rows. */
export const PROXMOX = {
  /** Confirmed certificate, synced a few minutes ago. */
  main: { id: "pxc_e2eseeded0000000001", name: "Lab cluster", host: "pve1.example.lan" },
  /** First contact done: a certificate waits for confirmation. */
  pending: {
    id: "pxc_e2eseeded0000000002",
    name: "New lab",
    host: "pve-new.example.lan",
    fingerprint: fingerprintOfCertificate("pending"),
  },
  /** The token can do more than read and nobody has acknowledged it. */
  wide: { id: "pxc_e2eseeded0000000003", name: "Wide token", host: "pve-wide.example.lan" },
  /** The server presents another certificate than the pinned one. */
  changed: {
    id: "pxc_e2eseeded0000000004",
    name: "Moved lab",
    host: "pve-moved.example.lan",
    pinned: fingerprintOfCertificate("moved-old"),
    offered: fingerprintOfCertificate("moved-new"),
  },
  guests: {
    web: { id: "pxg_e2eseeded0000000100", vmid: 100, name: "web-01" },
    db: { id: "pxg_e2eseeded0000000101", vmid: 101, name: "db-01" },
    old: { id: "pxg_e2eseeded0000000102", vmid: 102, name: "old-test" },
    cache: { id: "pxg_e2eseeded0000000200", vmid: 200, name: "cache-01", address: "192.0.2.60" },
    app: { id: "pxg_e2eseeded0000000103", vmid: 103, name: "app-01" },
    template: { id: "pxg_e2eseeded0000009000", vmid: 9000, name: "debian-12-template" },
    hostile: {
      id: "pxg_e2eseeded0000000300",
      vmid: 300,
      name: `<img src=x onerror="document.title='pwned'">`,
    },
  },
  total: 7,
  stale: 3,
  untracked: 4,
};

/**
 * UniFi as the sync would have left it (ADR 0022). No worker runs the sync here: its part is played by these rows.
 * The IPS preview is off and there are no threat events; the tests that need them switch them on and clean up.
 */
export const UNIFI = {
  /** Confirmed certificate, synced a few minutes ago: two sites, six devices, 53 clients. */
  main: { id: "ufc_e2eseeded0000000001", name: "Main console", host: "udm.example.lan" },
  /** First contact done: a certificate waits for confirmation. */
  pending: {
    id: "ufc_e2eseeded0000000002",
    name: "New console",
    host: "udm-new.example.lan",
    fingerprint: fingerprintOfCertificate("unifi-pending"),
  },
  /** The console presents another certificate than the pinned one. */
  changed: {
    id: "ufc_e2eseeded0000000003",
    name: "Moved console",
    host: "udm-moved.example.lan",
    pinned: fingerprintOfCertificate("unifi-moved-old"),
    offered: fingerprintOfCertificate("unifi-moved-new"),
  },
  sites: {
    main: { id: "ufs_e2eseeded0000000001", name: "Main office" },
    branch: { id: "ufs_e2eseeded0000000002", name: "Branch" },
  },
  devices: {
    gateway: "gateway.example.lan",
    switch: "switch-1",
    hall: "ap-hall",
    fresh: "ap-new",
    branch: "ap-branch",
    hostile: `<img src=x onerror="document.title='pwned'">`,
  },
  total: 6,
  online: 4,
  offline: 1,
  updatable: 2,
  clients: 53,
  /** The secret row that stands in for the sealed IPS password. */
  ipsSecret: "sec_e2eunifiips00000001",
  ipsUser: "garnetops-view",
};

/** External exposure as the worker would have left it (ADR 0023). The worker of the e2e run only handles what a test starts. */
export const EXPOSURE = {
  /** Verified by DNS, subdomains included, stage 2 on with a finished run: a critical and a high port, an expiring certificate. */
  main: { id: "exa_e2eseeded0000000001", value: "example.com" },
  /** Not verified itself, covered by the parent: a clean site. */
  covered: { id: "exa_e2eseeded0000000002", value: "www.example.com" },
  /** Not verified: an expired certificate and plain HTTP without a redirect. */
  shop: { id: "exa_e2eseeded0000000003", value: "shop.example.net" },
  /** The proof is gone; the last look failed. */
  lost: { id: "exa_e2eseeded0000000004", value: "old.example.org" },
  /** An address asset, with its reverse name. */
  address: { id: "exa_e2eseeded0000000005", value: "203.0.113.20" },
  /** Remote text that is hostile on purpose: it must stay text. */
  hostile: { id: "exa_e2eseeded0000000006", value: "odd.example.com" },
  total: 6,
  attention: 3,
  unverified: 5,
  stage2: 1,
  /** Open findings by severity over all assets. */
  open: { critical: 1, high: 2, medium: 3, low: 9 },
  token: "e2eSeededToken0123456789abcdefghijklmnopqr",
  hostileBanner: `<img src=x onerror="document.title='pwned'">`,
};

/** Wazuh as the sync would have left it (ADR 0015). No worker runs the sync here: its part is played by these rows. */
export const WAZUH = {
  connection: { id: "wzc_e2eseeded0000000001", name: "Lab Wazuh" },
  manager: { id: "wze_e2eseeded0000000001", host: "wazuh-api.example.lan" },
  indexer: { id: "wze_e2eseeded0000000002", host: "wazuh-idx.example.lan" },
  dashboardUrl: "https://wazuh-dashboard.example.lan/app/wz-home",
  enrollmentHost: "wazuh.example.lan",
  agents: {
    manager: { id: "wza_e2eseeded0000000000", agentId: "000", name: "wazuh-manager.example.lan" },
    /** Same address as the seeded server web-01: suggested, not linked. */
    web: { id: "wza_e2eseeded0000000001", agentId: "001", name: "web-01" },
    /** Linked to the seeded server db-01. */
    db: { id: "wza_e2eseeded0000000002", agentId: "002", name: "db-01" },
    app: { id: "wza_e2eseeded0000000003", agentId: "003", name: "app-02.example.lan" },
    win: { id: "wza_e2eseeded0000000004", agentId: "004", name: "win-fs01" },
    spare: { id: "wza_e2eseeded0000000005", agentId: "005", name: "spare-box" },
    hostile: {
      id: "wza_e2eseeded0000000006",
      agentId: "006",
      name: `<img src=x onerror="document.title='pwned'">`,
    },
  },
  /** The monitored agents (the manager itself is not counted). */
  total: 6,
  active: 4,
  /** The path of a file integrity event that tries to be markup and a link. */
  hostilePath: `/tmp/<img src=x onerror="document.title='pwned'"> https://evil.example/phish`,
};

/** The attack overview (ADR 0016): documentation addresses and a tiny synthetic GeoIP dataset that maps them to countries. */
export const ATTACKS = {
  ips: {
    de: "198.51.100.77",
    de2: "198.51.100.101",
    fr: "203.0.113.9",
    br: "2001:db8::bad",
    internal: "10.20.30.40",
    /** Public, but covered by no range of the dataset. */
    unknown: "203.0.114.5",
  },
  /** Organisation names are text from a data file: this one tries to be markup. */
  hostileOrg: `Example Hosting <img src=x onerror="document.title='pwned'"> GmbH`,
  country: [
    ["198.51.100.0", "198.51.100.255", "DE"],
    ["203.0.113.0", "203.0.113.255", "FR"],
    ["192.0.2.0", "192.0.2.127", "NL"],
    ["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "BR"],
  ] as const,
  asn: [
    [
      "198.51.100.0",
      "198.51.100.255",
      64500,
      `Example Hosting <img src=x onerror="document.title='pwned'"> GmbH`,
    ],
    ["203.0.113.0", "203.0.113.255", 64501, "Exemple Reseau"],
    ["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 64502, "Exemplo Telecom"],
  ] as const,
};

/**
 * The live attack feed (ADR 0021): events as the worker would have stored them, newest last. Descriptions are alert
 * text: one tries to be markup. Documentation addresses only; the GeoIP data above maps them to countries.
 */
export const LIVE = {
  hostileDescription: `Web scan <img src=x onerror="document.title='pwned'"> from client`,
  events: [
    {
      doc: "e2e-live-1",
      ip: ATTACKS.ips.de,
      level: 12,
      description: "sshd: brute force trying to get access to the system.",
      agentId: "001",
      agent: "web-01",
      ago: 5,
    },
    {
      doc: "e2e-live-2",
      ip: ATTACKS.ips.fr,
      level: 8,
      description: `Web scan <img src=x onerror="document.title='pwned'"> from client`,
      agentId: "002",
      agent: "db-01",
      ago: 4,
    },
    {
      doc: "e2e-live-3",
      ip: ATTACKS.ips.br,
      level: 9,
      description: "sshd: Attempt to login using a non-existent user",
      agentId: "001",
      agent: "web-01",
      ago: 3,
    },
    {
      doc: "e2e-live-4",
      ip: ATTACKS.ips.internal,
      level: 7,
      description: "sshd: authentication failed from inside",
      agentId: "002",
      agent: "db-01",
      ago: 2,
    },
  ],
};

/** A SHA-256 fingerprint of a made-up certificate, in the colon form Proxmox shows. */
function fingerprintOfCertificate(label: string): string {
  return (
    createHash("sha256")
      .update(`garnetops-e2e-certificate-${label}`)
      .digest("hex")
      .toUpperCase()
      .match(/../g) as string[]
  ).join(":");
}

/** A fake ssh-ed25519 public key blob (base64) and the fingerprint ssh would print for it. */
function keyBlob(label: string): string {
  const type = Buffer.from("ssh-ed25519");
  const body = createHash("sha256").update(`garnetops-e2e-${label}`).digest();
  const length = (n: number) => Buffer.from([0, 0, 0, n]);
  return Buffer.concat([length(type.length), type, length(body.length), body]).toString("base64");
}
function fingerprintOf(label: string): string {
  return `SHA256:${createHash("sha256")
    .update(Buffer.from(keyBlob(label), "base64"))
    .digest("base64")
    .replace(/=+$/, "")}`;
}

/**
 * What the worker reports for the System status page (ADR 0024). No real worker runs here: its part is played by
 * these rows. The scanners and the database are in states that need a look on purpose (syft differs from the pin,
 * the database is four days old and the last update failed); tests change them with `reportStatus`.
 */
export const SYSTEM = {
  workerVersion: "0.0.1",
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
    await seedFixes(client, org.id, repoId, scanId, now);
    await seedServers(client, org.id, now);
    await seedProxmox(client, org.id, now);
    await seedUnifi(client, org.id, now);
    await seedExposure(client, org.id, now);
    await seedWazuhRows(client, org.id, now);
    await seedGeoipRows(client);
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

/** Servers as the worker would have left them: keys, inventories, packages and findings. */
async function seedServers(client: Client, orgId: string, now: Date) {
  const minutes = (n: number) => new Date(now.getTime() - n * 60_000);
  const insertHost = (h: { id: string; name: string; address: string }, extra: Record<string, unknown>) => {
    const columns = Object.keys(extra);
    return client.query(
      `insert into host (id, organization_id, name, address, ${columns.join(", ")})
       values ($1, $2, $3, $4, ${columns.map((_, i) => `$${i + 5}`).join(", ")})`,
      [h.id, orgId, h.name, h.address, ...Object.values(extra)],
    );
  };
  const pinned = (label: string) => ({
    host_key_status: "confirmed",
    host_key_type: "ssh-ed25519",
    host_key: keyBlob(label),
    host_key_fingerprint: fingerprintOf(label),
    host_key_confirmed_at: minutes(60 * 24 * 3),
  });

  await client.query(
    `insert into host_access_key (id, organization_id, public_key, fingerprint, state, allowed_source)
     values ('hak_e2eseeded000000001', $1, $2, $3, 'active', '192.0.2.10')`,
    [orgId, `ssh-ed25519 ${keyBlob("access")} garnetops-host-access`, SERVERS.accessFingerprint],
  );

  await insertHost(SERVERS.vulnerable, {
    ...pinned("web"),
    os_id: "debian",
    os_version_id: "12",
    os_name: "Debian GNU/Linux 12 (bookworm)",
    kernel: "6.1.0-18-amd64",
    arch: "x86_64",
    package_count: 612,
    pending_updates: 4,
    security_updates: 2,
    last_inventory_at: minutes(2),
  });
  await insertHost(SERVERS.clean, {
    ...pinned("hv"),
    os_id: "ubuntu",
    os_version_id: "24.04",
    os_name: "Ubuntu 24.04.1 LTS",
    kernel: "6.8.0-45-generic",
    arch: "x86_64",
    package_count: 1043,
    pending_updates: 0,
    security_updates: 0,
    last_inventory_at: minutes(6),
  });
  await insertHost(SERVERS.changed, {
    ...pinned("mail-old"),
    host_key_status: "changed",
    candidate_key_type: "ssh-ed25519",
    candidate_key: keyBlob("mail-new"),
    candidate_key_fingerprint: fingerprintOf("mail-new"),
    candidate_key_seen_at: minutes(30),
    last_error:
      "The server's host key changed. An admin must confirm the new fingerprint before the inventory runs again.",
    os_name: "Debian GNU/Linux 12 (bookworm)",
    package_count: 541,
    pending_updates: 7,
    security_updates: 3,
    last_inventory_at: minutes(60 * 48),
  });
  await insertHost(SERVERS.pending, {
    candidate_key_type: "ssh-ed25519",
    candidate_key: keyBlob("pending"),
    candidate_key_fingerprint: SERVERS.pending.fingerprint,
    candidate_key_seen_at: minutes(1),
  });
  await insertHost(SERVERS.failed, {
    ...pinned("db"),
    os_name: "Debian GNU/Linux 12 (bookworm)",
    package_count: 388,
    pending_updates: 0,
    security_updates: 0,
    last_inventory_at: minutes(60 * 26),
    last_error: "The server could not be reached.",
  });

  // Inventory history of the first server: two good runs and a failed one.
  const run = (
    id: string,
    hostId: string,
    state: string,
    at: Date,
    values: { newFindings?: number; resolvedFindings?: number; packages?: number; error?: string } = {},
  ) =>
    client.query(
      `insert into host_inventory_run (id, organization_id, host_id, state, trigger, package_count, pending_updates,
         new_findings, resolved_findings, error, started_at, finished_at, created_at)
       values ($1, $2, $3, $4, 'manual', $5, 4, $6, $7, $8, $9, $9, $9)`,
      [
        id,
        orgId,
        hostId,
        state,
        values.packages ?? null,
        values.newFindings ?? null,
        values.resolvedFindings ?? null,
        values.error ?? null,
        at,
      ],
    );
  await run("hrun_e2eseeded00000001", SERVERS.vulnerable.id, "succeeded", minutes(60 * 24), {
    packages: 610,
    newFindings: 5,
    resolvedFindings: 0,
  });
  await run("hrun_e2eseeded00000002", SERVERS.vulnerable.id, "failed", minutes(60 * 12), {
    error: "The server could not be reached.",
  });
  await run("hrun_e2eseeded00000003", SERVERS.vulnerable.id, "succeeded", minutes(2), {
    packages: 612,
    newFindings: 0,
    resolvedFindings: 1,
  });
  await run("hrun_e2eseeded00000004", SERVERS.failed.id, "failed", minutes(60 * 2), {
    error: "The server could not be reached.",
  });

  // Findings: references to vulnerabilities the repository fixture already created.
  const finding = (
    n: number,
    vuln: string,
    severity: string,
    rank: number,
    pkg: string,
    version: string,
    state: string,
  ) =>
    client.query(
      `insert into host_finding (id, organization_id, host_id, vulnerability_id, dedup_key, package_name, package_version,
         package_type, fixed_in, severity, severity_rank, state, first_seen_run_id, last_seen_run_id, first_seen_at,
         last_seen_at, resolved_at)
       values ($1, $2, $3, $4, $5, $6, $7, 'deb', $8, $9, $10, $11, 'hrun_e2eseeded00000001', 'hrun_e2eseeded00000003',
         $12, $12, $13)`,
      [
        `hfn_e2eseeded0000000${n}`,
        orgId,
        SERVERS.vulnerable.id,
        vuln,
        `${SERVERS.vulnerable.id}|${vuln}|deb|${pkg}`,
        pkg,
        version,
        JSON.stringify(state === "open" && n <= 2 ? [`${version}+deb12u1`] : []),
        severity,
        rank,
        state,
        minutes(60 * 24),
        state === "resolved" ? minutes(2) : null,
      ],
    );
  await finding(1, "CVE-2099-0001", "critical", 5, "libssl3", "3.0.11-1~deb12u2", "open");
  await finding(2, "CVE-2099-0003", "high", 4, "openssh-server", "1:9.2p1-2+deb12u1", "open");
  await finding(3, "CVE-2099-0004", "high", 4, "libc6", "2.36-9+deb12u3", "open");
  await finding(4, "CVE-2099-0009", "medium", 3, "tzdata", "2024a-0+deb12u1", "open");
  await finding(5, "CVE-2099-0100", "high", 4, "bash", "5.2.15-2", "resolved");

  const pkg = (n: number, name: string, version: string, upgradableTo: string | null, security: boolean) =>
    client.query(
      `insert into host_package (id, organization_id, host_id, name, version, arch, type, origin, upgradable_to, security_update)
       values ($1, $2, $3, $4, $5, 'amd64', 'deb', null, $6, $7)`,
      [`hpk_e2eseeded0000000${n}`, orgId, SERVERS.vulnerable.id, name, version, upgradableTo, security],
    );
  await pkg(1, "bash", "5.2.15-2+b2", null, false);
  await pkg(2, "libc6", "2.36-9+deb12u3", "2.36-9+deb12u4", true);
  await pkg(3, "libssl3", "3.0.11-1~deb12u2", "3.0.11-1~deb12u3", true);
  await pkg(4, "openssh-server", "1:9.2p1-2+deb12u1", "1:9.2p1-2+deb12u2", false);
  await pkg(5, "tzdata", "2024a-0+deb12u1", "2024b-0+deb12u1", false);
  await pkg(6, "zlib1g", "1:1.2.13.dfsg-1", null, false);
}

async function seedProxmox(client: Client, orgId: string, now: Date) {
  const minutes = (n: number) => new Date(now.getTime() - n * 60_000);
  const days = (n: number) => new Date(now.getTime() - n * 24 * 3600 * 1000);
  const GiB = 1024 ** 3;
  const cluster = (c: { id: string; name: string; host: string }, extra: Record<string, unknown>) => {
    const columns = Object.keys(extra);
    return client.query(
      `insert into proxmox_cluster (id, organization_id, name, api_url, host, port, token_id, ${columns.join(", ")})
       values ($1, $2, $3, $4, $5, 8006, 'garnetops@pve!inventory', ${columns.map((_, i) => `$${i + 6}`).join(", ")})`,
      [c.id, orgId, c.name, `https://${c.host}:8006`, c.host, ...Object.values(extra)],
    );
  };
  const pinned = (label: string) => ({
    cert_status: "confirmed",
    cert_fingerprint: fingerprintOfCertificate(label),
    cert_subject: "CN=pve1.example.lan, O=Proxmox Virtual Environment",
    cert_issuer: "CN=Proxmox Virtual Environment, OU=PVE Cluster Node, O=Proxmox Virtual Environment",
    cert_valid_from: days(300),
    cert_valid_to: days(-3000),
    cert_confirmed_at: days(20),
  });

  await cluster(PROXMOX.main, {
    ...pinned("main"),
    version: "8.2.4",
    cluster_name: "lab-cluster",
    quorate: true,
    backups_readable: true,
    last_sync_at: minutes(5),
  });
  await cluster(PROXMOX.pending, {
    candidate_fingerprint: PROXMOX.pending.fingerprint,
    candidate_subject: "CN=pve-new.example.lan, O=Proxmox Virtual Environment",
    candidate_issuer: "CN=Proxmox Virtual Environment, OU=PVE Cluster Node, O=Proxmox Virtual Environment",
    candidate_valid_from: days(2),
    candidate_valid_to: days(-3650),
    candidate_ca_trusted: false,
    candidate_seen_at: minutes(1),
  });
  await cluster(PROXMOX.wide, {
    ...pinned("wide"),
    version: "9.0.3",
    extra_privileges: JSON.stringify(["Datastore.Allocate", "VM.PowerMgmt"]),
    permissions_checked_at: minutes(10),
    last_error: "The token can do more than read. An admin must acknowledge this before anything is synced.",
  });
  await cluster(PROXMOX.changed, {
    cert_status: "changed",
    cert_fingerprint: PROXMOX.changed.pinned,
    cert_subject: "CN=pve-moved.example.lan, O=Old",
    cert_issuer: "CN=Old CA",
    cert_valid_from: days(300),
    cert_valid_to: days(-100),
    candidate_fingerprint: PROXMOX.changed.offered,
    candidate_subject: "CN=pve-moved.example.lan, O=New",
    candidate_issuer: "CN=New CA",
    candidate_valid_from: days(1),
    candidate_valid_to: days(-365),
    candidate_ca_trusted: false,
    candidate_seen_at: minutes(3),
    last_error:
      "The certificate of the Proxmox server changed. An admin must confirm the new fingerprint before the next sync.",
  });

  const node = (
    n: number,
    name: string,
    values: {
      online: boolean;
      cpu?: number;
      mem?: number;
      disk?: number;
      uptime?: number;
      updates: number | null;
    },
  ) =>
    client.query(
      `insert into proxmox_node (id, organization_id, cluster_id, name, online, cpu, cpus, mem, max_mem, disk, max_disk,
         uptime, pve_version, kernel, pending_updates, last_seen_at)
       values ($1, $2, $3, $4, $5, $6, 8, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        `pxn_e2eseeded000000000${n}`,
        orgId,
        PROXMOX.main.id,
        name,
        values.online,
        values.cpu ?? null,
        values.mem ?? null,
        32 * GiB,
        values.disk ?? null,
        98 * GiB,
        values.uptime ?? null,
        values.online ? "8.2.4" : null,
        values.online ? "6.8.12-1-pve" : null,
        values.updates,
        now,
      ],
    );
  await node(1, "pve1", {
    online: true,
    cpu: 0.042,
    mem: 9 * GiB,
    disk: 14 * GiB,
    uptime: 2_592_000,
    updates: 3,
  });
  await node(2, "pve2", {
    online: true,
    cpu: 0.1,
    mem: 12 * GiB,
    disk: 20 * GiB,
    uptime: 1_296_000,
    updates: 0,
  });
  await node(3, "pve3", { online: false, updates: null });

  const storage = (
    n: number,
    nodeName: string,
    name: string,
    type: string,
    content: string[],
    shared: boolean,
    used: number,
    total: number,
  ) =>
    client.query(
      `insert into proxmox_storage (id, organization_id, cluster_id, node, name, type, content, shared, status, used, total)
       values ($1, $2, $3, $4, $5, $6, $7, $8, 'available', $9, $10)`,
      [
        `pxs_e2eseeded000000000${n}`,
        orgId,
        PROXMOX.main.id,
        nodeName,
        name,
        type,
        JSON.stringify(content),
        shared,
        used,
        total,
      ],
    );
  await storage(1, "pve1", "local", "dir", ["iso", "vztmpl", "backup"], false, 30 * GiB, 98 * GiB);
  await storage(2, "pve1", "nas-backup", "nfs", ["backup"], true, 500 * GiB, 2000 * GiB);

  const guest = (g: { id: string; vmid: number; name: string }, values: Record<string, unknown>) => {
    const base: Record<string, unknown> = {
      type: "qemu",
      node: "pve1",
      status: "running",
      status_since: days(100),
      cpu: 0.05,
      cpus: 2,
      mem: 1 * GiB,
      max_mem: 2 * GiB,
      max_disk: 20 * GiB,
      uptime: 864_000,
      ostype: "l26",
      in_backup_job: true,
      last_backup_at: days(1),
      snapshot_count: 0,
      first_seen_at: days(30),
      last_seen_at: now,
      ...values,
    };
    const columns = Object.keys(base);
    return client.query(
      `insert into proxmox_guest (id, organization_id, cluster_id, vmid, name, ${columns.join(", ")})
       values ($1, $2, $3, $4, $5, ${columns.map((_, i) => `$${i + 6}`).join(", ")})`,
      [
        g.id,
        orgId,
        PROXMOX.main.id,
        g.vmid,
        g.name,
        ...Object.values(base).map((v) => (Array.isArray(v) ? JSON.stringify(v) : v)),
      ],
    );
  };
  const G = PROXMOX.guests;
  await guest(G.web, { tags: ["prod", "web"], ha_state: "started", ips: ["192.0.2.50"] });
  await guest(G.db, {
    node: "pve2",
    cpu: 0.2,
    cpus: 4,
    mem: 6 * GiB,
    max_mem: 8 * GiB,
    max_disk: 100 * GiB,
    last_backup_at: null,
    tags: ["prod", "db"],
  });
  await guest(G.old, {
    node: "pve2",
    status: "stopped",
    status_since: days(45),
    cpu: null,
    mem: null,
    uptime: null,
    ostype: "win10",
    in_backup_job: false,
    last_backup_at: days(2),
  });
  await guest(G.cache, {
    type: "lxc",
    ostype: "debian",
    cpu: 0.001,
    cpus: 1,
    mem: 200 * 1024 ** 2,
    max_mem: 512 * 1024 ** 2,
    max_disk: 4 * GiB,
    uptime: 86_400,
    snapshot_count: 1,
    newest_snapshot_at: days(40),
    oldest_snapshot_at: days(40),
    ips: [PROXMOX.guests.cache.address],
    tags: ["cache"],
  });
  await guest(G.app, {
    node: "pve2",
    ha_state: "started",
    ips: ["192.0.2.61", "2001:db8::61"],
    last_backup_at: days(3),
  });
  await guest(G.template, {
    status: "stopped",
    template: true,
    status_since: days(200),
    cpu: null,
    mem: null,
    uptime: null,
    last_backup_at: null,
    in_backup_job: false,
  });
  await guest(G.hostile, { type: "lxc", node: "pve2", tags: [] });

  // The first server is a Proxmox guest: linked through source and source_ref (the lookup is by reference only).
  await client.query("update host set source = 'proxmox', source_ref = $1 where id = $2", [
    `${PROXMOX.main.id}:${G.web.vmid}`,
    SERVERS.vulnerable.id,
  ]);

  await client.query(
    `insert into proxmox_sync_run (id, organization_id, cluster_id, state, trigger, node_count, guest_count, request_count, warnings,
       started_at, finished_at, created_at)
     values ('pxr_e2eseeded0000000001', $1, $2, 'succeeded', 'schedule', 3, $3, 41, '["nodeOffline"]', $4, $4, $4)`,
    [orgId, PROXMOX.main.id, PROXMOX.total, minutes(5)],
  );
}

async function seedExposure(client: Client, orgId: string, now: Date) {
  const minutes = (n: number) => new Date(now.getTime() - n * 60_000);
  const days = (n: number) => new Date(now.getTime() - n * 24 * 3600 * 1000);
  const iso = (d: Date) => d.toISOString();
  const cert = (name: string, validTo: Date, over: Record<string, unknown> = {}) => ({
    subject: name,
    issuer: "Example Test CA",
    sans: [name],
    validFrom: iso(days(60)),
    validTo: iso(validTo),
    fingerprint: fingerprintOfCertificate(`exposure-${name}`),
    keyType: "ec",
    keyBits: 256,
    selfSigned: false,
    ...over,
  });
  const tls = (
    address: string,
    validTo: Date,
    over: Record<string, unknown> = {},
    certOver: Record<string, unknown> = {},
  ) => ({
    address,
    port: 443,
    ok: true,
    error: null,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    trusted: true,
    trustError: null,
    nameMatches: true,
    cert: cert(address, validTo, certOver),
    chainLength: 2,
    legacy: { tls10: false, tls11: false },
    ...over,
  });
  const headers = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
  };
  const dnsFull = (name: string) => ({
    failed: [],
    a: ["203.0.113.10"],
    aaaa: [],
    cname: [],
    mx: [{ priority: 10, exchange: `mail.${name}` }],
    ns: [`ns1.${name}`, "ns.dns-provider.example.net"],
    caa: [{ critical: false, tag: "issue", value: "ca.example.net" }],
    caaFound: true,
    spf: { records: 1, policy: "fail", record: "v=spf1 mx -all" },
    dmarc: { found: true, policy: "reject", record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" },
    dnssec: "unknown",
  });
  const passive = (over: Record<string, unknown>) => ({
    version: 1,
    takenAt: iso(minutes(30)),
    kind: "domain",
    addresses: ["203.0.113.10"],
    nonPublic: [],
    ptr: [],
    plain: {
      address: "203.0.113.10",
      status: 301,
      location: "https://example.com/",
      redirectsToHttps: true,
      error: null,
    },
    geo: [{ address: "203.0.113.10", country: "DE", asn: 64500, org: "Example Hosting" }],
    resolves: true,
    httpsOpen: true,
    ...over,
  });
  const http = (
    url: string,
    status: number,
    hdrs: Record<string, string>,
    extra: Record<string, unknown> = {},
  ) => ({
    address: "203.0.113.10",
    url,
    finalUrl: url,
    status,
    redirects: [],
    headers: hdrs,
    error: null,
    ...extra,
  });
  const asset = (a: { id: string; value: string }, kind: "domain" | "ip", cols: Record<string, unknown>) => {
    const columns = Object.keys(cols);
    return client.query(
      `insert into exposure_asset (id, organization_id, kind, value, verify_token, ${columns.join(", ")})
       values ($1, $2, $3, $4, $5, ${columns.map((_, i) => `$${i + 6}`).join(", ")})`,
      [
        a.id,
        orgId,
        kind,
        a.value,
        EXPOSURE.token + a.id.slice(-1),
        ...columns.map((c) =>
          typeof cols[c] === "object" && cols[c] !== null && !(cols[c] instanceof Date)
            ? JSON.stringify(cols[c])
            : cols[c],
        ),
      ],
    );
  };

  const main = EXPOSURE.main;
  await asset(main, "domain", {
    include_subdomains: true,
    verify_state: "verified",
    verify_method: "dns",
    verified_at: minutes(60),
    verify_checked_at: minutes(60),
    stage2_enabled: true,
    stage2_schedule: "daily",
    stage2_acknowledged_by: (await client.query<{ id: string }>('select id from "user" limit 1')).rows[0]?.id,
    stage2_acknowledged_at: days(2),
    last_passive_at: minutes(30),
    last_active_at: minutes(25),
    passive: passive({
      name: main.value,
      dns: dnsFull(main.value),
      tls: [
        tls(
          "203.0.113.10",
          new Date(now.getTime() + (12 * 24 + 6) * 3600 * 1000),
          {},
          { subject: main.value, sans: [main.value, `www.${main.value}`] },
        ),
      ],
      http: http(`https://${main.value}/`, 200, { ...headers, server: "nginx/1.22.1" }),
    }),
    active: {
      version: 1,
      takenAt: iso(minutes(25)),
      addresses: ["203.0.113.10"],
      open: [],
      checked: 30,
      closed: 26,
      noAnswer: 0,
      stopped: null,
    },
    cert_notified_level: 14,
  });
  await asset(EXPOSURE.covered, "domain", {
    last_passive_at: minutes(40),
    passive: passive({
      name: EXPOSURE.covered.value,
      dns: dnsFull(EXPOSURE.covered.value),
      tls: [tls("203.0.113.10", new Date(now.getTime() + 200 * 24 * 3600 * 1000))],
      http: http(`https://${EXPOSURE.covered.value}/`, 200, headers),
    }),
  });
  await asset(EXPOSURE.shop, "domain", {
    last_passive_at: minutes(50),
    passive: passive({
      name: EXPOSURE.shop.value,
      dns: { ...dnsFull(EXPOSURE.shop.value), mx: [], dmarc: { found: false, policy: null, record: null } },
      tls: [
        tls("203.0.113.30", new Date(now.getTime() - (4 * 24 + 18) * 3600 * 1000), {
          trusted: false,
          trustError: "CERT_HAS_EXPIRED",
        }),
      ],
      http: http(`https://${EXPOSURE.shop.value}/`, 200, { server: "Apache/2.4.57 (Debian)" }),
      plain: { address: "203.0.113.30", status: 200, location: null, redirectsToHttps: false, error: null },
      addresses: ["203.0.113.30"],
      geo: [{ address: "203.0.113.30", country: "FR", asn: 64501, org: "Example Cloud" }],
    }),
  });
  await asset(EXPOSURE.lost, "domain", {
    verify_state: "lost",
    verify_method: "dns",
    verified_at: days(3),
    verify_checked_at: minutes(20),
    verify_error: "dnsRecordMissing",
    last_passive_at: days(2),
    passive_error: "unexpected",
    passive: passive({
      name: EXPOSURE.lost.value,
      dns: dnsFull(EXPOSURE.lost.value),
      tls: [],
      http: null,
      httpsOpen: false,
      plain: null,
    }),
  });
  await asset(EXPOSURE.address, "ip", {
    last_passive_at: minutes(70),
    passive: passive({
      kind: "ip",
      name: EXPOSURE.address.value,
      dns: null,
      ptr: ["gateway.example.com"],
      addresses: ["203.0.113.20"],
      tls: [tls("203.0.113.20", new Date(now.getTime() + 90 * 24 * 3600 * 1000), { nameMatches: null })],
      http: http("https://203.0.113.20/", 403, { ...headers }),
      geo: [{ address: "203.0.113.20", country: null, asn: null, org: null }],
    }),
  });
  await asset(EXPOSURE.hostile, "domain", {
    last_passive_at: minutes(15),
    passive: passive({
      name: EXPOSURE.hostile.value,
      dns: {
        ...dnsFull(EXPOSURE.hostile.value),
        cname: [EXPOSURE.hostileBanner],
        ns: [EXPOSURE.hostileBanner],
      },
      tls: [
        tls(
          "203.0.113.10",
          new Date(now.getTime() + 100 * 24 * 3600 * 1000),
          {},
          { subject: EXPOSURE.hostileBanner, issuer: EXPOSURE.hostileBanner, sans: [EXPOSURE.hostileBanner] },
        ),
      ],
      http: http(`https://${EXPOSURE.hostile.value}/`, 200, {
        ...headers,
        server: EXPOSURE.hostileBanner,
        "x-powered-by": "PHP/8.2.7",
      }),
    }),
  });

  const finding = (
    id: number,
    a: { id: string },
    stage: "passive" | "active",
    rule: string,
    subject: string,
    severity: "critical" | "high" | "medium" | "low",
    params: Record<string, string | number>,
    state: "open" | "resolved" = "open",
  ) =>
    client.query(
      `insert into exposure_finding (id, organization_id, asset_id, stage, rule, subject, severity, severity_rank, state, params,
         first_seen_at, last_seen_at, resolved_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        `exf_e2eseeded${String(id).padStart(8, "0")}`,
        orgId,
        a.id,
        stage,
        rule,
        subject,
        severity,
        { critical: 4, high: 3, medium: 2, low: 1 }[severity],
        state,
        JSON.stringify(params),
        days(4),
        minutes(30),
        state === "resolved" ? days(1) : null,
      ],
    );
  // example.com: a critical Docker API, a high MySQL, a medium certificate with 12 days left and a low banner with a version.
  await finding(1, main, "active", "portExposed", "2375", "critical", {
    port: 2375,
    service: "docker",
    category: "managementApi",
    addresses: "203.0.113.10",
  });
  await finding(2, main, "active", "portExposed", "3306", "high", {
    port: 3306,
    service: "mysql",
    category: "database",
    addresses: "203.0.113.10",
  });
  await finding(3, main, "passive", "tlsExpiring", "443", "medium", {
    port: 443,
    address: "203.0.113.10",
    days: 12,
  });
  await finding(4, main, "passive", "httpBannerVersion", "server", "low", {
    header: "server",
    banner: "nginx/1.22.1",
  });
  await finding(5, main, "passive", "httpCspMissing", "", "low", {}, "resolved");
  // shop.example.net: high expired certificate, medium no redirect, low missing headers
  await finding(6, EXPOSURE.shop, "passive", "tlsExpired", "443", "high", {
    port: 443,
    address: "203.0.113.30",
    days: 5,
  });
  await finding(7, EXPOSURE.shop, "passive", "httpNoRedirectToHttps", "", "medium", { status: 200 });
  for (const [i, rule] of [
    "httpHstsMissing",
    "httpCspMissing",
    "httpNosniffMissing",
    "httpFramingMissing",
    "httpReferrerPolicyMissing",
    "httpPermissionsPolicyMissing",
  ].entries()) {
    await finding(8 + i, EXPOSURE.shop, "passive", rule, "", "low", {});
  }
  // The odd one has a banner finding whose text is hostile; the address has a missing framing header; the lost one a mail finding.
  await finding(20, EXPOSURE.hostile, "passive", "httpBannerVersion", "server", "low", {
    header: "server",
    banner: EXPOSURE.hostileBanner,
  });
  await finding(21, EXPOSURE.address, "passive", "httpFramingMissing", "", "low", {});
  await finding(22, EXPOSURE.lost, "passive", "dnsNoDmarc", "", "medium", {});

  const port = (
    a: { id: string },
    p: number,
    service: string,
    banner: string | null,
    tlsJson: unknown | null,
  ) =>
    client.query(
      `insert into exposure_port (asset_id, organization_id, address, port, service, banner, tls, first_seen_at, last_seen_at)
       values ($1, $2, '203.0.113.10', $3, $4, $5, $6, $7, $8)`,
      [
        a.id,
        orgId,
        p,
        service,
        banner,
        tlsJson === null ? null : JSON.stringify(tlsJson),
        days(4),
        minutes(25),
      ],
    );
  await port(main, 22, "ssh", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", null);
  await port(main, 2375, "docker", null, null);
  await port(main, 3306, "mysql", null, null);
  await port(
    main,
    8443,
    "httpsAlt",
    null,
    tls("203.0.113.10", new Date(now.getTime() + 150 * 24 * 3600 * 1000), { port: 8443 }),
  );
  await port(main, 25, "smtp", `220 mail.example.com ESMTP ${EXPOSURE.hostileBanner}\n220 ready`, null);
  await client.query(`update exposure_asset set active = $2 where id = $1`, [
    main.id,
    JSON.stringify({
      version: 1,
      takenAt: iso(minutes(25)),
      addresses: ["203.0.113.10"],
      open: [
        { address: "203.0.113.10", port: 22 },
        { address: "203.0.113.10", port: 25 },
        { address: "203.0.113.10", port: 2375 },
        { address: "203.0.113.10", port: 3306 },
        { address: "203.0.113.10", port: 8443 },
      ],
      checked: 30,
      closed: 25,
      noAnswer: 0,
      stopped: null,
    }),
  ]);

  const run = (
    id: number,
    a: { id: string },
    stage: "passive" | "active",
    state: "succeeded" | "failed",
    trigger: string,
    ago: number,
    error: string | null,
    counts: Record<string, number> | null,
    ports: number | null,
  ) =>
    client.query(
      `insert into exposure_run (id, organization_id, asset_id, stage, state, trigger, error, finding_counts, open_ports, started_at, finished_at, created_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $10)`,
      [
        `exr_e2eseeded${String(id).padStart(8, "0")}`,
        orgId,
        a.id,
        stage,
        state,
        trigger,
        error,
        counts ? JSON.stringify(counts) : null,
        ports,
        minutes(ago),
      ],
    );
  await run(
    1,
    main,
    "passive",
    "succeeded",
    "schedule",
    30,
    null,
    { critical: 0, high: 0, medium: 1, low: 1 },
    null,
  );
  await run(
    2,
    main,
    "active",
    "succeeded",
    "enable",
    25,
    null,
    { critical: 1, high: 1, medium: 0, low: 0 },
    5,
  );
  await run(3, main, "passive", "failed", "manual", 60 * 24, "timeout", null, null);
  await run(4, EXPOSURE.lost, "passive", "failed", "schedule", 60 * 24 * 2, "unexpected", null, null);

  for (const [i, [name, source]] of [
    ["api.example.com", "ct"],
    ["staging.example.com", "dns"],
    [`x${EXPOSURE.hostileBanner}.example.com`, "ct"],
  ].entries()) {
    await client.query(
      `insert into exposure_discovery (id, organization_id, asset_id, name, source, state, first_seen_at, last_seen_at)
       values ($1, $2, $3, $4, $5, 'new', $6, $6)`,
      [`exd_e2eseeded${String(i + 1).padStart(8, "0")}`, orgId, main.id, name, source, minutes(30)],
    );
  }
}

async function seedUnifi(client: Client, orgId: string, now: Date) {
  const minutes = (n: number) => new Date(now.getTime() - n * 60_000);
  const days = (n: number) => new Date(now.getTime() - n * 24 * 3600 * 1000);
  const connection = async (
    c: { id: string; name: string; host: string },
    extra: Record<string, unknown>,
  ) => {
    const columns = Object.keys(extra);
    await client.query(
      `insert into unifi_connection (id, organization_id, name, api_url, host, port, api_base, ${columns.join(", ")})
       values ($1, $2, $3, $4, $5, 443, 'unifi-os', ${columns.map((_, i) => `$${i + 6}`).join(", ")})`,
      [c.id, orgId, c.name, `https://${c.host}:443`, c.host, ...Object.values(extra)],
    );
  };
  await connection(UNIFI.main, {
    cert_status: "confirmed",
    cert_fingerprint: fingerprintOfCertificate("unifi-main"),
    cert_subject: "CN=udm.example.lan, O=Example",
    cert_issuer: "CN=udm.example.lan, O=Example",
    cert_valid_from: days(300),
    cert_valid_to: days(-3000),
    cert_confirmed_at: days(20),
    version: "9.0.114",
    last_sync_at: minutes(5),
  });
  await connection(UNIFI.pending, {
    candidate_fingerprint: UNIFI.pending.fingerprint,
    candidate_subject: "CN=udm-new.example.lan, O=Example",
    candidate_issuer: "CN=udm-new.example.lan, O=Example",
    candidate_valid_from: days(2),
    candidate_valid_to: days(-3650),
    candidate_ca_trusted: false,
    candidate_seen_at: minutes(1),
  });
  await connection(UNIFI.changed, {
    cert_status: "changed",
    cert_fingerprint: UNIFI.changed.pinned,
    cert_subject: "CN=udm-moved.example.lan, O=Old",
    cert_issuer: "CN=Old CA",
    cert_valid_from: days(300),
    cert_valid_to: days(-100),
    candidate_fingerprint: UNIFI.changed.offered,
    candidate_subject: "CN=udm-moved.example.lan, O=New",
    candidate_issuer: "CN=New CA",
    candidate_valid_from: days(1),
    candidate_valid_to: days(-365),
    candidate_ca_trusted: false,
    candidate_seen_at: minutes(3),
    last_error:
      "The certificate of the UniFi console changed. An admin must confirm the new fingerprint before the next sync.",
  });

  const site = (s: { id: string; name: string }, n: number, ref: string, clients: number) =>
    client.query(
      `insert into unifi_site (id, organization_id, connection_id, unifi_id, name, internal_ref, client_count, last_seen_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        s.id,
        orgId,
        UNIFI.main.id,
        `0a1b2c3d-0000-4000-8000-${String(n).padStart(12, "0")}`,
        s.name,
        ref,
        clients,
        minutes(5),
      ],
    );
  await site(UNIFI.sites.main, 1, "default", 41);
  await site(UNIFI.sites.branch, 2, "branch", 12);

  let n = 0;
  const device = (
    siteId: string,
    name: string,
    values: {
      model: string;
      state: "online" | "offline" | "other";
      raw: string;
      firmware: string;
      updatable: boolean | null;
      ip: string | null;
      uptime?: number;
      since: Date;
    },
  ) => {
    n += 1;
    return client.query(
      `insert into unifi_device (id, organization_id, connection_id, site_id, unifi_id, name, model, mac, ip, state, raw_state,
         state_since, firmware_version, firmware_updatable, uptime_sec, offline_syncs, first_seen_at, last_seen_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
      [
        `ufd_e2eseeded${String(n).padStart(8, "0")}`,
        orgId,
        UNIFI.main.id,
        siteId,
        `0d0d0d0d-0000-4000-8000-${String(n).padStart(12, "0")}`,
        name,
        values.model,
        `02:00:00:00:00:${String(n).padStart(2, "0")}`,
        values.ip,
        values.state,
        values.raw,
        values.since,
        values.firmware,
        values.updatable,
        values.uptime ?? null,
        values.state === "offline" ? 3 : 0,
        days(30),
        minutes(5),
      ],
    );
  };
  const main = UNIFI.sites.main.id;
  const branch = UNIFI.sites.branch.id;
  await device(main, UNIFI.devices.gateway, {
    model: "UCG Example",
    state: "online",
    raw: "ONLINE",
    firmware: "4.0.6",
    updatable: true,
    ip: "192.0.2.1",
    uptime: 864_000,
    since: days(10),
  });
  await device(main, UNIFI.devices.switch, {
    model: "USW Example 24",
    state: "online",
    raw: "ONLINE",
    firmware: "7.1.26",
    updatable: false,
    ip: "192.0.2.2",
    uptime: 90_000,
    since: days(3),
  });
  await device(main, UNIFI.devices.hall, {
    model: "U7 Example",
    state: "offline",
    raw: "OFFLINE",
    firmware: "6.7.1",
    updatable: true,
    ip: "192.0.2.3",
    since: minutes(50),
  });
  await device(main, UNIFI.devices.fresh, {
    model: "U7 Example",
    state: "other",
    raw: "PENDING_ADOPTION",
    firmware: "6.5.0",
    updatable: null,
    ip: null,
    since: minutes(20),
  });
  await device(branch, UNIFI.devices.branch, {
    model: "U6 Example",
    state: "online",
    raw: "ONLINE",
    firmware: "6.6.77",
    updatable: false,
    ip: "198.51.100.5",
    uptime: 4000,
    since: days(1),
  });
  await device(branch, UNIFI.devices.hostile, {
    model: "<b>model</b>",
    state: "online",
    raw: "ONLINE",
    firmware: "1.0.0",
    updatable: false,
    ip: "198.51.100.6",
    uptime: 100,
    since: days(1),
  });
}

async function seedWazuhRows(client: Client, orgId: string, now: Date) {
  const minutes = (n: number) => new Date(now.getTime() - n * 60_000);
  const days = (n: number) => new Date(now.getTime() - n * 24 * 3600 * 1000);
  const hours = (n: number) => new Date(now.getTime() - n * 3600 * 1000);
  await client.query(
    `insert into wazuh_connection (id, organization_id, name, dashboard_url, enrollment_host, adapter,
       manager_version, indexer_version, last_sync_at)
     values ($1, $2, $3, $4, $5, 'wazuh4', '4.12.0', '7.10.2', $6)`,
    [WAZUH.connection.id, orgId, WAZUH.connection.name, WAZUH.dashboardUrl, WAZUH.enrollmentHost, minutes(5)],
  );
  const endpoint = (
    e: { id: string; host: string },
    kind: "manager" | "indexer",
    port: number,
    user: string,
  ) =>
    client.query(
      `insert into wazuh_endpoint (id, organization_id, connection_id, kind, api_url, host, port, username,
         cert_status, cert_fingerprint, cert_subject, cert_issuer, cert_valid_from, cert_valid_to, cert_confirmed_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, 'confirmed', $9, $10, $10, $11, $12, $13)`,
      [
        e.id,
        orgId,
        WAZUH.connection.id,
        kind,
        `https://${e.host}:${port}`,
        e.host,
        port,
        user,
        fingerprintOfCertificate(`wazuh-${kind}`),
        `CN=${e.host}, O=Example`,
        days(300),
        days(-3000),
        days(30),
      ],
    );
  await endpoint(WAZUH.manager, "manager", 55000, "garnetops-api");
  await endpoint(WAZUH.indexer, "indexer", 9200, "garnetops-indexer");

  const window = (scale: number, previous: number) => {
    const counts = (k: number) => ({
      critical: Math.round(5 * k),
      high: Math.round(30 * k),
      medium: Math.round(120 * k),
      low: Math.round(1900 * k),
    });
    const sum = (c: Record<string, number>) => Object.values(c).reduce((a, b) => a + b, 0);
    const now = counts(scale);
    const before = counts(previous);
    return {
      readAt: minutes(5).toISOString(),
      total: sum(now),
      bySeverity: now,
      previous: { total: sum(before), bySeverity: before },
      tactics: [
        { name: "Credential Access", count: Math.round(40 * scale) },
        { name: "Initial Access", count: Math.round(12 * scale) },
        { name: "Persistence", count: Math.round(7 * scale) },
      ],
      agents: [
        { agentId: "001", name: "web-01", count: Math.round(900 * scale) },
        { agentId: "002", name: "db-01", count: Math.round(640 * scale) },
        { agentId: "006", name: WAZUH.agents.hostile.name, count: Math.round(100 * scale) },
      ],
      fim: Math.round(18 * scale),
    };
  };
  await client.query(
    "insert into wazuh_snapshot (connection_id, organization_id, data, synced_at) values ($1, $2, $3, $4)",
    [
      WAZUH.connection.id,
      orgId,
      JSON.stringify({
        windows: { "24h": window(1, 0.8), "7d": window(6, 5.5), "30d": window(22, 25) },
        vulnerabilities: {
          critical: 2,
          high: 10,
          medium: 21,
          low: 16,
          agentsAffected: 3,
          readAt: minutes(5).toISOString(),
        },
      }),
      minutes(5),
    ],
  );

  const agent = (a: { id: string; agentId: string; name: string }, extra: Record<string, unknown>) => {
    const columns = Object.keys(extra);
    return client.query(
      `insert into wazuh_agent (id, organization_id, connection_id, agent_id, name, first_seen_at, last_seen_at,
         ${columns.join(", ")})
       values ($1, $2, $3, $4, $5, $6, $6, ${columns.map((_, i) => `$${i + 7}`).join(", ")})`,
      [a.id, orgId, WAZUH.connection.id, a.agentId, a.name, minutes(5), ...Object.values(extra)],
    );
  };
  const A = WAZUH.agents;
  await agent(A.manager, {
    ip: "127.0.0.1",
    status: "active",
    is_manager: true,
    version: "4.12.0",
    os_name: "Ubuntu",
    os_version: "22.04.5 LTS",
    last_keep_alive_at: minutes(1),
  });
  await agent(A.web, {
    ip: SERVERS.vulnerable.address,
    status: "active",
    version: "4.12.0",
    os_name: "Debian GNU/Linux",
    os_version: "12",
    arch: "x86_64",
    groups: JSON.stringify(["default", "web"]),
    last_keep_alive_at: minutes(1),
    vuln_critical: 2,
    vuln_high: 9,
    vuln_medium: 20,
    vuln_low: 4,
    suggested_host_id: SERVERS.vulnerable.id,
    suggestion_reason: "address",
  });
  await agent(A.db, {
    ip: "192.0.2.31",
    status: "active",
    version: "4.12.0",
    os_name: "Ubuntu",
    os_version: "24.04",
    arch: "x86_64",
    groups: JSON.stringify(["default", "database"]),
    last_keep_alive_at: minutes(2),
    vuln_critical: 0,
    vuln_high: 1,
    vuln_medium: 1,
    vuln_low: 0,
    host_id: SERVERS.failed.id,
    linked_at: days(2),
  });
  await agent(A.app, {
    ip: "192.0.2.41",
    status: "disconnected",
    version: "4.11.2",
    os_name: "Rocky Linux",
    os_version: "9.4",
    arch: "x86_64",
    groups: JSON.stringify(["default"]),
    last_keep_alive_at: days(2),
    vuln_critical: 0,
    vuln_high: 0,
    vuln_medium: 0,
    vuln_low: 12,
  });
  await agent(A.win, {
    ip: "198.51.100.21",
    status: "active",
    version: "4.12.0",
    os_name: "Microsoft Windows Server 2022 Standard",
    os_version: "10.0.20348",
    arch: "x86_64",
    groups: JSON.stringify(["default", "windows"]),
    last_keep_alive_at: minutes(1),
  });
  await agent(A.spare, { ip: null, status: "never_connected", groups: JSON.stringify(["default"]) });
  await agent(A.hostile, {
    ip: "198.51.100.30",
    status: "active",
    version: "4.12.0",
    os_name: "macOS",
    os_version: "14.5",
    arch: "arm64",
    groups: JSON.stringify(["default"]),
    last_keep_alive_at: minutes(3),
  });

  const fim = (
    n: number,
    agentId: string,
    agentName: string,
    path: string,
    event: string,
    level: number | null,
  ) =>
    client.query(
      `insert into wazuh_fim_event (id, organization_id, connection_id, at, agent_id, agent_name, path, event, rule_level)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        `wzf_e2eseeded000000000${n}`,
        orgId,
        WAZUH.connection.id,
        minutes(n * 20),
        agentId,
        agentName,
        path,
        event,
        level,
      ],
    );
  await fim(1, "001", "web-01", "/etc/passwd", "modified", 7);
  await fim(2, "002", "db-01", "/var/lib/app/new.sh", "added", 5);
  await fim(3, "006", WAZUH.agents.hostile.name, WAZUH.hostilePath, "deleted", 12);

  // The live attack feed (ADR 0021): where it stands, and the latest events it stored.
  await client.query(
    `insert into wazuh_live_state (connection_id, organization_id, last_poll_at, last_event_at)
     values ($1, $2, $3, $4)`,
    [WAZUH.connection.id, orgId, new Date(now.getTime() - 10_000), minutes(2)],
  );
  for (const e of LIVE.events) {
    await client.query(
      `insert into wazuh_attack_event (organization_id, connection_id, doc_id, at, ip, rule_id, rule_level, description,
         groups, agent_id, agent_name)
       values ($1, $2, $3, $4, $5, '5710', $6, $7, '["authentication_failed"]', $8, $9)`,
      [orgId, WAZUH.connection.id, e.doc, minutes(e.ago), e.ip, e.level, e.description, e.agentId, e.agent],
    );
  }

  // The attack overview (ADR 0016): aggregated source addresses, documentation ranges only.
  const sourceRow = (
    n: number,
    window: string,
    ip: string,
    count: number,
    groups: string[],
    agents: { agentId: string; name: string; count: number }[],
    first: Date | null,
    last: Date | null,
  ) =>
    client.query(
      `insert into wazuh_source_ip (id, organization_id, connection_id, time_window, ip, count, groups, seen_at,
         first_seen_at, last_seen_at, agents)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        `wzs_e2eseeded${String(n).padStart(8, "0")}`,
        orgId,
        WAZUH.connection.id,
        window,
        ip,
        count,
        JSON.stringify(groups),
        minutes(5),
        first,
        last,
        JSON.stringify(agents),
      ],
    );
  const web = (count: number) => ({ agentId: "001", name: "web-01", count });
  const db = (count: number) => ({ agentId: "002", name: "db-01", count });
  const hostile = (count: number) => ({ agentId: "006", name: WAZUH.agents.hostile.name, count });
  const AUTH = ["authentication_failed", "authentication_failures"];
  await sourceRow(1, "24h", ATTACKS.ips.de, 55, AUTH, [web(40), db(15)], hours(20), minutes(10));
  await sourceRow(2, "24h", ATTACKS.ips.fr, 22, ["web_scan"], [web(22)], hours(9), minutes(30));
  await sourceRow(3, "24h", ATTACKS.ips.br, 3, ["invalid_login"], [hostile(3)], null, hours(2));
  await sourceRow(4, "24h", ATTACKS.ips.de2, 12, ["authentication_failed"], [db(12)], hours(5), hours(1));
  await sourceRow(5, "24h", ATTACKS.ips.internal, 9, ["authentication_failed"], [web(9)], hours(3), hours(2));
  await sourceRow(6, "24h", ATTACKS.ips.unknown, 4, ["recon"], [web(4)], hours(4), hours(4));
  await sourceRow(10, "7d", ATTACKS.ips.de, 300, AUTH, [web(250), db(50)], days(6), minutes(10));
  await sourceRow(11, "7d", ATTACKS.ips.fr, 120, ["web_scan"], [web(120)], days(5), minutes(30));
  await sourceRow(12, "7d", ATTACKS.ips.br, 15, ["invalid_login"], [hostile(15)], days(3), hours(2));
  const attackWindow = (
    window: string,
    alerts: number,
    distinct: number,
    previousAlerts: number,
    previousDistinct: number,
    agents: { agentId: string; name: string; count: number }[],
  ) =>
    client.query(
      `insert into wazuh_attack_window (organization_id, connection_id, time_window, attack_alerts, distinct_sources,
         agents, previous_attack_alerts, previous_distinct_sources, previous_sources, read_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        orgId,
        WAZUH.connection.id,
        window,
        alerts,
        distinct,
        JSON.stringify(agents),
        previousAlerts,
        previousDistinct,
        JSON.stringify([
          { ip: ATTACKS.ips.de, count: 40 },
          { ip: ATTACKS.ips.fr, count: 20 },
          { ip: "10.1.1.1", count: 3 },
        ]),
        minutes(5),
      ],
    );
  await attackWindow("24h", 120, 7, 100, 5, [web(70), db(30), hostile(20)]);
  await attackWindow("7d", 800, 25, 700, 22, [web(500), db(200), hostile(100)]);
  await client.query(
    `insert into wazuh_sync_run (id, organization_id, connection_id, state, trigger, agent_count, request_count, warnings,
       started_at, finished_at, created_at)
     values ('wzr_e2eseeded0000000001', $1, $2, 'succeeded', 'schedule', 7, 18, '[]', $3, $3, $3)`,
    [orgId, WAZUH.connection.id, minutes(5)],
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

async function seedGeoipRows(client: Client): Promise<void> {
  const dataset = async (kind: "country" | "asn", id: string) =>
    client.query(
      `insert into geoip_dataset (id, kind, state, source, dataset_month, row_count, finished_at)
       values ($1, $2, 'active', 'import', to_char(now(), 'YYYY-MM'), $3, now())`,
      [id, kind, kind === "country" ? ATTACKS.country.length : ATTACKS.asn.length],
    );
  await dataset("country", "geo_e2eseededcountry0001");
  for (const [start, end, country] of ATTACKS.country) {
    await client.query(
      "insert into geoip_country_range (dataset_id, range_start, range_end, country) values ($1, $2, $3, $4)",
      ["geo_e2eseededcountry0001", start, end, country],
    );
  }
  await dataset("asn", "geo_e2eseededasn000001");
  for (const [start, end, asn, org] of ATTACKS.asn) {
    await client.query(
      "insert into geoip_asn_range (dataset_id, range_start, range_end, asn, org) values ($1, $2, $3, $4, $5)",
      ["geo_e2eseededasn000001", start, end, asn, org],
    );
  }
}

/** Removes the GeoIP datasets (the page then says that no location data is loaded). */
export async function removeGeoip(): Promise<void> {
  await sql("delete from geoip_dataset");
}

/** Puts the seeded GeoIP datasets back. */
export async function restoreGeoip(): Promise<void> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    await client.query("begin");
    await client.query("delete from geoip_dataset");
    await seedGeoipRows(client);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

/** Removes the seeded Wazuh connection and everything read from it (a test connects one itself). */
export async function removeWazuh(): Promise<void> {
  await sql("delete from wazuh_connection");
}

/** Puts the seeded Wazuh rows back (after a test removed them). */
export async function restoreWazuh(): Promise<void> {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    const [org] = (await client.query<{ id: string }>("select id from organization limit 1")).rows;
    if (!org) throw new Error("No organisation in the e2e database");
    await client.query("begin");
    await client.query("delete from wazuh_connection");
    await seedWazuhRows(client, org.id, new Date());
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    await client.end();
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

/**
 * Stores one more event of the live attack feed and tells the browsers, as the worker does after a poll (ADR 0021).
 * The channel name is the one `liveChannel` of packages/core/src/attack-live.ts makes; keep the two in step.
 */
export async function addLiveEvent(event: {
  ip: string;
  description: string;
  level?: number;
  agentId?: string;
  agent?: string;
}): Promise<number> {
  const [org] = await sql<{ id: string }>("select id from organization limit 1");
  if (!org) throw new Error("No organisation in the e2e database");
  const doc = `e2e-live-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const [row] = await sql<{ seq: string }>(
    `insert into wazuh_attack_event (organization_id, connection_id, doc_id, at, ip, rule_id, rule_level, description,
       groups, agent_id, agent_name)
     values ($1, $2, $3, now(), $4, '5712', $5, $6, '["authentication_failures"]', $7, $8) returning seq`,
    [
      org.id,
      WAZUH.connection.id,
      doc,
      event.ip,
      event.level ?? 10,
      event.description,
      event.agentId ?? "001",
      event.agent ?? "web-01",
    ],
  );
  const seq = Number(row?.seq);
  const channel = `attack_live_${org.id.toLowerCase().replace(/[^a-z0-9]/g, "_")}`.slice(0, 63);
  await sql("select pg_notify($1, $2)", [channel, JSON.stringify({ s: seq })]);
  return seq;
}

/** Says that the live feed polled just now (the page then calls it live), or that it did so a while ago. */
export async function setLivePoll(
  ago: "now" | "long ago",
  lastEventMinutesAgo: number | null = 2,
): Promise<void> {
  await sql(
    `update wazuh_live_state set last_poll_at = ${ago === "now" ? "now()" : "now() - interval '1 hour'"},
       last_error = null, failures = 0,
       last_event_at = ${lastEventMinutesAgo === null ? "null" : `now() - interval '${lastEventMinutesAgo} minutes'`}`,
  );
}

/**
 * Switches the IPS preview of the main console on or off as an admin would, with the sealed password played by a row
 * (ADR 0022). Switching off also deletes the threat events, so the other tests see an untouched Attacks page.
 */
export async function setUnifiIps(
  on: boolean,
  options: { lastEventMinutesAgo?: number | null } = {},
): Promise<void> {
  if (on) {
    const [org] = await sql<{ id: string }>("select id from organization limit 1");
    await sql(
      `insert into secret (id, organization_id, purpose, sealed, vault_key_id)
       values ($1, $2, 'unifi-ips-password', '{}', 'e2e') on conflict do nothing`,
      [UNIFI.ipsSecret, org?.id],
    );
    const ago = options.lastEventMinutesAgo === undefined ? 2 : options.lastEventMinutesAgo;
    await sql(
      `update unifi_connection set ips_enabled = true, ips_username = $2, ips_secret_id = $3,
         ips_last_poll_at = now(), ips_last_error = null, ips_failures = 0, ips_rights = '[]', ips_rights_acknowledged = '[]', ips_rights_acknowledged_at = null,
         ips_rights_acknowledged_by = null,
         ips_last_event_at = ${ago === null ? "null" : `now() - interval '${ago} minutes'`}
       where id = $1`,
      [UNIFI.main.id, UNIFI.ipsUser, UNIFI.ipsSecret],
    );
  } else {
    await sql(
      `update unifi_connection set ips_enabled = false, ips_username = null, ips_secret_id = null,
         ips_last_poll_at = null, ips_last_event_at = null, ips_last_error = null, ips_rights = '[]', ips_rights_acknowledged = '[]', ips_rights_acknowledged_at = null,
         ips_rights_acknowledged_by = null,
         ips_interval_seconds = 60, ips_enabled_by = null, ips_enabled_at = null`,
    );
    await sql("delete from secret where purpose = 'unifi-ips-password'");
    await sql("delete from unifi_threat_event");
  }
}

/**
 * Stores one threat event as the worker does after a poll of the IPS preview and tells the browsers (ADR 0022). The
 * channel is the one of the Wazuh live feed: both sources share it and one sequence.
 */
export async function addUnifiEvent(event: {
  ip: string;
  signature: string;
  action?: "blocked" | "alerted";
  category?: string;
  destPort?: number | null;
  site?: string;
  agoMinutes?: number;
}): Promise<number> {
  const [org] = await sql<{ id: string }>("select id from organization limit 1");
  if (!org) throw new Error("No organisation in the e2e database");
  const doc = `e2e-unifi-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const [row] = await sql<{ seq: string }>(
    `insert into unifi_threat_event (organization_id, connection_id, doc_id, at, ip, action, signature, category, dest_port,
       proto, site_name)
     values ($1, $2, $3, now() - make_interval(mins => $4), $5, $6, $7, $8, $9, 'tcp', $10) returning seq`,
    [
      org.id,
      UNIFI.main.id,
      doc,
      event.agoMinutes ?? 0,
      event.ip,
      event.action ?? "blocked",
      event.signature,
      event.category ?? "Attempted Administrator Privilege Gain",
      event.destPort === undefined ? 22 : event.destPort,
      event.site ?? UNIFI.sites.main.name,
    ],
  );
  const seq = Number(row?.seq);
  const channel = `attack_live_${org.id.toLowerCase().replace(/[^a-z0-9]/g, "_")}`.slice(0, 63);
  await sql("select pg_notify($1, $2)", [channel, JSON.stringify({ s: seq })]);
  return seq;
}
