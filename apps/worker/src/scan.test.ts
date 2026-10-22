/**
 * End-to-end scan with the real scanner: grype and the local vulnerability
 * database from `pnpm scanners:fetch -- --with-db`, a throw-away PostgreSQL
 * database on the development server, and a real vault key. Only the clone is
 * replaced: it copies a recorded fixture (test/fixtures) instead of reaching
 * the network. Skipped when the development environment is not set up.
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { newId } from "@garnetops/core";
import { generateDeployKey } from "@garnetops/core/ssh";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { copyFixtureRepo } from "../test/fixture-repo.ts";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const grypeBin = join(root, ".tools", "grype", process.platform === "win32" ? "grype.exe" : "grype");
const grypeDb = join(root, ".tools", "grype-db");
const syftBin = join(root, ".tools", "syft", process.platform === "win32" ? "syft.exe" : "syft");

function devDatabaseUrl(): string | null {
  try {
    const line = readFileSync(join(root, ".data", "dev.env"), "utf8")
      .split("\n")
      .find((l) => l.startsWith("DATABASE_URL="));
    return line ? line.slice("DATABASE_URL=".length).trim() : null;
  } catch {
    return null;
  }
}
const adminUrl = devDatabaseUrl();
const ready =
  Boolean(adminUrl) &&
  existsSync(grypeBin) &&
  existsSync(syftBin) &&
  existsSync(join(grypeDb, "6", "vulnerability.db"));

/** What the replaced clone does: copy this fixture, or fail with this message. */
const clone = vi.hoisted(() => ({
  fixture: "npm-vulnerable" as string,
  fail: null as string | null,
  lastToken: null as string | null,
  /** What the clone saw of the SSH setup: the key file's content and the known_hosts content. */
  lastSsh: null as { pinned: boolean; key: string; knownHosts: string } | null,
  /** The host key line ssh would record on first contact. */
  hostKeyLine: "",
}));
vi.mock("./git.ts", () => ({
  sshClient: async () => ({ bin: "ssh", kex: ["mlkem768x25519-sha256"] }),
  shallowClone: async (options: {
    dir: string;
    token: string | null;
    ssh: { pinned: boolean; privateKeyFile: string; knownHostsFile: string } | null;
  }) => {
    clone.lastToken = options.token;
    clone.lastSsh = options.ssh
      ? {
          pinned: options.ssh.pinned,
          key: readFileSync(options.ssh.privateKeyFile, "utf8"),
          knownHosts: readFileSync(options.ssh.knownHostsFile, "utf8"),
        }
      : null;
    // Like ssh with StrictHostKeyChecking=accept-new: the host key is recorded before authentication.
    if (options.ssh && !options.ssh.pinned)
      writeFileSync(options.ssh.knownHostsFile, `${clone.hostKeyLine}\n`);
    if (clone.fail) throw new Error(clone.fail);
    await copyFixtureRepo(clone.fixture, options.dir);
    return { commitSha: `fixture-${clone.fixture}`, branch: "main" };
  },
}));

const SCAN_TIMEOUT = 120_000;

describe.skipIf(!ready)("scan with the real scanner", () => {
  const dbName = `garnetops_scan_test_${process.pid}`;
  const org = "org_scan";
  const repo = "repo_scan";
  const sshRepo = "repo_scan_ssh";
  const deployKey = generateDeployKey("garnetops-test");
  const token = "fixture-token-not-a-secret";
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let runScan: (scanId: string) => Promise<void>;
  let workerPool: { end(): Promise<void> };

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    workDir = await mkdtemp(join(tmpdir(), "garnetops-scan-test-"));
    const keys = generateVaultKeyPair();
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 });

    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: grypeBin,
      GARNETOPS_GRYPE_DB_DIR: grypeDb,
      GARNETOPS_SYFT_BIN: syftBin,
      GARNETOPS_WORK_DIR: workDir,
    });

    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);

    // The worker reads its configuration on import, so import it after the environment is set.
    ({ runScan } = await import("./scan.ts"));
    ({ pool: workerPool } = await import("./db.ts"));

    const vault = loadVaultPublicKey(keys.publicKeyPem);
    const secretId = "sec_scan";
    await conn.db.insert(schema.organization).values({ id: org, name: "Scan test" });
    await conn.db.insert(schema.secret).values({
      id: secretId,
      organizationId: org,
      purpose: "forge-token",
      sealed: seal(token, { organizationId: org, recordId: secretId, purpose: "forge-token" }, vault),
      vaultKeyId: vault.id,
    });
    await conn.db.insert(schema.repository).values({
      id: repo,
      organizationId: org,
      name: "fixture",
      url: "https://git.example.test/team/fixture.git",
      authKind: "https-token",
      secretId,
    });

    const keySecretId = "sec_ssh";
    await conn.db.insert(schema.secret).values({
      id: keySecretId,
      organizationId: org,
      purpose: "ssh-private-key",
      sealed: seal(
        deployKey.privateKey,
        { organizationId: org, recordId: keySecretId, purpose: "ssh-private-key" },
        vault,
      ),
      vaultKeyId: vault.id,
    });
    await conn.db.insert(schema.repository).values({
      id: sshRepo,
      organizationId: org,
      name: "fixture-ssh",
      url: "git@git.example.test:team/fixture.git",
      authKind: "ssh-deploy-key",
      secretId: keySecretId,
      deployPublicKey: deployKey.publicKey,
    });
  }, 60_000);

  afterAll(async () => {
    await workerPool?.end();
    await conn?.pool.end();
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin?.pool.end();
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  async function queueScan(
    state: "queued" | "running" = "queued",
    startedAgo?: string,
    repositoryId = repo,
  ): Promise<string> {
    const id = newId("scan");
    await conn.db.insert(schema.scan).values({
      id,
      organizationId: org,
      repositoryId,
      state,
      trigger: "manual",
      createdAt: new Date(),
      ...(startedAgo ? { startedAt: sql`now() - ${startedAgo}::interval` } : {}),
    });
    return id;
  }
  const scanRow = async (id: string) =>
    (await conn.db.select().from(schema.scan).where(eq(schema.scan.id, id)))[0];
  const findings = () => conn.db.select().from(schema.finding).where(eq(schema.finding.repositoryId, repo));
  const leftovers = () => readdirSync(workDir).filter((n) => n.startsWith("scan-"));

  it(
    "scans a repository end to end and records what it found",
    async () => {
      clone.fixture = "npm-vulnerable";
      const id = await queueScan();
      await runScan(id);

      const scan = await scanRow(id);
      expect(scan).toMatchObject({
        state: "succeeded",
        error: null,
        packageCount: 3, // the project itself, lodash and minimist
        newFindings: 8,
        resolvedFindings: 0,
        commitSha: "fixture-npm-vulnerable",
      });
      expect(scan?.scannerVersions).toEqual({ grype: "0.120.1", syft: "1.55.0" });

      // The full inventory is stored, not only the vulnerable packages.
      const inventory = await conn.db
        .select()
        .from(schema.repositoryPackage)
        .where(eq(schema.repositoryPackage.repositoryId, repo));
      expect(inventory.map((p) => `${p.name}@${p.version}`).sort()).toEqual([
        "garnetops-fixture-npm-vulnerable@1.0.0",
        "lodash@4.17.15",
        "minimist@1.2.0",
      ]);
      expect(inventory.every((p) => p.scanId === id && p.purl?.startsWith("pkg:npm/"))).toBe(true);
      expect(scan?.vulnDbBuiltAt).toBeInstanceOf(Date);

      // Publication dates come from the local database, not from grype's report.
      const [lodash] = await conn.db
        .select()
        .from(schema.vulnerability)
        .where(eq(schema.vulnerability.id, "GHSA-35jh-r3h4-6jhm"));
      expect(lodash?.publishedAt?.toISOString().slice(0, 10)).toBe("2021-02-15");

      const rows = await findings();
      expect(rows).toHaveLength(8);
      expect(rows.every((f) => f.state === "open" && f.firstSeenScanId === id)).toBe(true);
      expect(rows.map((f) => f.packageName).sort()).toEqual([
        ...Array(6).fill("lodash"),
        "minimist",
        "minimist",
      ]);
      const repoRow = (
        await conn.db.select().from(schema.repository).where(eq(schema.repository.id, repo))
      )[0];
      expect(repoRow?.lastScanId).toBe(id);

      // The worker opened the sealed token and handed it to the clone; nothing is left on disk.
      expect(clone.lastToken).toBe(token);
      expect(leftovers()).toEqual([]);
    },
    SCAN_TIMEOUT,
  );

  it(
    "reopens an expired acceptance and keeps a valid one",
    async () => {
      const [expired, valid] = await findings();
      if (!expired || !valid) throw new Error("expected findings from the first scan");
      const accept = (id: string, until: Date) =>
        conn.db
          .update(schema.finding)
          .set({ state: "accepted", acceptedReason: "test", acceptedUntil: until })
          .where(eq(schema.finding.id, id));
      await accept(expired.id, new Date(Date.now() - 60_000));
      await accept(valid.id, new Date(Date.now() + 86_400_000));

      const id = await queueScan();
      await runScan(id);

      expect(await scanRow(id)).toMatchObject({ state: "succeeded", newFindings: 0, resolvedFindings: 0 });
      const byId = new Map((await findings()).map((f) => [f.id, f]));
      expect(byId.get(expired.id)).toMatchObject({
        state: "open",
        acceptedUntil: null,
        acceptedReason: null,
      });
      expect(byId.get(valid.id)?.state).toBe("accepted");
    },
    SCAN_TIMEOUT,
  );

  it(
    "resolves every finding once the dependencies are fixed",
    async () => {
      clone.fixture = "npm-fixed";
      const id = await queueScan();
      await runScan(id);

      expect(await scanRow(id)).toMatchObject({ state: "succeeded", newFindings: 0, resolvedFindings: 8 });
      // The inventory is replaced, not appended.
      const inventory = await conn.db
        .select()
        .from(schema.repositoryPackage)
        .where(eq(schema.repositoryPackage.repositoryId, repo));
      expect(inventory.find((p) => p.name === "lodash")?.version).toBe("4.18.0");
      expect(inventory.filter((p) => p.name === "lodash")).toHaveLength(1);
      const rows = await findings();
      expect(rows.every((f) => f.state === "resolved" && f.resolvedAt instanceof Date)).toBe(true);
    },
    SCAN_TIMEOUT,
  );

  it(
    "reopens findings that come back and counts them as new",
    async () => {
      clone.fixture = "npm-vulnerable";
      const id = await queueScan();
      await runScan(id);

      expect(await scanRow(id)).toMatchObject({ state: "succeeded", newFindings: 8, resolvedFindings: 0 });
      const rows = await findings();
      expect(rows).toHaveLength(8); // the same rows, not duplicates
      expect(rows.every((f) => f.state === "open" && f.resolvedAt === null && f.firstSeenScanId === id)).toBe(
        true,
      );
    },
    SCAN_TIMEOUT,
  );

  it("fails a scan with the clone's safe message and cleans up", async () => {
    clone.fail = "The repository host could not be reached.";
    try {
      const id = await queueScan();
      await runScan(id);
      expect(await scanRow(id)).toMatchObject({
        state: "failed",
        error: "The repository host could not be reached.",
      });
      expect(leftovers()).toEqual([]);
    } finally {
      clone.fail = null;
    }
  });

  describe("SSH repository with a deploy key", () => {
    const hostLine = `git.example.test ${generateDeployKey("host").publicKey.split(" ").slice(0, 2).join(" ")}`;
    const repoRow = async () =>
      (await conn.db.select().from(schema.repository).where(eq(schema.repository.id, sshRepo)))[0];

    it(
      "hands the key to ssh, pins the host key on first contact and requires it afterwards",
      async () => {
        clone.fixture = "npm-fixed";
        clone.hostKeyLine = hostLine;
        const first = await queueScan("queued", undefined, sshRepo);
        await runScan(first);
        expect((await scanRow(first))?.state).toBe("succeeded");
        expect(clone.lastToken).toBeNull();
        expect(clone.lastSsh).toEqual({ pinned: false, key: deployKey.privateKey, knownHosts: "" });
        expect(await repoRow()).toMatchObject({ sshKnownHosts: hostLine });
        expect((await repoRow())?.sshKnownHostsPinnedAt).toBeInstanceOf(Date);

        clone.hostKeyLine = `git.example.test ${generateDeployKey("other").publicKey.split(" ").slice(0, 2).join(" ")}`;
        const second = await queueScan("queued", undefined, sshRepo);
        await runScan(second);
        expect(clone.lastSsh).toMatchObject({ pinned: true, knownHosts: hostLine });
        expect((await repoRow())?.sshKnownHosts).toBe(hostLine); // never replaced
        expect(leftovers()).toEqual([]); // key file and known_hosts are gone with the scan directory
      },
      SCAN_TIMEOUT,
    );

    it("pins the host key even when the deploy key is not on the forge yet", async () => {
      await conn.db
        .update(schema.repository)
        .set({ sshKnownHosts: null, sshKnownHostsPinnedAt: null })
        .where(eq(schema.repository.id, sshRepo));
      clone.hostKeyLine = hostLine;
      clone.fail = "The server refused the deploy key.";
      try {
        const id = await queueScan("queued", undefined, sshRepo);
        await runScan(id);
        expect(await scanRow(id)).toMatchObject({
          state: "failed",
          error: "The server refused the deploy key.",
        });
        expect((await repoRow())?.sshKnownHosts).toBe(hostLine);
      } finally {
        clone.fail = null;
      }
    });

    it(
      "refuses to record anything that is not a plain known_hosts entry",
      async () => {
        await conn.db
          .update(schema.repository)
          .set({ sshKnownHosts: null, sshKnownHostsPinnedAt: null })
          .where(eq(schema.repository.id, sshRepo));
        clone.hostKeyLine = `@cert-authority * ${hostLine.split(" ").slice(1).join(" ")}`;
        const id = await queueScan("queued", undefined, sshRepo);
        await runScan(id);
        expect((await repoRow())?.sshKnownHosts).toBeNull();
      },
      SCAN_TIMEOUT,
    );
  });

  it(
    "takes over a scan whose worker died, but never a live one",
    async () => {
      const live = await queueScan("running", "1 minute");
      await runScan(live);
      expect((await scanRow(live))?.state).toBe("running");

      const dead = await queueScan("running", "31 minutes");
      await runScan(dead);
      expect((await scanRow(dead))?.state).toBe("succeeded");

      await conn.db
        .update(schema.scan)
        .set({ state: "failed", error: "test cleanup" })
        .where(and(eq(schema.scan.id, live), eq(schema.scan.state, "running")));
    },
    SCAN_TIMEOUT,
  );
});
