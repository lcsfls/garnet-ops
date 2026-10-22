/**
 * Servers end to end (ADR 0011): the worker's access key, host key scan and inventory against
 * a local SSH server (ssh2) that stands in for a managed server, with the real OpenSSH client,
 * a throw-away PostgreSQL database on the development server and a real vault key.
 *
 * The server side either replays a fixed report or runs the real wrapper script exactly as
 * sshd would for a forced command. The vulnerability matcher is replaced by a synthetic
 * grype-shaped report (test/fixtures/host-grype-debian.json), because the vulnerability
 * database cannot be fetched in every environment; the test at the end runs the real grype
 * and is skipped without a database. Skipped entirely without the development PostgreSQL or
 * an OpenSSH client.
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { WRAPPER_SCRIPT } from "@garnetops/core/host-setup";
import { REPORT_HEADER } from "@garnetops/core/hosts";
import { fingerprint, generateDeployKey } from "@garnetops/core/ssh";
import { generateVaultKeyPair, loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { Server, utils } from "ssh2";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { findOnPath, findSsh } from "./git.ts";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../test/fixtures/", import.meta.url));

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
const ready = Boolean(adminUrl) && Boolean(findSsh()) && Boolean(findOnPath("ssh-keyscan"));

/** The grype step: what it was asked to match, and the answer it gives. */
const matcher = vi.hoisted(() => ({
  sbom: null as { artifacts: { name: string; purl: string }[]; distro: Record<string, string> } | null,
  report: null as unknown,
  fail: false,
}));
vi.mock("./grype.ts", async (original) => {
  const real = await original<typeof import("./grype.ts")>();
  const { readFileSync: read } = await import("node:fs");
  return {
    ...real,
    addAdvisoryDates: () => {},
    scanTarget: async (target: string) => {
      matcher.sbom = JSON.parse(read(target.replace(/^sbom:/, ""), "utf8"));
      if (matcher.fail) throw new Error("grype: failed to load vulnerability db");
      return matcher.report;
    },
  };
});

const T = "\t";
const DEBIAN_REPORT = [
  REPORT_HEADER,
  "@@section os-release",
  'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
  'NAME="Debian GNU/Linux"',
  'VERSION_ID="12"',
  "VERSION_CODENAME=bookworm",
  "ID=debian",
  "@@section kernel",
  "6.1.0-18-amd64",
  "@@section machine",
  "x86_64",
  "@@section dpkg",
  ["libssl3", "3.0.11-1~deb12u2", "amd64", "ii ", "openssl", "3.0.11-1~deb12u2"].join(T),
  ["bash", "5.2.15-2+b2", "amd64", "ii ", "bash", "5.2.15-2+b2"].join(T),
  ["tzdata", "2024a-0+deb12u1", "all", "ii ", "", ""].join(T),
  "@@section updates-apt",
  "Listing...",
  "libssl3/stable-security 3.0.11-1~deb12u3 amd64 [upgradable from: 3.0.11-1~deb12u2]",
  "@@end",
  "",
].join("\n");

type Behaviour =
  | { kind: "report"; text: string }
  | { kind: "wrapper" }
  | { kind: "stream"; bytes: number }
  | { kind: "hang" };

describe.skipIf(!ready)("servers: access key, host key scan and inventory", () => {
  const dbName = `garnetops_hosts_test_${process.pid}`;
  const org = "org_hosts";
  const hostKey = generateDeployKey("test-host");
  const otherHostKey = generateDeployKey("another-host");
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let server: Server;
  let port = 0;
  let allowedKey: ReturnType<typeof utils.parseKey> | null = null;
  const seen = { commands: [] as string[], connections: 0 };
  const behaviour: { current: Behaviour } = { current: { kind: "report", text: DEBIAN_REPORT } };
  let hosts: typeof import("./hosts.ts");
  let privateKeyOfAccess = "";
  let counter = 0;

  const resolveLocal = async () => "127.0.0.1";

  /** A fresh server record in the database; the host key is pinned unless said otherwise. */
  async function addHost(
    options: { status?: "pending" | "confirmed" | "changed"; pinned?: string; address?: string } = {},
  ) {
    const id = `host_${++counter}`;
    const status = options.status ?? "confirmed";
    const pinned = (options.pinned ?? hostKey.publicKey).split(" ")[1] as string;
    await conn.db.insert(schema.host).values({
      id,
      organizationId: org,
      name: `server-${counter}`,
      address: options.address ?? `server-${counter}.example.test`,
      port,
      hostKeyStatus: status,
      ...(status === "pending"
        ? {}
        : { hostKeyType: "ssh-ed25519", hostKey: pinned, hostKeyFingerprint: fingerprint(pinned) }),
    });
    return id;
  }
  async function queueRun(hostId: string) {
    const id = `hrun_${++counter}`;
    await conn.db.insert(schema.hostInventoryRun).values({
      id,
      organizationId: org,
      hostId,
      state: "queued",
      trigger: "manual",
    });
    return id;
  }
  const hostRow = async (id: string) =>
    (
      await conn.db.select().from(schema.host).where(eq(schema.host.id, id))
    )[0] as typeof schema.host.$inferSelect;
  const runRow = async (id: string) =>
    (
      await conn.db.select().from(schema.hostInventoryRun).where(eq(schema.hostInventoryRun.id, id))
    )[0] as typeof schema.hostInventoryRun.$inferSelect;

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    workDir = await mkdtemp(join(tmpdir(), "garnetops-hosts-test-"));
    const keys = generateVaultKeyPair();
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "grype-not-used",
      GARNETOPS_GRYPE_DB_DIR: join(workDir, "no-db"),
      GARNETOPS_WORK_DIR: workDir,
    });
    conn = createDb(url.toString(), { max: 2 });
    await runMigrations(conn.db);
    await conn.db.insert(schema.organization).values({ id: org, name: "Hosts Test" });
    hosts = await import("./hosts.ts");

    server = new Server({ hostKeys: [hostKey.privateKey] }, (client) => {
      seen.connections++;
      client.on("authentication", (ctx) => {
        const allowed = allowedKey && !(allowedKey instanceof Error) ? allowedKey : null;
        const key = Array.isArray(allowed) ? allowed[0] : allowed;
        if (ctx.method !== "publickey" || !key) return ctx.reject(["publickey"]);
        if (ctx.key.algo !== key.type || !ctx.key.data.equals(key.getPublicSSH()))
          return ctx.reject(["publickey"]);
        if (!ctx.signature) return ctx.accept();
        return key.verify(ctx.blob as Buffer, ctx.signature, ctx.hashAlgo) ? ctx.accept() : ctx.reject();
      });
      client.on("ready", () => {
        client.on("session", (accept) => {
          accept().on("exec", (acceptExec, reject, info) => {
            seen.commands.push(info.command);
            // The forced command of the real setup ignores the request; here only "inventory" is served.
            if (info.command !== "inventory") return reject();
            const stream = acceptExec();
            const b = behaviour.current;
            if (b.kind === "report") {
              stream.write(b.text);
              stream.exit(0);
              stream.end();
            } else if (b.kind === "stream") {
              const chunk = Buffer.alloc(64 * 1024, 0x61);
              let sent = 0;
              const pump = () => {
                while (sent < b.bytes) {
                  sent += chunk.length;
                  if (!stream.write(chunk)) return void stream.once("drain", pump);
                }
                stream.exit(0);
                stream.end();
              };
              stream.on("error", () => {});
              pump();
            } else if (b.kind === "wrapper") {
              // sshd runs the forced command through the account's shell with SSH_ORIGINAL_COMMAND set.
              const child = spawn("sh", ["-c", WRAPPER_SCRIPT], {
                env: { PATH: process.env.PATH, SSH_ORIGINAL_COMMAND: info.command },
                stdio: ["ignore", "pipe", "ignore"],
              });
              child.stdout.pipe(stream, { end: false });
              child.on("close", (code) => {
                stream.exit(code ?? 1);
                stream.end();
              });
            }
            // "hang": the connection stays open and silent.
          });
        });
      });
      client.on("error", () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  }, 60_000);

  afterAll(async () => {
    server?.close();
    const { pool } = await import("./db.ts");
    await pool.end().catch(() => {});
    await conn?.pool.end().catch(() => {});
    // pool.end() resolves before every socket has closed; dropping with force right away would
    // terminate those sockets and surface as an unhandled error, so wait for them first.
    for (let attempt = 0; attempt < 50; attempt++) {
      const dropped = await admin?.pool.query(`drop database if exists ${dbName}`).then(
        () => true,
        () => false,
      );
      if (dropped) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`).catch(() => {});
    await admin?.pool.end().catch(() => {});
    await rm(workDir, { recursive: true, force: true });
  });

  describe("access key", () => {
    it("is generated by the worker, sealed in the vault, and created once", async () => {
      await Promise.all([
        hosts.ensureHostAccessKey(org),
        hosts.ensureHostAccessKey(org),
        hosts.ensureHostAccessKey(org),
      ]);
      expect(await hosts.ensureHostAccessKey(org)).toEqual({ created: false });

      const rows = await conn.db
        .select()
        .from(schema.hostAccessKey)
        .where(eq(schema.hostAccessKey.organizationId, org));
      expect(rows).toHaveLength(1);
      const row = rows[0] as (typeof rows)[number];
      expect(row.publicKey).toMatch(
        /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA[A-Za-z0-9+/]{44} garnetops-host-access$/,
      );
      expect(row.fingerprint).toBe(fingerprint(row.publicKey.split(" ")[1] as string));
      expect(row.state).toBe("active");

      // The private half exists only sealed, bound to this organisation, record and purpose.
      const [secret] = await conn.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row.secretId as string));
      expect(secret?.purpose).toBe("host-ssh-key");
      const stored = JSON.stringify(secret?.sealed);
      expect(stored).not.toContain("PRIVATE KEY");
      expect(stored).not.toContain(row.publicKey.split(" ")[1] as string);
      const { env } = await import("./env.ts");
      const opened = open(
        secret?.sealed,
        { organizationId: org, recordId: row.secretId as string, purpose: "host-ssh-key" },
        loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8")),
      );
      privateKeyOfAccess = opened.toString("utf8");
      expect(privateKeyOfAccess).toContain("BEGIN OPENSSH PRIVATE KEY");
      expect(() =>
        open(
          secret?.sealed,
          { organizationId: "org_other", recordId: secret?.id as string, purpose: "host-ssh-key" },
          loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8")),
        ),
      ).toThrow();

      // The key pair matches: ssh-keygen derives the same public key from the sealed private key.
      const keyFile = join(workDir, "access-key-check");
      writeFileSync(keyFile, privateKeyOfAccess, { mode: 0o600 });
      const derived = spawnSync("ssh-keygen", ["-y", "-f", keyFile], { encoding: "utf8" });
      expect(derived.stdout.trim().split(" ").slice(0, 2).join(" ")).toBe(
        row.publicKey.split(" ").slice(0, 2).join(" "),
      );
      allowedKey = utils.parseKey(row.publicKey);

      const audit = await conn.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "host.access_key_created"));
      expect(audit).toHaveLength(1);
      expect(JSON.stringify(audit[0]?.data)).not.toContain("PRIVATE");
    });
  });

  describe("host key scan", () => {
    it("proposes the key a new server presents, as a candidate and nothing more", async () => {
      const id = await addHost({ status: "pending" });
      await hosts.scanHost(id, { resolve: resolveLocal });
      const host = await hostRow(id);
      expect(host.hostKeyStatus).toBe("pending");
      expect(host.hostKey).toBeNull();
      expect(host.candidateKeyType).toBe("ssh-ed25519");
      expect(host.candidateKey).toBe(hostKey.publicKey.split(" ")[1]);
      expect(host.candidateKeyFingerprint).toBe(fingerprint(hostKey.publicKey.split(" ")[1] as string));
      expect(host.lastError).toBeNull();
    });

    it("does not call a server changed that still presents its pinned key", async () => {
      const id = await addHost();
      await hosts.scanHost(id, { resolve: resolveLocal });
      const host = await hostRow(id);
      expect(host.hostKeyStatus).toBe("confirmed");
      expect(host.candidateKey).toBeNull();
    });

    it("marks a server whose key is not the pinned one as changed, keeps the pin and audits it", async () => {
      const id = await addHost({ pinned: otherHostKey.publicKey });
      await hosts.scanHost(id, { resolve: resolveLocal });
      const host = await hostRow(id);
      expect(host.hostKeyStatus).toBe("changed");
      expect(host.hostKey).toBe(otherHostKey.publicKey.split(" ")[1]);
      expect(host.candidateKeyFingerprint).toBe(fingerprint(hostKey.publicKey.split(" ")[1] as string));
      expect(host.lastError).toBe(
        "The server's host key changed. An admin must confirm the new fingerprint before the inventory runs again.",
      );
      const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit.map((a) => a.action)).toEqual(["host.key_changed"]);
    });

    it("reports an address that serves no SSH, with a short message and no ssh output", async () => {
      const id = await addHost({ status: "pending" });
      await conn.db.update(schema.host).set({ port: 1 }).where(eq(schema.host.id, id));
      await hosts.scanHost(id, { resolve: resolveLocal });
      const host = await hostRow(id);
      expect(host.candidateKey).toBeNull();
      expect(host.lastError).toBe(
        "No SSH host key could be read from the server. Check the address and port.",
      );
    });

    it("refuses loopback and metadata addresses before any connection", async () => {
      const before = seen.connections;
      for (const address of ["localhost", "127.0.0.1", "169.254.169.254", "app.localhost"]) {
        const id = await addHost({ status: "pending", address });
        await hosts.scanHost(id);
        expect((await hostRow(id)).lastError, address).toBe(
          "The address points to a loopback, link-local or otherwise reserved address.",
        );
      }
      expect(seen.connections).toBe(before);
    });
  });

  describe("inventory", () => {
    it("reads the report, stores packages and findings, and counts what is pending", async () => {
      matcher.report = JSON.parse(readFileSync(join(fixtures, "host-grype-debian.json"), "utf8"));
      matcher.fail = false;
      behaviour.current = { kind: "report", text: DEBIAN_REPORT };
      seen.commands.length = 0;
      const hostId = await addHost();
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });

      // The only thing asked of the server is the word "inventory".
      expect(seen.commands).toEqual(["inventory"]);
      const run = await runRow(runId);
      expect(run).toMatchObject({
        state: "succeeded",
        error: null,
        packageCount: 3,
        pendingUpdates: 1,
        newFindings: 2,
      });
      expect(run.severityCounts).toEqual({ critical: 1, low: 1 });
      expect(run.scannerVersions).toEqual({ grype: "0.120.1" });

      const host = await hostRow(hostId);
      expect(host).toMatchObject({
        osId: "debian",
        osVersionId: "12",
        osName: "Debian GNU/Linux 12 (bookworm)",
        kernel: "6.1.0-18-amd64",
        arch: "x86_64",
        packageCount: 3,
        pendingUpdates: 1,
        securityUpdates: 1,
        lastError: null,
      });
      expect(host.lastInventoryAt).not.toBeNull();

      const packages = await conn.db
        .select()
        .from(schema.hostPackage)
        .where(eq(schema.hostPackage.hostId, hostId));
      expect(packages.map((p) => [p.name, p.version, p.upgradableTo, p.securityUpdate]).sort()).toEqual([
        ["bash", "5.2.15-2+b2", null, false],
        ["libssl3", "3.0.11-1~deb12u2", "3.0.11-1~deb12u3", true],
        ["tzdata", "2024a-0+deb12u1", null, false],
      ]);

      const findings = await conn.db
        .select()
        .from(schema.hostFinding)
        .where(eq(schema.hostFinding.hostId, hostId));
      expect(findings.map((f) => [f.vulnerabilityId, f.packageName, f.severity, f.state, f.fixedIn])).toEqual(
        expect.arrayContaining([
          ["CVE-2099-1001", "libssl3", "critical", "open", ["3.0.11-1~deb12u3"]],
          ["CVE-2099-1002", "bash", "low", "open", []],
        ]),
      );
      const [vulnerability] = await conn.db
        .select()
        .from(schema.vulnerability)
        .where(eq(schema.vulnerability.id, "CVE-2099-1001"));
      expect(vulnerability).toMatchObject({
        severity: "critical",
        cvssScore: 9.8,
        epss: 0.42,
        knownExploited: true,
      });
    });

    it("hands grype an SBOM with the distribution and package URLs that include the source package", async () => {
      const sbom = matcher.sbom;
      expect(sbom?.distro).toMatchObject({ id: "debian", versionID: "12" });
      expect(sbom?.artifacts.find((a) => a.name === "libssl3")?.purl).toBe(
        "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
      );
    });

    it("does not duplicate findings on the next run, and resolves what is gone", async () => {
      const hostId = await addHost();
      for (const result of ["both", "both", "none"] as const) {
        matcher.report =
          result === "both"
            ? JSON.parse(readFileSync(join(fixtures, "host-grype-debian.json"), "utf8"))
            : { matches: [], descriptor: { version: "0.120.1" } };
        const runId = await queueRun(hostId);
        await hosts.runHostInventory(runId, { resolve: resolveLocal });
        const run = await runRow(runId);
        expect(run.state).toBe("succeeded");
        if (result === "none") expect(run.resolvedFindings).toBe(2);
      }
      const findings = await conn.db
        .select()
        .from(schema.hostFinding)
        .where(eq(schema.hostFinding.hostId, hostId));
      expect(findings).toHaveLength(2);
      expect(findings.every((f) => f.state === "resolved" && f.resolvedAt !== null)).toBe(true);
    });

    it("runs the real wrapper as sshd would and parses what it prints", async () => {
      if (process.platform === "win32") return;
      matcher.report = { matches: [], descriptor: { version: "0.120.1" } };
      behaviour.current = { kind: "wrapper" };
      const hostId = await addHost();
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      const run = await runRow(runId);
      // A test machine without a recognised os-release stops at the matching step, with a reason.
      expect(["succeeded", "failed"]).toContain(run.state);
      if (run.state === "failed")
        expect(run.error).toBe(
          "The operating system is not recognised, so vulnerabilities cannot be matched.",
        );
      const host = await hostRow(hostId);
      expect(host.kernel).not.toBeNull();
      expect(host.arch).not.toBeNull();
    });

    it("refuses to connect before an admin confirmed the host key", async () => {
      const before = seen.connections;
      const hostId = await addHost({ status: "pending" });
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      expect((await runRow(runId)).error).toBe(
        "The host key is not confirmed yet. Confirm its fingerprint first.",
      );
      expect(seen.connections).toBe(before);
    });

    it("stops on a changed host key, records the new one and leaves packages alone", async () => {
      behaviour.current = { kind: "report", text: DEBIAN_REPORT };
      const hostId = await addHost({ pinned: otherHostKey.publicKey });
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      const run = await runRow(runId);
      expect(run.state).toBe("failed");
      expect(run.error).toMatch(/^The server's host key changed\./);
      const host = await hostRow(hostId);
      expect(host.hostKeyStatus).toBe("changed");
      expect(host.candidateKeyFingerprint).toBe(fingerprint(hostKey.publicKey.split(" ")[1] as string));
      expect(host.hostKey).toBe(otherHostKey.publicKey.split(" ")[1]);
      expect(
        await conn.db.select().from(schema.hostPackage).where(eq(schema.hostPackage.hostId, hostId)),
      ).toHaveLength(0);

      // And it stays blocked: the next run asks nothing of the server (it only looks at the host key again).
      const asked = seen.commands.length;
      const again = await queueRun(hostId);
      await hosts.runHostInventory(again, { resolve: resolveLocal });
      expect((await runRow(again)).error).toMatch(/^The server's host key changed\./);
      expect(seen.commands.length).toBe(asked);
    });

    it("reports a server that does not accept the access key", async () => {
      const saved = allowedKey;
      allowedKey = utils.parseKey(generateDeployKey("someone-else").publicKey);
      try {
        const runId = await queueRun(await addHost());
        await hosts.runHostInventory(runId, { resolve: resolveLocal });
        const run = await runRow(runId);
        expect(run.state).toBe("failed");
        expect(run.error).toBe(
          "The server refused the access key. Run the host setup script again and check the allowed source address.",
        );
      } finally {
        allowedKey = saved;
      }
    });

    it("cuts off a report that is larger than the limit", async () => {
      behaviour.current = { kind: "stream", bytes: 3 * 1024 * 1024 };
      const runId = await queueRun(await addHost());
      await hosts.runHostInventory(runId, { resolve: resolveLocal, maxBytes: 1024 * 1024 });
      const run = await runRow(runId);
      expect(run.state).toBe("failed");
      expect(run.error).toBe("The inventory is larger than the 16 MB limit.");
    });

    it("gives up on a server that stays silent", async () => {
      behaviour.current = { kind: "hang" };
      const runId = await queueRun(await addHost());
      const started = Date.now();
      await hosts.runHostInventory(runId, { resolve: resolveLocal, timeoutMs: 1500 });
      expect(Date.now() - started).toBeLessThan(15_000);
      expect((await runRow(runId)).error).toBe("The inventory took longer than 60 seconds.");
    });

    it("refuses output in an unexpected format without showing it", async () => {
      behaviour.current = { kind: "report", text: "root:x:0:0:root:/root:/bin/bash\nsecret-looking-line\n" };
      const hostId = await addHost();
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      const run = await runRow(runId);
      expect(run.error).toBe("The server returned an inventory in an unexpected format.");
      expect(JSON.stringify(await hostRow(hostId))).not.toContain("secret-looking-line");
    });

    it("refuses a report that was cut off, so a short list never looks like a clean server", async () => {
      behaviour.current = { kind: "report", text: DEBIAN_REPORT.replace("@@end\n", "") };
      const hostId = await addHost();
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      expect((await runRow(runId)).error).toBe("The server returned an inventory in an unexpected format.");
      expect((await hostRow(hostId)).packageCount).toBeNull();
    });

    it("keeps the packages but marks the run failed when the operating system is unknown", async () => {
      behaviour.current = { kind: "report", text: DEBIAN_REPORT.replace("ID=debian\n", "") };
      const hostId = await addHost();
      const runId = await queueRun(hostId);
      await hosts.runHostInventory(runId, { resolve: resolveLocal });
      const run = await runRow(runId);
      expect(run).toMatchObject({ state: "failed", packageCount: 3 });
      expect(run.error).toBe("The operating system is not recognised, so vulnerabilities cannot be matched.");
      expect((await hostRow(hostId)).packageCount).toBe(3);
    });

    it("keeps the packages but marks the run failed when the vulnerability database is missing", async () => {
      behaviour.current = { kind: "report", text: DEBIAN_REPORT };
      matcher.fail = true;
      try {
        const hostId = await addHost();
        const runId = await queueRun(hostId);
        await hosts.runHostInventory(runId, { resolve: resolveLocal });
        const run = await runRow(runId);
        expect(run).toMatchObject({ state: "failed", packageCount: 3 });
        expect(run.error).toBe(
          "The vulnerability scanner failed. Check that the vulnerability database is installed.",
        );
        expect(
          await conn.db.select().from(schema.hostFinding).where(eq(schema.hostFinding.hostId, hostId)),
        ).toHaveLength(0);
      } finally {
        matcher.fail = false;
      }
    });

    it("takes a queued run once, even when two workers get the same job", async () => {
      behaviour.current = { kind: "report", text: DEBIAN_REPORT };
      matcher.report = { matches: [], descriptor: { version: "0.120.1" } };
      const before = seen.connections;
      const runId = await queueRun(await addHost());
      await Promise.all([
        hosts.runHostInventory(runId, { resolve: resolveLocal }),
        hosts.runHostInventory(runId, { resolve: resolveLocal }),
      ]);
      expect(seen.connections).toBe(before + 1);
      expect((await runRow(runId)).state).toBe("succeeded");
    });

    it("never writes the private key or the report text into the database or its error messages", async () => {
      const dump = JSON.stringify([
        await conn.db.select().from(schema.hostInventoryRun),
        await conn.db.select().from(schema.host),
        await conn.db.select().from(schema.auditLog),
      ]);
      expect(dump).not.toContain("PRIVATE KEY");
      expect(dump).not.toContain(privateKeyOfAccess.split("\n")[1] as string);
      expect(dump).not.toContain("Permission denied");
    });
  });
});
