/**
 * Proxmox VE end to end (ADR 0012): reading the certificate, the pinned connection, the
 * read-only client and the sync, against a local HTTPS server that replays recorded
 * (synthetic) answers of PVE 8.x and 9.x. The server has a throw-away self-signed certificate
 * made with openssl, like the notification test. A throw-away PostgreSQL database on the
 * development server and a real vault key stand in for the installation. Skipped without
 * openssl or the development PostgreSQL. Nothing leaves the machine.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isReadPath } from "@garnetops/core/proxmox";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../../../packages/core/test/fixtures/proxmox/", import.meta.url));

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
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}

const HOST = "pve.example.test";
const TOKEN_ID = "garnetops@pve!inventory";
/** A made-up secret in the shape Proxmox issues (a UUID). It must never appear in a row or a log line. */
const TOKEN_SECRET = "11111111-2222-4333-8444-555555555555";
const ORG = "org_proxmox";

interface Logged {
  method: string;
  url: string;
  path: string;
  authorization: string | undefined;
  host: string | undefined;
}

function selfSigned(dir: string, name: string): { key: string; cert: string } {
  const keyFile = join(dir, `${name}.key`);
  const certFile = join(dir, `${name}.pem`);
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-days",
      "1",
      "-subj",
      `/CN=${HOST}/O=Example ${name}`,
      "-addext",
      `subjectAltName=DNS:${HOST}`,
      "-keyout",
      keyFile,
      "-out",
      certFile,
    ],
    { stdio: "ignore" },
  );
  return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
}

describe.skipIf(!openssl || !adminUrl)("Proxmox VE: certificate pinning, read-only client and sync", () => {
  const dbName = `garnetops_proxmox_test_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let server: Server;
  let port = 0;
  let certA = { key: "", cert: "" };
  let certB = { key: "", cert: "" };
  let fingerprintA = "";
  let fingerprintB = "";
  let px: typeof import("./proxmox.ts");
  let http: typeof import("./proxmox-http.ts");
  let core: typeof import("@garnetops/core/proxmox");
  let counter = 0;
  const log: Logged[] = [];
  const connections = { n: 0 };
  /** Replaces the answer for one path (path without query), or makes it hang or stream. */
  const overrides = new Map<string, (res: import("node:http").ServerResponse) => void>();
  const state = { permissions: "permissions" };
  const consoleLines: string[] = [];

  const fixture = (name: string) => readFileSync(join(fixtures, "pve8", `${name}.json`), "utf8");
  const resolveLocal = async () => "127.0.0.1";
  const deps = () => ({ resolve: resolveLocal, test: { ca: certA.cert }, gapMs: 0 });

  /** What the fake Proxmox answers: the recorded fixtures by path. */
  function answer(path: string, query: string): string | null {
    const fixed: Record<string, string> = {
      "/version": "version",
      "/cluster/status": "cluster-status",
      "/cluster/resources": "cluster-resources",
      "/cluster/ha/resources": "ha-resources",
      "/cluster/backup": "backup-jobs",
      "/access/permissions": state.permissions,
      "/nodes/pve1/status": "node-status-pve1",
      "/nodes/pve2/status": "node-status-pve2",
      "/nodes/pve1/apt/update": "apt-update-pve1",
      "/nodes/pve2/apt/update": "apt-update-pve2",
      "/nodes/pve1/qemu/100/agent/network-get-interfaces": "qemu-agent-interfaces-100",
      "/nodes/pve1/lxc/200/interfaces": "lxc-interfaces-200",
    };
    if (fixed[path]) return fixture(fixed[path]);
    const guest = /^\/nodes\/pve\d\/(qemu|lxc)\/(\d+)\/(config|snapshot)$/.exec(path);
    if (guest) {
      try {
        return fixture(`${guest[1]}-${guest[2]}-${guest[3]}`);
      } catch {
        return null;
      }
    }
    if (query === "content=backup") {
      if (path === "/nodes/pve1/storage/local/content") return fixture("storage-content-backup-local-pve1");
      if (path === "/nodes/pve2/storage/local/content") return JSON.stringify({ data: [] });
      if (path === "/nodes/pve1/storage/nas-backup/content") return fixture("storage-content-backup-nas");
    }
    return null;
  }

  function newClusterRow(overrides: Partial<typeof schema.proxmoxCluster.$inferInsert> = {}) {
    const n = ++counter;
    return {
      id: `pxc_test${String(n).padStart(12, "0")}`,
      organizationId: ORG,
      name: `Lab ${n}`,
      // Every connection of an organisation has its own endpoint (unique index); the test resolves them all to the local server.
      apiUrl: `https://pve${n}.example.test:${port}`,
      host: `pve${n}.example.test`,
      port,
      tokenId: TOKEN_ID,
      ...overrides,
    };
  }

  /** A connection with its token sealed in the vault, like the API stores it. */
  async function addCluster(
    options: Partial<typeof schema.proxmoxCluster.$inferInsert> & { pinned?: string | null } = {},
  ) {
    const { pinned, ...rest } = options;
    const row = newClusterRow(rest);
    const secretId = `sec_test${String(counter).padStart(12, "0")}`;
    const { env } = await import("./env.ts");
    const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
    await conn.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "proxmox-token",
      sealed: seal(
        TOKEN_SECRET,
        { organizationId: ORG, recordId: secretId, purpose: "proxmox-token" },
        vaultPublicKeyOf(vault),
      ),
      vaultKeyId: vault.id,
    });
    const fingerprint = pinned === undefined ? fingerprintA : pinned;
    await conn.db.insert(schema.proxmoxCluster).values({
      secretId,
      ...(fingerprint ? { certStatus: "confirmed" as const, certFingerprint: fingerprint } : {}),
      ...row,
    });
    return row.id;
  }
  async function queueRun(clusterId: string) {
    const id = `pxr_test${String(++counter).padStart(12, "0")}`;
    await conn.db
      .insert(schema.proxmoxSyncRun)
      .values({ id, organizationId: ORG, clusterId, state: "queued", trigger: "manual" });
    return id;
  }
  const cluster = async (id: string) =>
    (
      await conn.db.select().from(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id))
    )[0] as typeof schema.proxmoxCluster.$inferSelect;
  const run = async (id: string) =>
    (
      await conn.db.select().from(schema.proxmoxSyncRun).where(eq(schema.proxmoxSyncRun.id, id))
    )[0] as typeof schema.proxmoxSyncRun.$inferSelect;
  const guests = async (clusterId: string) =>
    conn.db.select().from(schema.proxmoxGuest).where(eq(schema.proxmoxGuest.clusterId, clusterId));
  const sync = async (clusterId: string, extra: Record<string, unknown> = {}) => {
    const id = await queueRun(clusterId);
    log.length = 0;
    await px.runProxmoxSync(id, { ...deps(), ...extra });
    return run(id);
  };

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    workDir = await mkdtemp(join(tmpdir(), "garnetops-proxmox-test-"));
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
    await conn.db.insert(schema.organization).values({ id: ORG, name: "Proxmox Test" });

    certA = selfSigned(workDir, "A");
    certB = selfSigned(workDir, "B");
    const { X509Certificate } = await import("node:crypto");
    fingerprintA = new X509Certificate(certA.cert).fingerprint256;
    fingerprintB = new X509Certificate(certB.cert).fingerprint256;

    server = createServer({ key: certA.key, cert: certA.cert }, (req, res) => {
      const [path = "", query = ""] = (req.url ?? "").replace(/^\/api2\/json/, "").split("?");
      log.push({
        method: req.method ?? "",
        url: req.url ?? "",
        path,
        authorization: req.headers.authorization,
        host: req.headers.host,
      });
      const override = overrides.get(path);
      if (override) return override(res);
      if (req.method !== "GET") return void res.writeHead(501).end();
      const body = answer(path, query);
      if (body === null) {
        return void res
          .writeHead(500, { "content-type": "application/json" })
          .end('{"data":null,"message":"not here"}');
      }
      res.writeHead(200, { "content-type": "application/json;charset=UTF-8" }).end(body);
    });
    server.on("secureConnection", () => {
      connections.n++;
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;

    for (const method of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      });
    }
    px = await import("./proxmox.ts");
    http = await import("./proxmox-http.ts");
    core = await import("@garnetops/core/proxmox");
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    server?.close();
    server?.closeAllConnections();
    const { pool } = await import("./db.ts");
    await pool.end().catch(() => {});
    await conn?.pool.end().catch(() => {});
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

  describe("certificate (trust on first use)", () => {
    it("reads the leaf certificate without sending a request, and only proposes it", async () => {
      const id = await addCluster({ pinned: null });
      log.length = 0;
      await px.readCertificate(id, deps());
      const row = await cluster(id);
      expect(row.certStatus).toBe("pending");
      expect(row.certFingerprint).toBeNull();
      expect(row.candidateFingerprint).toBe(fingerprintA);
      expect(row.candidateSubject).toContain(`CN=${HOST}`);
      expect(row.candidateIssuer).toContain(`CN=${HOST}`);
      expect(row.candidateValidTo && row.candidateValidTo > new Date()).toBe(true);
      // The test certificate is self-signed: it chains to no public CA.
      expect(row.candidateCaTrusted).toBe(false);
      expect(row.lastError).toBeNull();
      // Not one HTTP request: the token was never sent.
      expect(log).toEqual([]);
    });

    it("refuses to sync before an admin has confirmed the fingerprint", async () => {
      const id = await addCluster({ pinned: null });
      const result = await sync(id);
      expect(result.state).toBe("failed");
      expect(result.error).toBe("The certificate is not confirmed yet. Confirm its fingerprint first.");
      expect(log).toEqual([]);
    });

    it("a changed certificate blocks the sync before the token is sent, and is audited once", async () => {
      const id = await addCluster();
      server.setSecureContext({ key: certB.key, cert: certB.cert });
      try {
        const first = await sync(id);
        expect(first.state).toBe("failed");
        expect(first.error).toBe(
          "The certificate of the Proxmox server changed. An admin must confirm the new fingerprint before the next sync.",
        );
        // Not even one HTTP request reached the server: the connection was dropped after the handshake.
        expect(log).toEqual([]);
        const row = await cluster(id);
        expect(row.certStatus).toBe("changed");
        expect(row.certFingerprint).toBe(fingerprintA);
        expect(row.candidateFingerprint).toBe(fingerprintB);
        expect(row.candidateSubject).toContain("Example B");

        // Asking again does not repeat the audit entry.
        await sync(id);
        await px.readCertificate(id, { ...deps(), test: { ca: certB.cert } });
        const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
        expect(audit.map((a) => a.action)).toEqual(["proxmox.certificate_changed"]);
        expect(audit[0]?.data).toEqual({ name: row.name, pinned: fingerprintA, seen: fingerprintB });

        // The old certificate is back: looking again clears the alarm, and then the sync works.
        server.setSecureContext({ key: certA.key, cert: certA.cert });
        expect((await sync(id)).state).toBe("failed"); // still blocked until the certificate was looked at again
        await px.readCertificate(id, deps());
        const again = await sync(id);
        expect(again.state).toBe("succeeded");
        expect((await cluster(id)).certStatus).toBe("confirmed");
        expect((await cluster(id)).candidateFingerprint).toBeNull();
      } finally {
        server.setSecureContext({ key: certA.key, cert: certA.cert });
      }
    });

    it("pins exactly the leaf: a certificate for the right name from another key is refused", async () => {
      const id = await addCluster({ pinned: fingerprintB });
      const result = await sync(id);
      expect(result.error).toContain("certificate of the Proxmox server changed");
      expect(log).toEqual([]);
    });
  });

  describe("read-only client", () => {
    const client = () =>
      new http.ProxmoxClient({
        endpoint: { host: HOST, port, address: "127.0.0.1" },
        pinned: fingerprintA,
        tokenId: TOKEN_ID,
        tokenSecret: TOKEN_SECRET,
        gapMs: 0,
        test: { ca: certA.cert },
      });

    it("sends GET only, with the token in the Authorization header", async () => {
      const c = client();
      try {
        log.length = 0;
        expect(await c.get("/version")).toMatchObject({ version: "8.2.4" });
        expect(log).toHaveLength(1);
        expect(log[0]).toMatchObject({
          method: "GET",
          path: "/version",
          authorization: `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
          host: `${HOST}:${port}`,
        });
      } finally {
        c.close();
      }
    });

    it("refuses every other method before it connects", async () => {
      const c = client();
      try {
        const before = connections.n;
        log.length = 0;
        for (const method of ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get", ""]) {
          await expect(c.request(method, "/version")).rejects.toThrow(/not allowed/);
        }
        await expect(c.request("POST", "/nodes/pve1/qemu/100/status/start")).rejects.toThrow(/not allowed/);
        expect(log).toEqual([]);
        expect(connections.n).toBe(before);
        expect(c.requests).toBe(0);
      } finally {
        c.close();
      }
    });

    it("refuses paths outside the allow-list, even with GET", async () => {
      const c = client();
      try {
        for (const path of [
          "/nodes/pve1/qemu/100/status/start",
          "/nodes/pve1/qemu/100/agent/exec",
          "/access/users",
          "/nodes/pve1/tasks",
          "/version/../access/users",
          "/api2/json/version",
        ]) {
          await expect(c.get(path), path).rejects.toThrow(/allow-list/);
        }
        await expect(c.get("/version", { x: "1" })).rejects.toThrow(/allow-list/);
        expect(log).toEqual([]);
      } finally {
        c.close();
      }
    });

    it("sent only allow-listed GET requests during a whole sync", async () => {
      const id = await addCluster();
      const result = await sync(id);
      expect(result.state).toBe("succeeded");
      expect(log.length).toBeGreaterThan(20);
      for (const entry of log) {
        expect(entry.method).toBe("GET");
        expect(isReadPath(entry.url.replace(/^\/api2\/json/, "").split("?")[0] as string), entry.url).toBe(
          true,
        );
        expect(entry.authorization).toBe(`PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`);
      }
      // The node that is offline is not asked anything.
      expect(log.some((l) => l.path.startsWith("/nodes/pve3/"))).toBe(false);
      // No refresh, no status change, no console: only reads.
      expect(
        log.some((l) => /\/status\/(start|stop|shutdown|reset)|termproxy|vncproxy|agent\/exec/.test(l.path)),
      ).toBe(false);
      expect(core.READ_PATHS.length).toBe(12);
    });

    it("does not follow redirects", async () => {
      overrides.set(
        "/version",
        (res) => void res.writeHead(302, { location: "/api2/json/access/users" }).end(),
      );
      const c = client();
      try {
        log.length = 0;
        await expect(c.get("/version")).rejects.toMatchObject({ code: "redirected" });
        expect(log.map((l) => l.path)).toEqual(["/version"]);
      } finally {
        overrides.delete("/version");
        c.close();
      }
    });

    it("refuses an answer larger than the limit, declared or streamed", async () => {
      const big = Buffer.alloc(100_000, 0x20);
      overrides.set("/version", (res) => void res.writeHead(200, { "content-length": big.length }).end(big));
      overrides.set("/cluster/status", (res) => {
        // No content-length: chunks until the client gives up.
        res.writeHead(200);
        const timer = setInterval(() => res.write(big), 1);
        res.on("close", () => clearInterval(timer));
      });
      const c = new http.ProxmoxClient({
        endpoint: { host: HOST, port, address: "127.0.0.1" },
        pinned: fingerprintA,
        tokenId: TOKEN_ID,
        tokenSecret: TOKEN_SECRET,
        gapMs: 0,
        maxBytes: 50_000,
        test: { ca: certA.cert },
      });
      try {
        await expect(c.get("/version")).rejects.toMatchObject({ code: "responseTooLarge" });
        await expect(c.get("/cluster/status")).rejects.toMatchObject({ code: "responseTooLarge" });
      } finally {
        overrides.delete("/version");
        overrides.delete("/cluster/status");
        c.close();
      }
    });

    it("answers a request that never finishes with a timeout", async () => {
      overrides.set("/version", () => {});
      const c = new http.ProxmoxClient({
        endpoint: { host: HOST, port, address: "127.0.0.1" },
        pinned: fingerprintA,
        tokenId: TOKEN_ID,
        tokenSecret: TOKEN_SECRET,
        gapMs: 0,
        timeoutMs: 300,
        test: { ca: certA.cert },
      });
      try {
        await expect(c.get("/version")).rejects.toMatchObject({ code: "timeout" });
      } finally {
        overrides.delete("/version");
        c.close();
      }
    });

    it("treats malformed JSON and a missing data member as an invalid response", async () => {
      const c = client();
      try {
        overrides.set("/version", (res) => void res.writeHead(200).end("not json {"));
        await expect(c.get("/version")).rejects.toMatchObject({ code: "invalidResponse" });
        overrides.set("/version", (res) => void res.writeHead(200).end('{"version":"8"}'));
        await expect(c.get("/version")).rejects.toMatchObject({ code: "invalidResponse" });
      } finally {
        overrides.delete("/version");
        c.close();
      }
    });

    it("never resolves a name to a reserved address", async () => {
      for (const host of ["localhost", "127.0.0.1", "169.254.169.254", "::1", "app.localhost", "127.1"]) {
        await expect(http.resolveProxmoxAddress(host), host).rejects.toMatchObject({
          code: "addressRefused",
        });
      }
      await expect(http.resolveProxmoxAddress("192.0.2.5")).resolves.toBe("192.0.2.5");
    });
  });

  describe("sync", () => {
    it("stores nodes, guests, storage and the run, from the recorded PVE 8 answers", async () => {
      const id = await addCluster();
      const result = await sync(id);
      expect(result).toMatchObject({ state: "succeeded", error: null, nodeCount: 3, guestCount: 8 });
      expect(result.warnings).toEqual(["entriesDropped", "nodeOffline"]);
      expect(result.requestCount).toBe(log.length);

      const c = await cluster(id);
      expect(c).toMatchObject({
        version: "8.2.4",
        clusterName: "lab-cluster",
        quorate: true,
        backupsReadable: true,
        lastError: null,
        extraPrivileges: [],
      });
      expect(c.lastSyncAt).not.toBeNull();

      const nodes = await conn.db
        .select()
        .from(schema.proxmoxNode)
        .where(eq(schema.proxmoxNode.clusterId, id));
      const byName = Object.fromEntries(nodes.map((n) => [n.name, n]));
      expect(Object.keys(byName).sort()).toEqual(["pve1", "pve2", "pve3"]);
      expect(byName.pve1).toMatchObject({
        online: true,
        cpus: 8,
        pveVersion: "8.2.4",
        kernel: "6.8.12-1-pve",
        pendingUpdates: 3,
      });
      expect(byName.pve2?.pendingUpdates).toBe(0);
      expect(byName.pve3).toMatchObject({ online: false, pendingUpdates: null, uptime: null });

      const rows = await guests(id);
      const guest = (vmid: number) => rows.find((g) => g.vmid === vmid) as (typeof rows)[number];
      expect(rows.map((g) => g.vmid).sort((a, b) => a - b)).toEqual([
        100, 101, 102, 103, 200, 201, 202, 9000,
      ]);
      expect(guest(100)).toMatchObject({
        type: "qemu",
        name: "web-01",
        node: "pve1",
        status: "running",
        ostype: "l26",
        tags: ["prod", "web"],
        template: false,
        haState: "started",
        inBackupJob: true,
        snapshotCount: 2,
        ips: ["192.0.2.50", "2001:db8::50"],
      });
      expect(guest(100).lastBackupAt?.toISOString()).toBe("2026-10-20T02:00:05.000Z");
      expect(guest(100).newestSnapshotAt?.toISOString()).toBe("2026-10-18T08:00:00.000Z");
      expect(guest(100).oldestSnapshotAt?.toISOString()).toBe("2026-08-01T08:00:00.000Z");
      // The guest agent was asked for the second guest too, failed, and that is tolerated.
      expect(guest(101)).toMatchObject({ inBackupJob: true, snapshotCount: 0, ips: [] });
      expect(guest(101).lastBackupAt?.toISOString()).toBe("2026-10-01T02:00:05.000Z");
      expect(guest(102)).toMatchObject({
        status: "stopped",
        ostype: "win10",
        inBackupJob: false,
        lastBackupAt: null,
      });
      expect(guest(102).oldestSnapshotAt?.toISOString()).toBe("2026-01-05T08:00:00.000Z");
      expect(guest(200)).toMatchObject({
        type: "lxc",
        ostype: "debian",
        ips: ["192.0.2.60", "2001:db8::60"],
      });
      expect(guest(200).lastBackupAt?.toISOString()).toBe("2026-10-20T02:00:01.000Z");
      expect(guest(9000)).toMatchObject({ template: true, snapshotCount: null });
      expect(guest(103)).toMatchObject({ status: "other", node: "pve3", ostype: null, snapshotCount: null });
      expect(guest(202).name).toBe("<img src=x onerror=alert(1)>evil");
      // Loopback and link-local addresses written into a configuration are not kept.
      expect(guest(202).ips).toEqual([]);

      const storage = await conn.db
        .select()
        .from(schema.proxmoxStorage)
        .where(eq(schema.proxmoxStorage.clusterId, id));
      expect(storage).toHaveLength(5);
    });

    it("reads the shared storage once and every local one", async () => {
      const id = await addCluster();
      await sync(id);
      const listings = log.filter((l) => l.path.endsWith("/content")).map((l) => l.path);
      expect(listings.sort()).toEqual([
        "/nodes/pve1/storage/local/content",
        "/nodes/pve1/storage/nas-backup/content",
        "/nodes/pve2/storage/local/content",
      ]);
    });

    it("never stores descriptions, cloud-init data or the token secret, in rows or in logs", async () => {
      const id = await addCluster();
      const before = consoleLines.length;
      await sync(id);
      const dump: string[] = [];
      for (const table of [
        "proxmox_cluster",
        "proxmox_node",
        "proxmox_guest",
        "proxmox_storage",
        "proxmox_sync_run",
        "secret",
        "audit_log",
      ]) {
        const res = await conn.pool.query(`select row_to_json(t)::text as row from ${table} t`);
        dump.push(...res.rows.map((r: { row: string }) => r.row));
      }
      const all = dump.join("\n");
      expect(all).not.toContain(TOKEN_SECRET);
      expect(all).not.toMatch(/hunter2|owned|cipassword|AAAA|\*{6}/);
      // The sealed secret is not the plain text either.
      const secrets = await conn.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, (await cluster(id)).secretId as string));
      expect(JSON.stringify(secrets[0]?.sealed)).not.toContain(TOKEN_SECRET);
      expect(consoleLines.slice(before).join("\n")).not.toContain(TOKEN_SECRET);
      expect(consoleLines.join("\n")).not.toContain(TOKEN_SECRET);
    });

    it("keeps when a guest was first seen stopped, and forgets guests that are gone", async () => {
      const id = await addCluster();
      await sync(id);
      const first = (await guests(id)).find((g) => g.vmid === 102);
      await new Promise((r) => setTimeout(r, 20));
      await conn.db.insert(schema.proxmoxGuest).values({
        id: "pxg_gone000000000000001",
        organizationId: ORG,
        clusterId: id,
        vmid: 777,
        type: "qemu",
        name: "removed-guest",
        node: "pve1",
        status: "running",
        statusSince: new Date(),
        firstSeenAt: new Date(),
        lastSeenAt: new Date(Date.now() - 1000),
      });
      await sync(id);
      const rows = await guests(id);
      expect(rows.some((g) => g.vmid === 777)).toBe(false);
      const again = rows.find((g) => g.vmid === 102);
      expect(again?.id).toBe(first?.id);
      expect(again?.statusSince.toISOString()).toBe(first?.statusSince.toISOString());
      expect(again?.firstSeenAt.toISOString()).toBe(first?.firstSeenAt.toISOString());
    });

    it("reads PVE 9 answers as well", async () => {
      const pve9 = (name: string) => readFileSync(join(fixtures, "pve9", `${name}.json`), "utf8");
      const map: Record<string, string> = {
        "/version": pve9("version"),
        "/cluster/status": pve9("cluster-status"),
        "/cluster/resources": pve9("cluster-resources"),
        "/access/permissions": pve9("permissions"),
        "/cluster/backup": pve9("backup-jobs"),
        "/cluster/ha/resources": pve9("ha-resources"),
        "/nodes/pve1/status": pve9("node-status-pve1"),
        "/nodes/pve1/apt/update": pve9("apt-update-pve1"),
        "/nodes/pve1/storage/local/content": JSON.stringify({ data: [] }),
      };
      for (const [path, body] of Object.entries(map))
        overrides.set(path, (res) => void res.writeHead(200).end(body));
      try {
        const id = await addCluster();
        const result = await sync(id);
        expect(result).toMatchObject({ state: "succeeded", nodeCount: 1, guestCount: 2 });
        expect(await cluster(id)).toMatchObject({ version: "9.0.3", clusterName: null, quorate: null });
        const rows = await guests(id);
        expect(rows.find((g) => g.vmid === 100)).toMatchObject({
          name: "app-01",
          inBackupJob: true,
          tags: ["a", "b", "c"],
        });
        expect(rows.find((g) => g.vmid === 101)).toMatchObject({
          status: "paused",
          template: true,
          inBackupJob: false,
        });
      } finally {
        for (const path of Object.keys(map)) overrides.delete(path);
      }
    });

    it("tolerates a token that may not read backups, updates or one guest's details", async () => {
      const forbid = (res: import("node:http").ServerResponse) =>
        void res
          .writeHead(403, { "content-type": "application/json" })
          .end('{"data":null,"message":"Permission check failed"}');
      overrides.set("/nodes/pve1/storage/nas-backup/content", forbid);
      overrides.set("/nodes/pve1/apt/update", forbid);
      overrides.set("/nodes/pve2/qemu/102/config", forbid);
      overrides.set("/cluster/backup", forbid);
      try {
        const id = await addCluster();
        const result = await sync(id);
        expect(result.state).toBe("succeeded");
        expect(result.warnings).toEqual(
          expect.arrayContaining([
            "backupsUnreadable",
            "backupJobsUnreadable",
            "updatesUnreadable",
            "detailsUnreadable",
          ]),
        );
        const c = await cluster(id);
        // "No recent backup" cannot be told when a listing was refused, so it must not be flagged.
        expect(c.backupsReadable).toBe(false);
        const rows = await guests(id);
        expect(rows.find((g) => g.vmid === 100)?.inBackupJob).toBeNull();
        expect(rows.find((g) => g.vmid === 102)?.ostype).toBeNull();
        const nodes = await conn.db
          .select()
          .from(schema.proxmoxNode)
          .where(eq(schema.proxmoxNode.clusterId, id));
        expect(nodes.find((n) => n.name === "pve1")?.pendingUpdates).toBeNull();
        expect(nodes.find((n) => n.name === "pve2")?.pendingUpdates).toBe(0);
      } finally {
        for (const p of [
          "/nodes/pve1/storage/nas-backup/content",
          "/nodes/pve1/apt/update",
          "/nodes/pve2/qemu/102/config",
          "/cluster/backup",
        ]) {
          overrides.delete(p);
        }
      }
    });

    it("keeps what it knew of a node that is offline", async () => {
      const id = await addCluster();
      await sync(id);
      await conn.db
        .update(schema.proxmoxNode)
        .set({ pendingUpdates: 9, pveVersion: "8.1.0" })
        .where(eq(schema.proxmoxNode.name, "pve3"));
      await conn.db
        .update(schema.proxmoxGuest)
        .set({ ostype: "l26", snapshotCount: 4 })
        .where(eq(schema.proxmoxGuest.vmid, 103));
      await sync(id);
      const nodes = await conn.db
        .select()
        .from(schema.proxmoxNode)
        .where(eq(schema.proxmoxNode.clusterId, id));
      expect(nodes.find((n) => n.name === "pve3")).toMatchObject({ pendingUpdates: 9, pveVersion: "8.1.0" });
      expect((await guests(id)).find((g) => g.vmid === 103)).toMatchObject({
        ostype: "l26",
        snapshotCount: 4,
      });
    });

    it("fails with a plain message when the token is rejected or may read nothing", async () => {
      const denied = (status: number) => (res: import("node:http").ServerResponse) =>
        void res.writeHead(status).end('{"data":null}');
      overrides.set("/version", denied(401));
      try {
        const id = await addCluster();
        const result = await sync(id);
        expect(result.error).toBe("Proxmox rejected the API token. Check the token ID and secret.");
        expect((await cluster(id)).lastError).toBe(result.error);
      } finally {
        overrides.delete("/version");
      }
      overrides.set("/cluster/resources", denied(403));
      try {
        const id = await addCluster();
        const result = await sync(id);
        expect(result.error).toContain("The token may not read the inventory");
        expect(await guests(id)).toEqual([]);
      } finally {
        overrides.delete("/cluster/resources");
      }
    });

    it("does not take an answer that is not Proxmox, and never lets one empty the inventory", async () => {
      const id = await addCluster();
      await sync(id);
      const before = (await guests(id)).length;
      expect(before).toBe(8);
      overrides.set("/cluster/resources", (res) => void res.writeHead(200).end('{"data":{"not":"a list"}}'));
      try {
        const result = await sync(id);
        expect(result.error).toBe("Proxmox returned an answer in an unexpected format.");
        expect((await guests(id)).length).toBe(before);
      } finally {
        overrides.delete("/cluster/resources");
      }
      overrides.set("/version", (res) => void res.writeHead(200).end('{"data":{"version":"<b>9</b>"}}'));
      try {
        expect((await sync(id)).error).toBe("The server did not answer like Proxmox VE.");
      } finally {
        overrides.delete("/version");
      }
    });

    it("stops a sync that would send too many requests", async () => {
      const id = await addCluster();
      const result = await sync(id, { maxRequests: 6 });
      expect(result.error).toBe("The sync was stopped because it would send too many requests.");
      expect(log.length).toBeLessThanOrEqual(6);
    });

    it("stops a sync that takes longer than its budget", async () => {
      const id = await addCluster();
      const result = await sync(id, { budgetMs: -1 });
      expect(result.error).toBe("The sync took longer than 10 minutes and was stopped.");
    });

    it("gives up on a server that stops answering", async () => {
      overrides.set("/version", () => {});
      try {
        const id = await addCluster();
        const result = await sync(id, { timeoutMs: 200 });
        expect(result.error).toBe("The Proxmox server did not answer in time.");
      } finally {
        overrides.delete("/version");
      }
    });

    it("refuses a loopback or metadata address before any connection", async () => {
      const before = connections.n;
      for (const host of ["localhost", "127.0.0.1", "169.254.169.254"]) {
        const id = await addCluster({ host });
        const result = await sync(id, { resolve: undefined });
        expect(result.error, host).toBe(
          "The address points to a loopback, link-local or otherwise reserved address.",
        );
      }
      expect(connections.n).toBe(before);
    });

    it("runs a queued sync only once", async () => {
      const id = await addCluster();
      const runId = await queueRun(id);
      log.length = 0;
      await Promise.all([px.runProxmoxSync(runId, deps()), px.runProxmoxSync(runId, deps())]);
      const first = log.length;
      expect(first).toBeGreaterThan(0);
      await px.runProxmoxSync(runId, deps());
      expect(log.length).toBe(first);
    });

    it("reports a connection that was removed meanwhile", async () => {
      const id = await addCluster();
      const runId = await queueRun(id);
      await conn.db
        .update(schema.proxmoxSyncRun)
        .set({ state: "queued" })
        .where(eq(schema.proxmoxSyncRun.id, runId));
      await conn.db.delete(schema.proxmoxCluster).where(eq(schema.proxmoxCluster.id, id));
      // The run went with the cascade: nothing to do, nothing fails.
      await expect(px.runProxmoxSync(runId, deps())).resolves.toBeUndefined();
    });
  });

  describe("token privileges", () => {
    it("blocks the sync of a token that can do more than read, until an admin acknowledges it", async () => {
      state.permissions = "permissions-extra";
      try {
        const id = await addCluster();
        const blocked = await sync(id);
        expect(blocked.state).toBe("failed");
        expect(blocked.error).toBe(
          "The token can do more than read. An admin must acknowledge this before anything is synced.",
        );
        // Only the version and the token's own permissions were read: no inventory.
        expect(log.map((l) => l.path)).toEqual(["/version", "/access/permissions"]);
        expect(await guests(id)).toEqual([]);
        const c = await cluster(id);
        expect(c.extraPrivileges).toEqual(["Datastore.Allocate", "Permissions.Modify", "VM.PowerMgmt"]);
        const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
        expect(audit.map((a) => a.action)).toEqual(["proxmox.privileges_detected"]);

        // A partial acknowledgement is not enough ...
        await conn.db
          .update(schema.proxmoxCluster)
          .set({ acknowledgedPrivileges: ["VM.PowerMgmt"] })
          .where(eq(schema.proxmoxCluster.id, id));
        expect((await sync(id)).state).toBe("failed");
        // ... all of them are. Even then only reads are sent.
        await conn.db
          .update(schema.proxmoxCluster)
          .set({ acknowledgedPrivileges: c.extraPrivileges })
          .where(eq(schema.proxmoxCluster.id, id));
        const ok = await sync(id);
        expect(ok.state).toBe("succeeded");
        expect(log.every((l) => l.method === "GET")).toBe(true);
        // The same privileges are not reported twice.
        const again = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
        expect(again).toHaveLength(1);
      } finally {
        state.permissions = "permissions";
      }
    });
  });

  describe("schedule", () => {
    it("queues a sync for confirmed, acknowledged and idle connections only", async () => {
      await conn.db.delete(schema.proxmoxCluster);
      const due = await addCluster();
      const disabled = await addCluster({ enabled: false });
      const unconfirmed = await addCluster({ pinned: null });
      const changed = await addCluster({ certStatus: "changed" });
      const busy = await addCluster();
      await queueRun(busy);
      const unacknowledged = await addCluster({ extraPrivileges: ["VM.PowerMgmt"] });
      const sent: { name: string; data: { runId: string }; options: Record<string, unknown> }[] = [];
      const boss = {
        send: async (name: string, data: { runId: string }, options: Record<string, unknown>) => {
          sent.push({ name, data, options });
          return "job";
        },
      };
      await px.proxmoxTick(boss as never);
      const runs = await conn.db.select().from(schema.proxmoxSyncRun);
      const queuedFor = (cluster: string) =>
        runs.filter((r) => r.clusterId === cluster && r.trigger === "schedule");
      expect(queuedFor(due)).toHaveLength(1);
      for (const skipped of [disabled, unconfirmed, changed, busy, unacknowledged]) {
        expect(queuedFor(skipped), skipped).toHaveLength(0);
      }
      expect(sent.find((s) => s.data.runId === queuedFor(due)[0]?.id)).toMatchObject({
        name: "proxmox.sync",
        options: { retryLimit: 0, singletonKey: due },
      });
      // A connection blocked by a changed certificate is not synced; its certificate is looked at again.
      expect(
        sent
          .filter((x) => x.name === "proxmox.certificate")
          .map((x) => (x.data as unknown as { clusterId: string }).clusterId),
      ).toEqual([changed]);
      // A second tick right away does not queue it again (the first is still waiting).
      await px.proxmoxTick(boss as never);
      expect(
        (await conn.db.select().from(schema.proxmoxSyncRun)).filter(
          (r) => r.clusterId === due && r.trigger === "schedule",
        ),
      ).toHaveLength(1);
    });
  });
});
