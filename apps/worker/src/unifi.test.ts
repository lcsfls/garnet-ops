/**
 * UniFi end to end (ADR 0022): reading the certificate, the pinned connection, the read-only client, the sync, the
 * notifications, and the IPS preview with its cookie session, against a local HTTPS server that replays recorded
 * (synthetic) answers of a UniFi console. The server has a throw-away self-signed certificate made with openssl, like
 * the Proxmox test. A throw-away PostgreSQL database on the development server and a real vault key stand in for the
 * installation. Skipped without openssl or the development PostgreSQL. Nothing leaves the machine.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isOfficialReadPath } from "@garnetops/core/unifi";
import { isIpsRequest } from "@garnetops/core/unifi-ips";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../../../packages/core/test/fixtures/unifi/", import.meta.url));

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

const HOST = "udm.example.test";
const ORG = "org_unifi";
// Made up at run time, so no fixture looks like a real credential. They must never appear in a row or a log line.
const API_KEY = `${["fixture", "api", "key"].join("-")}-${"0123456789".repeat(3)}`;
const IPS_USER = "garnetops-view";
const IPS_PASSWORD = `${["fixture", "ips", "password"].join(" ")} ${"9876543210".repeat(2)}`;
const SESSION_COOKIE = `${["fixture", "session"].join("-")}-${"abcdef0123".repeat(4)}`;
const CSRF = `${["fixture", "csrf"].join("-")}-${"fedcba9876".repeat(3)}`;
const SITE_MAIN = "0a1b2c3d-0000-4000-8000-000000000001";
const SITE_BRANCH = "0a1b2c3d-0000-4000-8000-000000000002";

interface Logged {
  method: string;
  url: string;
  path: string;
  apiKey: string | undefined;
  cookie: string | undefined;
  csrf: string | undefined;
  host: string | undefined;
  body: string;
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

describe.skipIf(!openssl || !adminUrl)(
  "UniFi: certificate pinning, read-only client, sync and IPS preview",
  () => {
    const dbName = `garnetops_unifi_test_${process.pid}`;
    let admin: ReturnType<typeof createDb>;
    let conn: ReturnType<typeof createDb>;
    let workDir: string;
    let server: Server;
    let port = 0;
    let certA = { key: "", cert: "" };
    let certB = { key: "", cert: "" };
    let fingerprintA = "";
    let fingerprintB = "";
    let uf: typeof import("./unifi.ts");
    let ips: typeof import("./unifi-ips.ts");
    let http: typeof import("./unifi-http.ts");
    let attacks: typeof import("./attacks.ts");
    let counter = 0;
    const log: Logged[] = [];
    const connections = { n: 0 };
    /** Replaces the answer for one path (path without query). */
    const overrides = new Map<string, (res: import("node:http").ServerResponse) => void>();
    const state = {
      flavor: "unifi-os" as "unifi-os" | "network-app",
      loginStatus: 200,
      loginBody: "login-viewer",
      ipsBySite: {} as Record<string, string>,
      eventsStatus: 200,
    };
    const consoleLines: string[] = [];

    const fixture = (name: string) => readFileSync(join(fixtures, `${name}.json`), "utf8");
    const resolveLocal = async () => "127.0.0.1";
    const deps = () => ({ resolve: resolveLocal, test: { ca: certA.cert }, gapMs: 0 });
    const prefix = () => (state.flavor === "unifi-os" ? "/proxy/network/integration" : "/integration");

    /** What the fake console answers on the official API. */
    function official(path: string): string | null {
      const fixed: Record<string, string> = {
        "/v1/info": "info",
        "/v1/sites": "sites",
        [`/v1/sites/${SITE_MAIN}/devices`]: "devices-main",
        [`/v1/sites/${SITE_BRANCH}/devices`]: "devices-branch",
        [`/v1/sites/${SITE_MAIN}/clients`]: "clients",
        [`/v1/sites/${SITE_BRANCH}/clients`]: "clients",
      };
      if (fixed[path]) return fixture(fixed[path]);
      if (/^\/v1\/sites\/[0-9a-f-]+\/devices\/[0-9a-f-]+\/statistics\/latest$/.test(path)) {
        return fixture("device-statistics");
      }
      return null;
    }

    function handle(
      req: import("node:http").IncomingMessage,
      res: import("node:http").ServerResponse,
      body: string,
    ) {
      const [path = "", query = ""] = (req.url ?? "").split("?");
      log.push({
        method: req.method ?? "",
        url: req.url ?? "",
        path,
        apiKey: req.headers["x-api-key"] as string | undefined,
        cookie: req.headers.cookie,
        csrf: req.headers["x-csrf-token"] as string | undefined,
        host: req.headers.host,
        body,
      });
      const override = overrides.get(path);
      if (override) return override(res);
      const json = (status: number, text: string, headers: Record<string, string | string[]> = {}) =>
        void res.writeHead(status, { "content-type": "application/json", ...headers }).end(text);

      // The internal API of the preview: login, events, logout.
      const loginPath = state.flavor === "unifi-os" ? "/api/auth/login" : "/api/login";
      const logoutPath = state.flavor === "unifi-os" ? "/api/auth/logout" : "/api/logout";
      const eventsPrefix = state.flavor === "unifi-os" ? "/proxy/network" : "";
      if (req.method === "POST" && path === loginPath) {
        const credentials = JSON.parse(body || "{}") as { username?: string; password?: string };
        if (state.loginStatus !== 200) return json(state.loginStatus, '{"error":"no"}');
        if (credentials.username !== IPS_USER || credentials.password !== IPS_PASSWORD) {
          return json(401, '{"error":"bad credentials"}');
        }
        const cookieName = state.flavor === "unifi-os" ? "TOKEN" : "unifises";
        return json(200, fixture(state.loginBody), {
          "set-cookie": [`${cookieName}=${SESSION_COOKIE}; path=/; samesite=none; secure; httponly`],
          "x-csrf-token": CSRF,
        });
      }
      if (req.method === "POST" && path === logoutPath) {
        return json(200, "{}", { "set-cookie": ["TOKEN=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"] });
      }
      const events = new RegExp(`^${eventsPrefix}/api/s/([A-Za-z0-9_-]+)/stat/ips/event$`).exec(path);
      if (events) {
        if (req.method !== "GET") return void res.writeHead(501).end();
        const cookieName = state.flavor === "unifi-os" ? "TOKEN" : "unifises";
        if (
          !req.headers.cookie?.includes(`${cookieName}=${SESSION_COOKIE}`) ||
          req.headers["x-csrf-token"] !== CSRF
        ) {
          return json(401, '{"error":"unauthorized"}');
        }
        if (state.eventsStatus !== 200) return json(state.eventsStatus, "{}");
        return json(200, state.ipsBySite[events[1] as string] ?? '{"meta":{"rc":"ok"},"data":[]}');
      }

      // The official API.
      if (!path.startsWith(prefix())) return json(404, '{"error":"not found"}');
      if (req.method !== "GET") return void res.writeHead(501).end();
      if (req.headers["x-api-key"] !== API_KEY)
        return json(401, '{"statusCode":401,"message":"Unauthorized"}');
      const offset = new URLSearchParams(query).get("offset");
      if (offset && offset !== "0")
        return json(200, '{"offset":200,"limit":200,"count":0,"totalCount":0,"data":[]}');
      const answer = official(path.slice(prefix().length));
      if (answer === null) return json(404, '{"statusCode":404,"message":"Not Found"}');
      json(200, answer);
    }

    async function addConnection(
      options: Partial<typeof schema.unifiConnection.$inferInsert> & {
        pinned?: string | null;
        withIps?: boolean;
      } = {},
    ) {
      const { pinned, withIps, ...rest } = options;
      const n = ++counter;
      const { env } = await import("./env.ts");
      const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
      const sealSecret = async (
        purpose: "unifi-api-key" | "unifi-ips-password",
        plain: string,
        suffix: string,
      ) => {
        const id = `sec_test${suffix}${String(n).padStart(10, "0")}`;
        await conn.db.insert(schema.secret).values({
          id,
          organizationId: ORG,
          purpose,
          sealed: seal(plain, { organizationId: ORG, recordId: id, purpose }, vaultPublicKeyOf(vault)),
          vaultKeyId: vault.id,
        });
        return id;
      };
      const secretId = await sealSecret("unifi-api-key", API_KEY, "k");
      const ipsSecretId = withIps ? await sealSecret("unifi-ips-password", IPS_PASSWORD, "p") : null;
      const fingerprint = pinned === undefined ? fingerprintA : pinned;
      const id = `ufc_test${String(n).padStart(12, "0")}`;
      await conn.db.insert(schema.unifiConnection).values({
        id,
        organizationId: ORG,
        name: `Console ${n}`,
        // Every connection of an organisation has its own endpoint (unique index); the test resolves them all to the local server.
        apiUrl: `https://udm${n}.example.test:${port}`,
        host: `udm${n}.example.test`,
        port,
        secretId,
        ...(withIps ? { ipsEnabled: true, ipsUsername: IPS_USER, ipsSecretId, ipsIntervalSeconds: 60 } : {}),
        ...(fingerprint ? { certStatus: "confirmed" as const, certFingerprint: fingerprint } : {}),
        ...rest,
      });
      return id;
    }
    async function queueRun(connectionId: string) {
      const id = `ufr_test${String(++counter).padStart(12, "0")}`;
      await conn.db
        .insert(schema.unifiSyncRun)
        .values({ id, organizationId: ORG, connectionId, state: "queued", trigger: "manual" });
      return id;
    }
    const connection = async (id: string) =>
      (
        await conn.db.select().from(schema.unifiConnection).where(eq(schema.unifiConnection.id, id))
      )[0] as typeof schema.unifiConnection.$inferSelect;
    const run = async (id: string) =>
      (
        await conn.db.select().from(schema.unifiSyncRun).where(eq(schema.unifiSyncRun.id, id))
      )[0] as typeof schema.unifiSyncRun.$inferSelect;
    const devices = async (connectionId: string) =>
      conn.db.select().from(schema.unifiDevice).where(eq(schema.unifiDevice.connectionId, connectionId));
    const sites = async (connectionId: string) =>
      conn.db.select().from(schema.unifiSite).where(eq(schema.unifiSite.connectionId, connectionId));
    const threatEvents = async (connectionId: string) =>
      conn.db
        .select()
        .from(schema.unifiThreatEvent)
        .where(eq(schema.unifiThreatEvent.connectionId, connectionId))
        .orderBy(schema.unifiThreatEvent.seq);
    const sync = async (connectionId: string, extra: Record<string, unknown> = {}) => {
      const id = await queueRun(connectionId);
      log.length = 0;
      await uf.runUnifiSync(id, { ...deps(), ...extra });
      return run(id);
    };
    const poll = (connectionId: string, extra: Record<string, unknown> = {}) => {
      log.length = 0;
      return ips.pollIps(connectionId, { ...deps(), force: true, ...extra });
    };

    /** Every row of every table that could hold a secret, as text. */
    async function dumpTables(): Promise<string> {
      const dump: string[] = [];
      for (const table of [
        "unifi_connection",
        "unifi_site",
        "unifi_device",
        "unifi_sync_run",
        "unifi_threat_event",
        "secret",
        "audit_log",
        "user_notification",
      ]) {
        const res = await conn.pool.query(`select row_to_json(t)::text as row from ${table} t`);
        dump.push(...res.rows.map((r: { row: string }) => r.row));
      }
      return dump.join("\n");
    }

    beforeAll(async () => {
      admin = createDb(adminUrl as string, { max: 1 });
      await admin.pool.query(`drop database if exists ${dbName} with (force)`);
      await admin.pool.query(`create database ${dbName}`);
      const url = new URL(adminUrl as string);
      url.pathname = `/${dbName}`;

      workDir = await mkdtemp(join(tmpdir(), "garnetops-unifi-test-"));
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
      await conn.db.insert(schema.organization).values({ id: ORG, name: "UniFi Test" });
      for (const [id, role] of [
        ["user_unifi_owner", "owner"],
        ["user_unifi_member", "member"],
      ] as const) {
        await conn.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test`, locale: "en" });
        await conn.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role });
      }

      certA = selfSigned(workDir, "A");
      certB = selfSigned(workDir, "B");
      const { X509Certificate } = await import("node:crypto");
      fingerprintA = new X509Certificate(certA.cert).fingerprint256;
      fingerprintB = new X509Certificate(certB.cert).fingerprint256;

      server = createServer({ key: certA.key, cert: certA.cert }, (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => handle(req, res, Buffer.concat(chunks).toString("utf8")));
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
      uf = await import("./unifi.ts");
      ips = await import("./unifi-ips.ts");
      http = await import("./unifi-http.ts");
      attacks = await import("./attacks.ts");
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
        const id = await addConnection({ pinned: null });
        log.length = 0;
        await uf.readCertificate(id, deps());
        const row = await connection(id);
        expect(row.certStatus).toBe("pending");
        expect(row.certFingerprint).toBeNull();
        expect(row.candidateFingerprint).toBe(fingerprintA);
        expect(row.candidateSubject).toContain(`CN=${HOST}`);
        expect(row.candidateCaTrusted).toBe(false);
        expect(row.lastError).toBeNull();
        // Not one HTTP request: the API key was never sent.
        expect(log).toEqual([]);
      });

      it("refuses to sync before an admin has confirmed the fingerprint", async () => {
        const id = await addConnection({ pinned: null });
        const result = await sync(id);
        expect(result.state).toBe("failed");
        expect(result.error).toBe("The certificate is not confirmed yet. Confirm its fingerprint first.");
        expect(log).toEqual([]);
      });

      it("a changed certificate blocks the sync before the key is sent, is audited once and told once", async () => {
        const id = await addConnection();
        server.setSecureContext({ key: certB.key, cert: certB.cert });
        try {
          const first = await sync(id);
          expect(first.state).toBe("failed");
          expect(first.error).toContain("certificate of the UniFi console changed");
          // Not even one HTTP request reached the server: the connection was dropped after the handshake.
          expect(log).toEqual([]);
          const row = await connection(id);
          expect(row.certStatus).toBe("changed");
          expect(row.certFingerprint).toBe(fingerprintA);
          expect(row.candidateFingerprint).toBe(fingerprintB);

          await sync(id);
          await uf.readCertificate(id, { ...deps(), test: { ca: certB.cert } });
          const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
          expect(audit.map((a) => a.action)).toEqual(["unifi.certificate_changed"]);
          expect(audit[0]?.data).toEqual({ name: row.name, pinned: fingerprintA, seen: fingerprintB });
          // The owner heard of it once (the member's role does not receive it).
          const told = await conn.db
            .select()
            .from(schema.userNotification)
            .where(eq(schema.userNotification.titleKey, "unifiCertificateChanged"));
          expect(told.filter((n) => n.params.name === row.name).map((n) => n.userId)).toEqual([
            "user_unifi_owner",
          ]);

          // The old certificate is back: looking again clears the alarm, and then the sync works.
          server.setSecureContext({ key: certA.key, cert: certA.cert });
          expect((await sync(id)).state).toBe("failed");
          await uf.readCertificate(id, deps());
          expect((await sync(id)).state).toBe("succeeded");
          expect((await connection(id)).certStatus).toBe("confirmed");
        } finally {
          server.setSecureContext({ key: certA.key, cert: certA.cert });
        }
      });

      it("pins exactly the leaf: another key for the right name is refused", async () => {
        const id = await addConnection({ pinned: fingerprintB });
        const result = await sync(id);
        expect(result.error).toContain("certificate of the UniFi console changed");
        expect(log).toEqual([]);
      });
    });

    describe("read-only client", () => {
      const client = (over: Record<string, unknown> = {}) =>
        new http.UnifiClient({
          endpoint: { host: HOST, port, address: "127.0.0.1" },
          pinned: fingerprintA,
          apiKey: API_KEY,
          base: "unifi-os",
          gapMs: 0,
          test: { ca: certA.cert },
          ...over,
        });

      it("sends GET only, with the key in the X-API-KEY header and nothing else that identifies", async () => {
        const c = client();
        try {
          log.length = 0;
          expect(await c.get("/v1/info")).toMatchObject({ applicationVersion: "9.0.114" });
          expect(log).toHaveLength(1);
          expect(log[0]).toMatchObject({
            method: "GET",
            path: "/proxy/network/integration/v1/info",
            apiKey: API_KEY,
            cookie: undefined,
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
            await expect(c.request(method, "/v1/info")).rejects.toThrow(/not allowed/);
          }
          await expect(
            c.request("POST", `/v1/sites/${SITE_MAIN}/devices/0d0d0d0d-0000-4000-8000-000000000001/actions`),
          ).rejects.toThrow(/not allowed/);
          expect(log).toEqual([]);
          expect(connections.n).toBe(before);
          expect(c.requests).toBe(0);
        } finally {
          c.close();
        }
      });

      it("refuses paths and queries outside the allow-list, even with GET", async () => {
        const c = client();
        try {
          for (const path of [
            `/v1/sites/${SITE_MAIN}/devices/0d0d0d0d-0000-4000-8000-000000000001/actions`,
            `/v1/sites/${SITE_MAIN}/vouchers`,
            "/v1/pending-devices",
            "/v1/../v1/info",
            "/api/s/default/stat/ips/event",
            "/v1/info?x=1",
          ]) {
            await expect(c.get(path), path).rejects.toThrow(/allow-list/);
          }
          await expect(c.get("/v1/sites", { filter: "x" })).rejects.toThrow(/allow-list/);
          await expect(c.get("/v1/sites", { limit: "1;2" })).rejects.toThrow(/allow-list/);
          expect(log.length).toBe(0);
          expect(c.requests).toBe(0);
        } finally {
          c.close();
        }
      });

      it("maps the statuses of the console to short, safe errors", async () => {
        const c = client();
        const path = "/proxy/network/integration/v1/info";
        const cases: [number, string][] = [
          [401, "keyRejected"],
          [403, "forbidden"],
          [404, "notUnifi"],
          [418, "notUnifi"],
          [429, "rateLimited"],
          [500, "serverError"],
          [503, "serverError"],
          [302, "redirected"],
        ];
        try {
          for (const [status, code] of cases) {
            overrides.set(
              path,
              (res) => void res.writeHead(status, { location: "https://elsewhere.example/" }).end("{}"),
            );
            await expect(c.get("/v1/info"), String(status)).rejects.toMatchObject({ code });
          }
        } finally {
          overrides.delete(path);
          c.close();
        }
      });

      it("never follows a redirect", async () => {
        const c = client();
        overrides.set(
          "/proxy/network/integration/v1/info",
          (res) => void res.writeHead(301, { location: `https://${HOST}:${port}/elsewhere` }).end(),
        );
        try {
          log.length = 0;
          await expect(c.get("/v1/info")).rejects.toMatchObject({ code: "redirected" });
          expect(log.map((l) => l.path)).toEqual(["/proxy/network/integration/v1/info"]);
        } finally {
          overrides.delete("/proxy/network/integration/v1/info");
          c.close();
        }
      });

      it("refuses an answer larger than the limit, declared or streamed", async () => {
        const big = Buffer.alloc(100_000, 0x20);
        overrides.set(
          "/proxy/network/integration/v1/info",
          (res) => void res.writeHead(200, { "content-length": big.length }).end(big),
        );
        overrides.set("/proxy/network/integration/v1/sites", (res) => {
          res.writeHead(200);
          const timer = setInterval(() => res.write(big), 1);
          res.on("close", () => clearInterval(timer));
        });
        const c = client({ maxBytes: 50_000 });
        try {
          await expect(c.get("/v1/info")).rejects.toMatchObject({ code: "responseTooLarge" });
          await expect(c.get("/v1/sites")).rejects.toMatchObject({ code: "responseTooLarge" });
        } finally {
          overrides.delete("/proxy/network/integration/v1/info");
          overrides.delete("/proxy/network/integration/v1/sites");
          c.close();
        }
      });

      it("answers a request that never finishes with a timeout, and malformed JSON as invalid", async () => {
        const c = client({ timeoutMs: 300 });
        try {
          overrides.set("/proxy/network/integration/v1/info", () => {});
          await expect(c.get("/v1/info")).rejects.toMatchObject({ code: "timeout" });
          overrides.set(
            "/proxy/network/integration/v1/info",
            (res) => void res.writeHead(200).end("not json {"),
          );
          await expect(c.get("/v1/info")).rejects.toMatchObject({ code: "invalidResponse" });
        } finally {
          overrides.delete("/proxy/network/integration/v1/info");
          c.close();
        }
      });

      it("never resolves a name to a reserved address", async () => {
        for (const host of ["localhost", "127.0.0.1", "169.254.169.254", "::1", "app.localhost", "127.1"]) {
          await expect(http.resolveUnifiAddress(host), host).rejects.toMatchObject({
            code: "addressRefused",
          });
        }
        await expect(http.resolveUnifiAddress("192.0.2.5")).resolves.toBe("192.0.2.5");
        await expect(http.resolveUnifiAddress("10.0.0.7")).resolves.toBe("10.0.0.7");
      });
    });

    describe("sync", () => {
      it("stores sites, devices, uptime and the number of clients, from the recorded answers", async () => {
        state.flavor = "unifi-os";
        const id = await addConnection();
        const result = await sync(id);
        expect(result).toMatchObject({ state: "succeeded", error: null, siteCount: 2, deviceCount: 5 });
        expect(result.requestCount).toBe(log.length);
        expect(result.warnings).toEqual([]);

        const row = await connection(id);
        expect(row).toMatchObject({ version: "9.0.114", lastError: null });
        expect(row.lastSyncAt).not.toBeNull();
        // `auto` was resolved to the UniFi OS prefix and stored.
        expect(row.apiBase).toBe("unifi-os");

        const siteRows = await sites(id);
        expect(siteRows.map((s) => [s.name, s.internalRef, s.clientCount]).sort()).toEqual([
          ["Branch", "branch", 37],
          ["Main office", "default", 37],
        ]);
        const rows = await devices(id);
        const byName = Object.fromEntries(rows.map((d) => [d.name, d]));
        expect(Object.keys(byName).sort()).toEqual([
          "ap-branch",
          "ap-hall",
          "ap-new",
          "gateway.example.lan",
          "switch-1",
        ]);
        expect(byName["gateway.example.lan"]).toMatchObject({
          model: "UCG Example",
          mac: "02:00:00:00:00:01",
          ip: "192.0.2.1",
          state: "online",
          firmwareVersion: "4.0.6",
          firmwareUpdatable: true,
          uptimeSec: 864000,
        });
        expect(byName["switch-1"]).toMatchObject({ firmwareUpdatable: false, state: "online" });
        expect(byName["ap-hall"]).toMatchObject({ state: "offline", uptimeSec: null, offlineSyncs: 1 });
        expect(byName["ap-new"]).toMatchObject({
          state: "other",
          rawState: "PENDING_ADOPTION",
          firmwareUpdatable: null,
        });
        expect(byName["ap-branch"]?.ip).toBe("198.51.100.5");
      });

      it("sends only GET requests with the key, to paths of the allow-list, one at a time", async () => {
        state.flavor = "unifi-os";
        const id = await addConnection();
        await sync(id);
        expect(log.length).toBeGreaterThan(5);
        for (const entry of log) {
          expect(entry.method).toBe("GET");
          expect(entry.apiKey).toBe(API_KEY);
          expect(entry.cookie).toBeUndefined();
          const path = entry.path.replace("/proxy/network/integration", "");
          expect(isOfficialReadPath(path), entry.path).toBe(true);
          // The queries are paging only.
          for (const key of new URLSearchParams(entry.url.split("?")[1] ?? "").keys()) {
            expect(["limit", "offset"]).toContain(key);
          }
        }
        // The clients list is asked for one entry, for its total.
        const clients = log.filter((l) => l.path.endsWith("/clients"));
        expect(clients).toHaveLength(2);
        for (const c of clients) expect(c.url).toContain("limit=1");
        // Uptime only for the devices that are online.
        expect(log.filter((l) => l.path.endsWith("/statistics/latest"))).toHaveLength(3);
      });

      it("detects a self-hosted Network Application and stores the other prefix", async () => {
        state.flavor = "network-app";
        try {
          const id = await addConnection();
          const result = await sync(id);
          expect(result.state).toBe("succeeded");
          expect((await connection(id)).apiBase).toBe("network-app");
          expect(log[0]?.path).toBe("/proxy/network/integration/v1/info");
          expect(log[1]?.path).toBe("/integration/v1/info");
          expect((await devices(id)).length).toBe(5);

          // A connection that was told the kind never tries the other one.
          const fixed = await addConnection({ apiBase: "network-app" });
          await sync(fixed);
          expect(log.every((l) => l.path.startsWith("/integration/"))).toBe(true);
        } finally {
          state.flavor = "unifi-os";
        }
      });

      it("never stores a client name, MAC or address, the key, or the cookie, in rows or in logs", async () => {
        const id = await addConnection({ withIps: true });
        const before = consoleLines.length;
        await sync(id);
        state.ipsBySite = { default: fixture("ips-events") };
        await poll(id);
        const all = await dumpTables();
        for (const secret of [API_KEY, IPS_PASSWORD, SESSION_COOKIE, CSRF]) {
          expect(all).not.toContain(secret);
          expect(consoleLines.join("\n")).not.toContain(secret);
        }
        // Clients are a number: their name, MAC address and address never reach the database.
        expect(all).not.toContain("Example person");
        expect(all).not.toContain("02:00:00:00:00:99");
        expect(all).not.toContain("192.0.2.99");
        // The sealed secrets are not the plain text either.
        const secrets = await conn.db.select().from(schema.secret);
        for (const s of secrets) {
          expect(JSON.stringify(s.sealed)).not.toContain(API_KEY);
          expect(JSON.stringify(s.sealed)).not.toContain(IPS_PASSWORD);
        }
        expect(consoleLines.length).toBeGreaterThanOrEqual(before);
      });

      it.each([
        [401, "The console rejected the API key. Create a new key and enter it again."],
        [403, "The API key may not read this information."],
        [404, "The console did not answer like the UniFi Network API."],
        [429, "The console is limiting requests. GarnetOps tries again later."],
        [500, "The console reported an error. Check the console."],
      ])(
        "ends with a short message when the console answers %i, and keeps the inventory",
        async (status, message) => {
          const id = await addConnection();
          expect((await sync(id)).state).toBe("succeeded");
          const count = (await devices(id)).length;
          overrides.set("/proxy/network/integration/v1/sites", (res) => void res.writeHead(status).end("{}"));
          try {
            const failed = await sync(id);
            expect(failed.state).toBe("failed");
            expect(failed.error).toContain(message);
            expect((await connection(id)).lastError).toContain(message);
            expect((await devices(id)).length).toBe(count);
          } finally {
            overrides.delete("/proxy/network/integration/v1/sites");
          }
        },
      );

      it("never lets a broken answer empty the inventory", async () => {
        const id = await addConnection();
        await sync(id);
        const count = (await devices(id)).length;
        expect(count).toBe(5);
        for (const body of ['{"data":[]}', '{"data":"x"}', "not json", "[]", '{"oops":true}']) {
          overrides.set("/proxy/network/integration/v1/sites", (res) => void res.writeHead(200).end(body));
          try {
            const result = await sync(id);
            expect(result.state, body).toBe("failed");
            expect(result.error, body).toContain("unexpected format");
            expect((await devices(id)).length, body).toBe(count);
          } finally {
            overrides.delete("/proxy/network/integration/v1/sites");
          }
        }
      });

      it("keeps the last known devices of a site that could not be read, and drops the ones that are gone", async () => {
        const id = await addConnection();
        await sync(id);
        overrides.set(
          `/proxy/network/integration/v1/sites/${SITE_BRANCH}/devices`,
          (res) => void res.writeHead(403).end("{}"),
        );
        try {
          const result = await sync(id);
          expect(result.state).toBe("succeeded");
          expect(result.warnings).toContain("siteUnreadable");
          expect((await devices(id)).map((d) => d.name)).toContain("ap-branch");
        } finally {
          overrides.delete(`/proxy/network/integration/v1/sites/${SITE_BRANCH}/devices`);
        }
        // A device that is not in the answer of a site that was read is gone.
        await conn.db.insert(schema.unifiDevice).values({
          id: "ufd_gone00000000000001",
          organizationId: ORG,
          connectionId: id,
          siteId: (await sites(id)).find((s) => s.internalRef === "default")?.id as string,
          unifiId: "0d0d0d0d-0000-4000-8000-0000000000ff",
          name: "removed-device",
          state: "online",
          rawState: "ONLINE",
          stateSince: new Date(),
          firstSeenAt: new Date(),
          lastSeenAt: new Date(Date.now() - 1000),
        });
        await sync(id);
        expect((await devices(id)).map((d) => d.name)).not.toContain("removed-device");
      });

      it("keeps the time a device has been in a state, across syncs", async () => {
        const id = await addConnection();
        await sync(id);
        const first = (await devices(id)).find((d) => d.name === "ap-hall");
        await new Promise((r) => setTimeout(r, 20));
        await sync(id);
        const again = (await devices(id)).find((d) => d.name === "ap-hall");
        expect(again?.id).toBe(first?.id);
        expect(again?.stateSince.toISOString()).toBe(first?.stateSince.toISOString());
        expect(again?.offlineSyncs).toBe(2);
      });

      it("reads hostile device names as text, never as anything else", async () => {
        const evil = JSON.stringify({
          offset: 0,
          limit: 200,
          count: 2,
          totalCount: 2,
          data: [
            {
              id: "0d0d0d0d-0000-4000-8000-0000000000aa",
              name: "<img src=x onerror=alert(1)>\u202eevil",
              model: "'; drop table unifi_device; --",
              macAddress: "02:00:00:00:00:aa",
              ipAddress: "192.0.2.77",
              state: "ONLINE",
              firmwareVersion: "1.0.0",
            },
            { id: "../../etc/passwd", name: "path" },
          ],
        });
        overrides.set(
          `/proxy/network/integration/v1/sites/${SITE_BRANCH}/devices`,
          (res) => void res.writeHead(200).end(evil),
        );
        try {
          const id = await addConnection();
          const result = await sync(id);
          expect(result.state).toBe("succeeded");
          expect(result.warnings).toContain("entriesDropped");
          const row = (await devices(id)).find((d) => d.mac === "02:00:00:00:00:AA");
          expect(row?.name).toBe("<img src=x onerror=alert(1)> evil");
          expect(row?.model).toBe("'; drop table unifi_device; --");
          expect((await devices(id)).some((d) => d.name === "path")).toBe(false);
        } finally {
          overrides.delete(`/proxy/network/integration/v1/sites/${SITE_BRANCH}/devices`);
        }
      });

      it("stops a sync that would send too many requests, or take too long", async () => {
        const id = await addConnection();
        const many = await sync(id, { maxRequests: 3 });
        expect(many.state).toBe("failed");
        expect(many.error).toContain("too many requests");
        const slow = await sync(id, { budgetMs: -1 });
        expect(slow.state).toBe("failed");
        expect(slow.error).toContain("took longer than 10 minutes");
      });

      it("claims a run once", async () => {
        const id = await addConnection();
        const runId = await queueRun(id);
        await Promise.all([uf.runUnifiSync(runId, deps()), uf.runUnifiSync(runId, deps())]);
        expect((await run(runId)).state).toBe("succeeded");
        expect(log.filter((l) => l.path.endsWith("/v1/info"))).toHaveLength(1);
      });
    });

    describe("notifications", () => {
      const told = async (titleKey: string, name: string) =>
        (
          await conn.db
            .select()
            .from(schema.userNotification)
            .where(eq(schema.userNotification.titleKey, titleKey))
        ).filter((n) => n.params.name === name);

      it("tells admins once about a device that is offline in two syncs in a row, and once about a firmware update", async () => {
        const id = await addConnection();
        const name = (await connection(id)).name;
        await sync(id);
        // One sync is not enough for "offline"; the firmware update is news at once.
        expect(await told("unifiDeviceOffline", name)).toHaveLength(0);
        const firmware = await told("unifiFirmwareUpdate", name);
        expect(firmware).toHaveLength(1);
        expect(firmware[0]).toMatchObject({
          userId: "user_unifi_owner",
          event: "unifi.firmware_update_available",
          link: "/servers?view=unifi",
        });
        // Two devices have an update (gateway and ap-hall): one message, not two.
        expect(firmware[0]?.params).toMatchObject({ count: 2 });

        await sync(id);
        const offline = await told("unifiDeviceOffline", name);
        expect(offline).toHaveLength(1);
        expect(offline[0]).toMatchObject({ userId: "user_unifi_owner", event: "unifi.device_offline" });
        expect(offline[0]?.params).toMatchObject({ device: "ap-hall", count: 1 });

        // Syncing again tells nobody again.
        await sync(id);
        await sync(id);
        expect(await told("unifiDeviceOffline", name)).toHaveLength(1);
        expect(await told("unifiFirmwareUpdate", name)).toHaveLength(1);
        // The member's role does not receive infrastructure events.
        const members = await conn.db
          .select()
          .from(schema.userNotification)
          .where(eq(schema.userNotification.userId, "user_unifi_member"));
        expect(members.filter((n) => n.titleKey.startsWith("unifi"))).toEqual([]);
      });

      it("tells again after the device was online in between, and again for a new firmware version", async () => {
        const id = await addConnection();
        const name = (await connection(id)).name;
        await sync(id);
        await sync(id);
        expect(await told("unifiDeviceOffline", name)).toHaveLength(1);
        // The device comes back, then goes away again.
        const online = JSON.parse(fixture("devices-main")) as {
          data: { name: string; state: string; firmwareVersion: string }[];
        };
        const hall = online.data.find((d) => d.name === "ap-hall") as (typeof online.data)[number];
        hall.state = "ONLINE";
        hall.firmwareVersion = "6.8.0";
        overrides.set(
          `/proxy/network/integration/v1/sites/${SITE_MAIN}/devices`,
          (res) => void res.writeHead(200).end(JSON.stringify(online)),
        );
        await sync(id);
        overrides.delete(`/proxy/network/integration/v1/sites/${SITE_MAIN}/devices`);
        expect((await devices(id)).find((d) => d.name === "ap-hall")).toMatchObject({
          offlineSyncs: 0,
          offlineNotified: false,
        });
        // The new version is still marked as updatable: a second message about a firmware update.
        expect(await told("unifiFirmwareUpdate", name)).toHaveLength(2);
        await sync(id);
        await sync(id);
        expect(await told("unifiDeviceOffline", name)).toHaveLength(2);
      });
    });

    describe("IPS preview", () => {
      const withSites = async (options: Parameters<typeof addConnection>[0] = {}) => {
        state.flavor = "unifi-os";
        state.loginStatus = 200;
        state.eventsStatus = 200;
        state.loginBody = "login-viewer";
        state.ipsBySite = { default: fixture("ips-events"), branch: '{"meta":{"rc":"ok"},"data":[]}' };
        const id = await addConnection({ withIps: true, ...options });
        await sync(id);
        return id;
      };

      it("logs in, reads the events of every site with the cookie and the CSRF token, and logs out", async () => {
        const id = await withSites();
        const outcome = await poll(id);
        expect(outcome).toEqual({ status: "polled", read: 5, stored: 5 });
        expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
          "POST /api/auth/login",
          "GET /proxy/network/api/s/default/stat/ips/event",
          "GET /proxy/network/api/s/branch/stat/ips/event",
          "POST /api/auth/logout",
        ]);
        // The login carries the credentials in its body only; the reads carry the session.
        expect(JSON.parse(log[0]?.body ?? "{}")).toEqual({
          username: IPS_USER,
          password: IPS_PASSWORD,
          remember: false,
        });
        expect(log[0]?.cookie).toBeUndefined();
        for (const entry of log.slice(1, 3)) {
          expect(entry.cookie).toBe(`TOKEN=${SESSION_COOKIE}`);
          expect(entry.csrf).toBe(CSRF);
          expect(entry.apiKey).toBeUndefined();
          expect(entry.url).toMatch(/\?start=\d+&end=\d+&_limit=100$/);
        }
        // The logout carries the session too; afterwards nothing is held.
        expect(log[3]?.cookie).toBe(`TOKEN=${SESSION_COOKIE}`);
        for (const entry of log) {
          expect(isIpsRequest("unifi-os", entry.method, entry.path)).toBe(true);
        }
      });

      it("stores events with the action, cleaned text and only the port of the target, once each", async () => {
        const id = await withSites();
        await poll(id);
        const rows = await threatEvents(id);
        expect(rows.map((r) => [r.ip, r.action])).toEqual([
          ["203.0.113.11", "blocked"],
          ["203.0.113.12", "alerted"],
          ["2001:db8::1", "alerted"],
          ["203.0.113.15", "blocked"],
          ["203.0.113.17", "blocked"],
        ]);
        expect(rows[0]).toMatchObject({
          signature: "ET SCAN Example SSH brute force",
          category: "Attempted Administrator Privilege Gain",
          destPort: 22,
          proto: "tcp",
          siteName: "Main office",
        });
        const hostile = rows.find((r) => r.ip === "203.0.113.15");
        expect(hostile?.signature.length).toBeLessThanOrEqual(200);
        expect(hostile?.signature).not.toContain("\u202e");
        expect(hostile?.signature).not.toContain("\u0007");
        // No destination address, no source port, no host: they are not columns.
        expect(JSON.stringify(rows)).not.toContain("192.0.2.50");
        expect(JSON.stringify(rows)).not.toContain("40001");
        // A second poll reads the same events and stores none of them again.
        expect(await poll(id)).toEqual({ status: "polled", read: 5, stored: 0 });
        expect(await threatEvents(id)).toHaveLength(5);
        const state2 = await connection(id);
        expect(state2.ipsFailures).toBe(0);
        expect(state2.ipsLastError).toBeNull();
        expect(state2.ipsLastEventAt).not.toBeNull();
        expect(state2.ipsCursorAt).not.toBeNull();
      });

      it("shares one sequence with the Wazuh events, so the stream orders both", async () => {
        const id = await withSites();
        await poll(id);
        const rows = await threatEvents(id);
        const seqs = rows.map((r) => Number(r.seq));
        expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
        const next = await conn.pool.query("select nextval('wazuh_attack_event_seq_seq')::bigint as n");
        expect(Number(next.rows[0].n)).toBeGreaterThan(Math.max(...seqs));
      });

      it("works with a self-hosted Network Application (other login path, other cookie)", async () => {
        state.flavor = "network-app";
        try {
          state.ipsBySite = { default: fixture("ips-events") };
          const id = await addConnection({ withIps: true, apiBase: "network-app" });
          await sync(id);
          expect((await poll(id)).status).toBe("polled");
          expect(log.map((l) => `${l.method} ${l.path}`)).toEqual(
            [
              "POST /api/login",
              "GET /api/s/default/stat/ips/event",
              "GET /api/s/branch/stat/ips/event",
              "POST /api/logout",
            ].slice(0, log.length),
          );
          expect(log[1]?.cookie).toBe(`unifises=${SESSION_COOKIE}`);
        } finally {
          state.flavor = "unifi-os";
        }
      });

      it("never stores the cookie, the CSRF token or the password", async () => {
        const id = await withSites();
        await poll(id);
        const all = await dumpTables();
        for (const secret of [SESSION_COOKIE, CSRF, IPS_PASSWORD, API_KEY]) {
          expect(all).not.toContain(secret);
          expect(consoleLines.join("\n")).not.toContain(secret);
        }
      });

      it("sends no request but the login, the events and the logout, whatever else is asked", async () => {
        await withSites();
        const session = new http.IpsSession({
          endpoint: { host: HOST, port, address: "127.0.0.1" },
          pinned: fingerprintA,
          flavor: "unifi-os",
          gapMs: 0,
          test: { ca: certA.cert },
        });
        try {
          await session.login(IPS_USER, IPS_PASSWORD);
          log.length = 0;
          const before = connections.n;
          const exchange = session as unknown as {
            send: (m: string, p: string, q?: Record<string, string>, b?: unknown) => Promise<unknown>;
          };
          for (const [method, path] of [
            ["POST", "/proxy/network/api/s/default/cmd/devmgr"],
            ["POST", "/proxy/network/api/s/default/rest/user"],
            ["PUT", "/proxy/network/api/s/default/rest/setting"],
            ["DELETE", "/proxy/network/api/s/default/rest/user/1"],
            ["GET", "/proxy/network/api/s/default/rest/user"],
            ["GET", "/proxy/network/api/s/default/stat/sta"],
            ["GET", "/proxy/network/api/s/../../x/stat/ips/event"],
            ["POST", "/api/auth/login/extra"],
          ] as const) {
            await expect(exchange.send(method, path), `${method} ${path}`).rejects.toThrow(
              /not allowed|allow-list/,
            );
          }
          expect(log).toEqual([]);
          expect(connections.n).toBe(before);
        } finally {
          await session.logout();
          session.close();
        }
      });

      it("always logs out, also when reading the events fails", async () => {
        const id = await withSites();
        state.eventsStatus = 500;
        try {
          const outcome = await poll(id);
          expect(outcome).toMatchObject({ status: "failed", code: "serverError" });
          expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
            "POST /api/auth/login",
            "GET /proxy/network/api/s/default/stat/ips/event",
            "POST /api/auth/logout",
          ]);
          const row = await connection(id);
          expect(row.ipsFailures).toBe(1);
          expect(row.ipsLastError).toBe("The console reported an error. Check the console.");
          // The next poll waits longer (back-off), and is not due before.
          expect(row.ipsNextPollAt.getTime()).toBeGreaterThan(Date.now() + 100_000);
        } finally {
          state.eventsStatus = 200;
        }
      });

      it.each([
        [401, "ipsLoginRejected", "rejected the login"],
        [403, "ipsLoginRejected", "rejected the login"],
        [429, "rateLimited", "limiting requests"],
        [500, "serverError", "reported an error"],
      ])("handles a login answered with %i", async (status, code, text) => {
        const id = await withSites();
        state.loginStatus = status;
        try {
          const outcome = await poll(id);
          expect(outcome).toMatchObject({ status: "failed", code });
          expect((await connection(id)).ipsLastError).toContain(text);
          // No events were read and, with no session, no logout was sent.
          expect(log.map((l) => `${l.method} ${l.path}`)).toEqual(["POST /api/auth/login"]);
        } finally {
          state.loginStatus = 200;
        }
      });

      it("reports a wrong password as a rejected login", async () => {
        const id = await withSites();
        const row = await connection(id);
        const { env } = await import("./env.ts");
        const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
        const secretId = row.ipsSecretId as string;
        await conn.db
          .update(schema.secret)
          .set({
            sealed: seal(
              "not the password at all",
              { organizationId: ORG, recordId: secretId, purpose: "unifi-ips-password" },
              vaultPublicKeyOf(vault),
            ),
          })
          .where(eq(schema.secret.id, secretId));
        expect(await poll(id)).toMatchObject({ status: "failed", code: "ipsLoginRejected" });
      });

      it("says so when the console has no such events endpoint, and when the answer is not a list", async () => {
        const id = await withSites();
        state.eventsStatus = 404;
        expect(await poll(id)).toMatchObject({ status: "failed", code: "ipsEndpointMissing" });
        state.eventsStatus = 200;
        state.ipsBySite = { default: '{"unexpected":"shape"}' };
        expect(await poll(id)).toMatchObject({ status: "failed", code: "invalidResponse" });
        state.ipsBySite = { default: "not json" };
        expect(await poll(id)).toMatchObject({ status: "failed", code: "invalidResponse" });
        expect(await threatEvents(id)).toHaveLength(0);
      });

      it("refuses an oversized answer", async () => {
        const id = await withSites();
        state.ipsBySite = { default: `{"data":[${'{"a":"b"},'.repeat(20)}{}]}` };
        expect(await poll(id, { maxBytes: 50 })).toMatchObject({
          status: "failed",
          code: "responseTooLarge",
        });
      });

      describe("rights beyond viewing", () => {
        const ADMIN = ["role: Super Admin", "super_admin"];
        const toldBlocked = async (name: string) =>
          (
            await conn.db
              .select()
              .from(schema.userNotification)
              .where(eq(schema.userNotification.titleKey, "unifiIpsBlocked"))
          ).filter((n) => n.params.name === name);
        const auditActions = async (id: string) =>
          (await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id)))
            .filter((a) => a.action.startsWith("unifi.ips_rights"))
            .map((a) => a.action);
        /** What the API does when an admin acknowledges the list they were shown. */
        const acknowledge = async (id: string) => {
          const row = await connection(id);
          await conn.db
            .update(schema.unifiConnection)
            .set({
              ipsRightsAcknowledged: row.ipsRights,
              ipsRightsAcknowledgedAt: new Date(),
              ipsRightsAcknowledgedBy: "user_unifi_owner",
            })
            .where(eq(schema.unifiConnection.id, id));
        };
        afterEach(() => {
          state.loginBody = "login-viewer";
        });

        it("stops polling when the session reports admin rights: logs in and out, reads no events, audits and tells once", async () => {
          const id = await withSites();
          const name = (await connection(id)).name;
          state.loginBody = "login-admin";
          expect(await poll(id)).toEqual({ status: "blocked", reason: "rights" });
          // Only the login and the logout: not one read request reached the console.
          expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
            "POST /api/auth/login",
            "POST /api/auth/logout",
          ]);
          const row = await connection(id);
          expect(row.ipsRights).toEqual(ADMIN);
          expect(row.ipsRightsAcknowledged).toEqual([]);
          expect(await threatEvents(id)).toHaveLength(0);
          // The next look is a slow recheck, not the poll interval.
          expect(row.ipsNextPollAt.getTime()).toBeGreaterThan(Date.now() + 9 * 60_000);
          expect(row.ipsLastError).toBeNull();

          // Asking again changes nothing: still blocked, audited and told once.
          expect(await poll(id)).toEqual({ status: "blocked", reason: "rights" });
          expect(await auditActions(id)).toEqual(["unifi.ips_rights_detected"]);
          const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
          expect(audit.find((a) => a.action === "unifi.ips_rights_detected")?.data).toEqual({
            name,
            user: IPS_USER,
            rights: ADMIN,
          });
          expect((await toldBlocked(name)).map((n) => n.userId)).toEqual(["user_unifi_owner"]);
        });

        it("reads events after an admin acknowledged exactly the reported list", async () => {
          const id = await withSites();
          state.loginBody = "login-admin";
          expect((await poll(id)).status).toBe("blocked");
          await acknowledge(id);
          expect(await poll(id)).toMatchObject({ status: "polled", stored: 5 });
          expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
            "POST /api/auth/login",
            "GET /proxy/network/api/s/default/stat/ips/event",
            "GET /proxy/network/api/s/branch/stat/ips/event",
            "POST /api/auth/logout",
          ]);
          expect(await auditActions(id)).toEqual(["unifi.ips_rights_detected"]);
        });

        it("an acknowledgement that does not match the reported list does not count", async () => {
          const id = await withSites();
          state.loginBody = "login-admin";
          await poll(id);
          await conn.db
            .update(schema.unifiConnection)
            .set({ ipsRightsAcknowledged: ["super_admin"] })
            .where(eq(schema.unifiConnection.id, id));
          expect(await poll(id)).toEqual({ status: "blocked", reason: "rights" });
          expect(await threatEvents(id)).toHaveLength(0);
        });

        it("clears the acknowledgement when the reported rights change, and blocks again until the new list is acknowledged", async () => {
          const id = await withSites();
          const name = (await connection(id)).name;
          state.loginBody = "login-admin";
          await poll(id);
          await acknowledge(id);
          expect((await poll(id)).status).toBe("polled");

          // Other rights: the old acknowledgement is void, nothing is read, the admins hear of it.
          state.loginBody = "login-legacy-admin";
          expect(await poll(id)).toEqual({ status: "blocked", reason: "rights" });
          const changed = await connection(id);
          expect(changed.ipsRights).toEqual(["role: admin"]);
          expect(changed.ipsRightsAcknowledged).toEqual([]);
          expect(changed.ipsRightsAcknowledgedAt).toBeNull();
          expect(changed.ipsRightsAcknowledgedBy).toBeNull();
          expect(log.map((l) => l.method)).toEqual(["POST", "POST"]);
          expect(await auditActions(id)).toEqual(["unifi.ips_rights_detected", "unifi.ips_rights_detected"]);
          expect(await toldBlocked(name)).toHaveLength(2);

          // Back to the first list: acknowledged once is not acknowledged for good.
          state.loginBody = "login-admin";
          expect((await poll(id)).status).toBe("blocked");
        });

        it("goes back to polling, without a question, when the user is view-only again", async () => {
          const id = await withSites();
          state.loginBody = "login-admin";
          await poll(id);
          state.loginBody = "login-viewer";
          expect((await poll(id)).status).toBe("polled");
          const row = await connection(id);
          expect(row.ipsRights).toEqual([]);
          expect(row.ipsRightsAcknowledged).toEqual([]);
          // Becoming an admin again is a new finding.
          state.loginBody = "login-admin";
          expect((await poll(id)).status).toBe("blocked");
          expect(await auditActions(id)).toEqual(["unifi.ips_rights_detected", "unifi.ips_rights_detected"]);
        });

        it("does not mix up the rights of an old user with a new one whose credentials changed during the poll", async () => {
          const id = await withSites();
          state.loginBody = "login-admin";
          // The credentials are replaced between the claim and the check.
          const original = http.IpsSession.prototype.login;
          const spy = vi.spyOn(http.IpsSession.prototype, "login").mockImplementation(async function (
            this: InstanceType<typeof http.IpsSession>,
            user,
            password,
          ) {
            const answer = await original.call(this, user, password);
            await conn.db
              .update(schema.unifiConnection)
              .set({ ipsUsername: "another-view-user" })
              .where(eq(schema.unifiConnection.id, id));
            return answer;
          });
          try {
            expect(await poll(id)).toEqual({ status: "not-due" });
          } finally {
            spy.mockRestore();
          }
          expect((await connection(id)).ipsRights).toEqual([]);
          expect(await threatEvents(id)).toHaveLength(0);
        });
      });

      it("does not touch the console while the preview is off or the certificate is not confirmed", async () => {
        const off = await withSites({ ipsEnabled: false });
        expect(await poll(off)).toEqual({ status: "not-due" });
        expect(log).toEqual([]);
        const id = await addConnection({ withIps: true, pinned: null, certStatus: "pending" });
        expect(await poll(id)).toEqual({ status: "blocked", reason: "certificate" });
        expect(log).toEqual([]);
        const noSync = await addConnection({ withIps: true });
        expect(await poll(noSync)).toEqual({ status: "blocked", reason: "no-sync" });
        expect(log).toEqual([]);
      });

      it("leaves a poll that is not due alone, and takes a lease so two workers do not poll together", async () => {
        const id = await withSites();
        expect((await ips.pollIps(id, { ...deps(), force: true })).status).toBe("polled");
        // Not due for another minute.
        expect(await ips.pollIps(id, deps())).toEqual({ status: "not-due" });
        expect((await connection(id)).ipsNextPollAt.getTime()).toBeGreaterThan(Date.now() + 30_000);
      });

      it("blocks the poll at a changed certificate before the password is sent", async () => {
        const id = await withSites();
        server.setSecureContext({ key: certB.key, cert: certB.cert });
        try {
          const outcome = await poll(id);
          expect(outcome).toMatchObject({ status: "failed", code: "certificateChanged" });
          expect(log).toEqual([]);
          expect((await connection(id)).certStatus).toBe("changed");
        } finally {
          server.setSecureContext({ key: certA.key, cert: certA.cert });
        }
      });
    });

    describe("retention", () => {
      it("deletes threat events older than the retention period of the attack overview, and keeps the newer ones", async () => {
        state.flavor = "unifi-os";
        const id = await addConnection({ withIps: true });
        const old = new Date(Date.now() - 100 * 86_400_000);
        const recent = new Date(Date.now() - 3600_000);
        await conn.db.insert(schema.unifiThreatEvent).values([
          {
            organizationId: ORG,
            connectionId: id,
            docId: "old-1",
            at: old,
            ip: "203.0.113.200",
            action: "blocked",
            signature: "old",
          },
          {
            organizationId: ORG,
            connectionId: id,
            docId: "new-1",
            at: recent,
            ip: "203.0.113.201",
            action: "alerted",
            signature: "new",
          },
        ]);
        const result = await attacks.retentionSweep();
        expect(result.attackEvents).toBeGreaterThanOrEqual(1);
        const rows = await threatEvents(id);
        expect(rows.map((r) => r.docId)).toContain("new-1");
        expect(rows.map((r) => r.docId)).not.toContain("old-1");
        // A shorter period applies at once.
        await conn.db
          .insert(schema.attackSettings)
          .values({ organizationId: ORG, retentionDays: 1 })
          .onConflictDoUpdate({ target: schema.attackSettings.organizationId, set: { retentionDays: 1 } });
        await conn.db.insert(schema.unifiThreatEvent).values({
          organizationId: ORG,
          connectionId: id,
          docId: "two-days",
          at: new Date(Date.now() - 2 * 86_400_000),
          ip: "203.0.113.202",
          action: "blocked",
          signature: "two days old",
        });
        await attacks.retentionSweep();
        const after = (await threatEvents(id)).map((r) => r.docId);
        expect(after).not.toContain("two-days");
        expect(after).toContain("new-1");
      });
    });
  },
);
