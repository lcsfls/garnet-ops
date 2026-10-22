/**
 * Wazuh end to end (ADR 0015): reading the certificates, the pinned and the CA-verified
 * connection, the read-only clients (method and path allow-lists, the JWT login), and the sync,
 * against two local HTTPS servers that replay synthetic answers of Wazuh 4.12 and 5.0 (a manager
 * API and an indexer). The servers have throw-away self-signed certificates made with openssl,
 * like the notification and Proxmox tests. A throw-away PostgreSQL database on the development
 * server and a real vault key stand in for the installation. Skipped without openssl or the
 * development PostgreSQL. Nothing leaves the machine.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import {
  ADAPTERS,
  agentsQuery,
  buildIndexerRequest,
  type IndexerQuery,
  isIndexerRequestAllowed,
  isManagerRequestAllowed,
  WINDOWS,
} from "@garnetops/core/wazuh";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../../../packages/core/test/fixtures/wazuh/", import.meta.url));

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

const MANAGER_HOST = "wazuh-api.example.test";
const INDEXER_HOST = "wazuh-idx.example.test";
const MANAGER_USER = "garnetops-api";
const INDEXER_USER = "garnetops-idx";
/** Made-up passwords. They must never appear in a row, a log line or an error. */
const MANAGER_PASSWORD = "manager password for tests 4711";
const INDEXER_PASSWORD = "indexer password for tests 0815";
const TOKEN = "garnetops-test-jwt-aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc";
const basicOf = (user: string, password: string) =>
  `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;

interface Logged {
  server: "manager" | "indexer";
  method: string;
  path: string;
  query: string;
  authorization: string | undefined;
  host: string | undefined;
  body: string;
}

function selfSigned(dir: string, name: string, host: string): { key: string; cert: string } {
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
      `/CN=${host}/O=Example ${name}`,
      "-addext",
      `subjectAltName=DNS:${host}`,
      "-keyout",
      keyFile,
      "-out",
      certFile,
    ],
    { stdio: "ignore" },
  );
  return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
}

describe.skipIf(!openssl || !adminUrl)("Wazuh: certificates, read-only clients and sync", () => {
  const dbName = `garnetops_wazuh_test_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let managerServer: Server;
  let indexerServer: Server;
  let managerPort = 0;
  let indexerPort = 0;
  const mgrCert = { key: "", cert: "" };
  const idxCert = { key: "", cert: "" };
  let other = { key: "", cert: "" };
  let mgrFingerprint = "";
  let idxFingerprint = "";
  let otherFingerprint = "";
  let wz: typeof import("./wazuh.ts");
  let http: typeof import("./wazuh-http.ts");
  let counter = 0;
  const log: Logged[] = [];
  const connections = { n: 0 };
  const logins = { n: 0 };
  const consoleLines: string[] = [];
  const overrides = new Map<string, (res: ServerResponse) => void>();
  const state = {
    set: "wazuh4" as "wazuh4" | "wazuh5",
    policies: "manager-policies-readonly",
    authinfo: "indexer-authinfo-readonly",
    permissions: "indexer-permissionsinfo-readonly",
    /** Number of Bearer requests to reject with 401 before accepting the token (an expired JWT). */
    expireTokens: 0,
    managerRoot: null as string | null,
    agents: null as string | null,
  };

  const fixture = (name: string) => readFileSync(join(fixtures, state.set, `${name}.json`), "utf8");
  const resolveLocal = async () => "127.0.0.1";
  const deps = () => ({ resolve: resolveLocal, test: { ca: mgrCert.cert }, gapMs: 0 });

  /** The indexer answers the fixed questions by their exact body; any other body is an error. */
  const questions = new Map<string, string>();
  function register(question: IndexerQuery, name: string) {
    questions.set(JSON.stringify(buildIndexerRequest(ADAPTERS.wazuh4, question)), name);
  }

  function managerAnswer(req: Logged): { status: number; body: string } {
    if (req.method === "POST" && req.path === "/security/user/authenticate") {
      if (req.authorization !== basicOf(MANAGER_USER, MANAGER_PASSWORD)) return { status: 401, body: "{}" };
      logins.n++;
      return { status: 200, body: fixture("manager-login") };
    }
    if (req.authorization !== `Bearer ${TOKEN}`) return { status: 401, body: '{"title":"Unauthorized"}' };
    if (state.expireTokens > 0) {
      state.expireTokens--;
      return { status: 401, body: '{"title":"Unauthorized"}' };
    }
    if (req.method !== "GET") return { status: 405, body: "{}" };
    if (req.path === "/") return { status: 200, body: state.managerRoot ?? fixture("manager-root") };
    if (req.path === "/security/users/me/policies") return { status: 200, body: fixture(state.policies) };
    if (req.path === "/agents") {
      const offset = Number(new URLSearchParams(req.query).get("offset") ?? "0");
      if (offset > 0) {
        return {
          status: 200,
          body: JSON.stringify({ data: { affected_items: [], total_affected_items: 7 }, error: 0 }),
        };
      }
      return { status: 200, body: state.agents ?? fixture("manager-agents") };
    }
    return { status: 404, body: '{"title":"Not found"}' };
  }

  function indexerAnswer(req: Logged): { status: number; body: string } {
    if (req.authorization !== basicOf(INDEXER_USER, INDEXER_PASSWORD)) return { status: 401, body: "{}" };
    if (req.method === "GET") {
      if (req.path === "/") return { status: 200, body: fixture("indexer-root") };
      if (req.path === "/_plugins/_security/authinfo") return { status: 200, body: fixture(state.authinfo) };
      if (req.path === "/_plugins/_security/api/permissionsinfo") {
        return { status: 200, body: fixture(state.permissions) };
      }
      return { status: 404, body: "{}" };
    }
    const name = questions.get(
      JSON.stringify({ method: req.method, path: req.path, body: JSON.parse(req.body || "null") }),
    );
    if (!name) return { status: 400, body: '{"error":"unknown question"}' };
    return { status: 200, body: fixture(name) };
  }

  function listen(
    kind: "manager" | "indexer",
    cert: { key: string; cert: string },
    answer: (req: Logged) => { status: number; body: string },
  ): Server {
    const server = createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const [path = "", query = ""] = (req.url ?? "").split("?");
        const entry: Logged = {
          server: kind,
          method: req.method ?? "",
          path,
          query,
          authorization: req.headers.authorization,
          host: req.headers.host,
          body: Buffer.concat(chunks).toString("utf8"),
        };
        log.push(entry);
        const override = overrides.get(`${kind}:${path}`);
        if (override) return override(res);
        const { status, body } = answer(entry);
        res.writeHead(status, { "content-type": "application/json" }).end(body);
      });
    });
    server.on("secureConnection", () => {
      connections.n++;
    });
    return server;
  }

  /** A connection with both passwords sealed in the vault, like the API stores them. */
  async function addConnection(
    options: {
      managerPinned?: string | null;
      indexerPinned?: string | null;
      trust?: "pin" | "ca";
      managerCa?: string;
      indexerCa?: string;
      connection?: Partial<typeof schema.wazuhConnection.$inferInsert>;
      managerStatus?: "pending" | "confirmed" | "changed";
      indexerStatus?: "pending" | "confirmed" | "changed";
      managerPassword?: string;
    } = {},
  ) {
    const n = ++counter;
    const orgId = `org_wz${String(n).padStart(6, "0")}`;
    await conn.db.insert(schema.organization).values({ id: orgId, name: `Wazuh Test ${n}` });
    const id = `wzc_test${String(n).padStart(12, "0")}`;
    await conn.db
      .insert(schema.wazuhConnection)
      .values({ id, organizationId: orgId, name: `Lab ${n}`, ...options.connection });
    const { env } = await import("./env.ts");
    const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
    const endpoints: Record<"manager" | "indexer", string> = { manager: "", indexer: "" };
    for (const kind of ["manager", "indexer"] as const) {
      const purpose = kind === "manager" ? "wazuh-api-password" : "wazuh-indexer-password";
      const secretId = `sec_wz${kind[0]}${String(n).padStart(10, "0")}`;
      const password = kind === "manager" ? (options.managerPassword ?? MANAGER_PASSWORD) : INDEXER_PASSWORD;
      await conn.db.insert(schema.secret).values({
        id: secretId,
        organizationId: orgId,
        purpose,
        sealed: seal(
          password,
          { organizationId: orgId, recordId: secretId, purpose },
          vaultPublicKeyOf(vault),
        ),
        vaultKeyId: vault.id,
      });
      const pinned = kind === "manager" ? options.managerPinned : options.indexerPinned;
      const fingerprint =
        pinned === undefined ? (kind === "manager" ? mgrFingerprint : idxFingerprint) : pinned;
      const status = kind === "manager" ? options.managerStatus : options.indexerStatus;
      const ca = kind === "manager" ? options.managerCa : options.indexerCa;
      const endpointId = `wze_${kind[0]}${String(n).padStart(14, "0")}`;
      await conn.db.insert(schema.wazuhEndpoint).values({
        id: endpointId,
        organizationId: orgId,
        connectionId: id,
        kind,
        apiUrl: `https://${kind === "manager" ? MANAGER_HOST : INDEXER_HOST}:${kind === "manager" ? managerPort : indexerPort}`,
        host: kind === "manager" ? MANAGER_HOST : INDEXER_HOST,
        port: kind === "manager" ? managerPort : indexerPort,
        username: kind === "manager" ? MANAGER_USER : INDEXER_USER,
        secretId,
        trustMode: ca ? "ca" : "pin",
        caPem: ca ?? null,
        ...(status
          ? { certStatus: status, certFingerprint: fingerprint }
          : fingerprint
            ? { certStatus: "confirmed" as const, certFingerprint: fingerprint }
            : {}),
      });
      endpoints[kind] = endpointId;
    }
    return { id, orgId, endpoints };
  }
  async function queueRun(connectionId: string, orgId: string) {
    const id = `wzr_test${String(++counter).padStart(12, "0")}`;
    await conn.db
      .insert(schema.wazuhSyncRun)
      .values({ id, organizationId: orgId, connectionId, state: "queued", trigger: "manual" });
    return id;
  }
  const connection = async (id: string) =>
    (
      await conn.db.select().from(schema.wazuhConnection).where(eq(schema.wazuhConnection.id, id))
    )[0] as typeof schema.wazuhConnection.$inferSelect;
  const endpoint = async (id: string) =>
    (
      await conn.db.select().from(schema.wazuhEndpoint).where(eq(schema.wazuhEndpoint.id, id))
    )[0] as typeof schema.wazuhEndpoint.$inferSelect;
  /** The per-period aggregates of a stored snapshot row. */
  const windowsOf = (row: { data: unknown } | undefined) =>
    ((row?.data ?? { windows: {} }) as { windows: Record<string, { readAt: string }> }).windows;
  const run = async (id: string) =>
    (
      await conn.db.select().from(schema.wazuhSyncRun).where(eq(schema.wazuhSyncRun.id, id))
    )[0] as typeof schema.wazuhSyncRun.$inferSelect;
  const agents = async (connectionId: string) =>
    conn.db.select().from(schema.wazuhAgent).where(eq(schema.wazuhAgent.connectionId, connectionId));
  const sync = async (c: { id: string; orgId: string }, extra: Record<string, unknown> = {}) => {
    const id = await queueRun(c.id, c.orgId);
    log.length = 0;
    await wz.runWazuhSync(id, { ...deps(), ...extra });
    return run(id);
  };

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    workDir = await mkdtemp(join(tmpdir(), "garnetops-wazuh-test-"));
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

    Object.assign(mgrCert, selfSigned(workDir, "M", MANAGER_HOST));
    Object.assign(idxCert, selfSigned(workDir, "I", INDEXER_HOST));
    other = selfSigned(workDir, "O", MANAGER_HOST);
    const { X509Certificate } = await import("node:crypto");
    mgrFingerprint = new X509Certificate(mgrCert.cert).fingerprint256;
    idxFingerprint = new X509Certificate(idxCert.cert).fingerprint256;
    otherFingerprint = new X509Certificate(other.cert).fingerprint256;

    register({ kind: "alertsReadable" }, "indexer-alerts-count");
    register({ kind: "fimLatest" }, "indexer-fim-latest");
    register({ kind: "vulnerabilityStats" }, "indexer-vulnerabilities");
    for (const window of WINDOWS) {
      register({ kind: "alertStats", window }, `indexer-alerts-${window}`);
      register({ kind: "alertStatsPrevious", window }, `indexer-previous-${window}`);
    }

    managerServer = listen("manager", mgrCert, managerAnswer);
    indexerServer = listen("indexer", idxCert, indexerAnswer);
    await new Promise<void>((r) => managerServer.listen(0, "127.0.0.1", r));
    await new Promise<void>((r) => indexerServer.listen(0, "127.0.0.1", r));
    managerPort = (managerServer.address() as AddressInfo).port;
    indexerPort = (indexerServer.address() as AddressInfo).port;

    for (const method of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      });
    }
    wz = await import("./wazuh.ts");
    http = await import("./wazuh-http.ts");
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    for (const s of [managerServer, indexerServer]) {
      s?.close();
      s?.closeAllConnections();
    }
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

  /* ------------------------------------------------------------------------ */

  describe("certificates (trust on first use)", () => {
    it("reads the leaf certificate of each endpoint without sending a request, and only proposes it", async () => {
      const c = await addConnection({ managerPinned: null, indexerPinned: null });
      log.length = 0;
      await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
      await wz.readCertificate(c.endpoints.indexer, { resolve: resolveLocal });
      const m = await endpoint(c.endpoints.manager);
      const i = await endpoint(c.endpoints.indexer);
      expect(m.certStatus).toBe("pending");
      expect(m.certFingerprint).toBeNull();
      expect(m.candidateFingerprint).toBe(mgrFingerprint);
      expect(i.candidateFingerprint).toBe(idxFingerprint);
      expect(m.candidateSubject).toContain(`CN=${MANAGER_HOST}`);
      expect(m.candidateCaTrusted).toBe(false);
      expect(m.lastError).toBeNull();
      // Not one HTTP request: neither password was sent.
      expect(log).toEqual([]);
    });

    it("refuses to sync before an admin has confirmed both fingerprints", async () => {
      const c = await addConnection({ managerPinned: null });
      const result = await sync(c);
      expect(result.state).toBe("failed");
      expect(result.error).toBe(
        "The certificate of the Wazuh manager API is not confirmed yet. Confirm its fingerprint first.",
      );
      expect(log).toEqual([]);
      const d = await addConnection({ indexerPinned: null });
      const second = await sync(d);
      expect(second.error).toBe(
        "The certificate of the Wazuh indexer is not confirmed yet. Confirm its fingerprint first.",
      );
      expect(log).toEqual([]);
    });

    it("a changed manager certificate blocks the sync before any password is sent, and is audited once", async () => {
      const c = await addConnection();
      managerServer.setSecureContext({ key: other.key, cert: other.cert });
      try {
        const first = await sync(c);
        expect(first.state).toBe("failed");
        expect(first.error).toBe(
          "The certificate of the Wazuh manager API changed. An admin must confirm the new fingerprint before the next sync.",
        );
        // Not one request reached either server: the connection was dropped after the handshake.
        expect(log).toEqual([]);
        const m = await endpoint(c.endpoints.manager);
        expect(m.certStatus).toBe("changed");
        expect(m.certFingerprint).toBe(mgrFingerprint);
        expect(m.candidateFingerprint).toBe(otherFingerprint);

        // Asking again does not repeat the audit entry.
        await sync(c);
        await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
        const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
        expect(audit.map((a) => a.action)).toEqual(["xdr.certificate_changed"]);
        expect(audit[0]?.data).toEqual({
          name: (await connection(c.id)).name,
          endpoint: "manager",
          pinned: mgrFingerprint,
          seen: otherFingerprint,
        });

        // The old certificate is back: looking again clears the alarm, and then the sync works.
        managerServer.setSecureContext({ key: mgrCert.key, cert: mgrCert.cert });
        await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
        expect((await endpoint(c.endpoints.manager)).certStatus).toBe("confirmed");
        expect((await sync(c)).state).toBe("succeeded");
      } finally {
        managerServer.setSecureContext({ key: mgrCert.key, cert: mgrCert.cert });
      }
    });

    it("a changed indexer certificate stops the sync before the indexer password is sent", async () => {
      const c = await addConnection();
      indexerServer.setSecureContext({ key: other.key, cert: other.cert });
      try {
        const result = await sync(c);
        expect(result.state).toBe("failed");
        expect(result.error).toContain("certificate of the Wazuh indexer changed");
        expect(log.filter((l) => l.server === "indexer")).toEqual([]);
        expect((await endpoint(c.endpoints.indexer)).certStatus).toBe("changed");
        // Nothing was stored from a half-read system.
        expect(await agents(c.id)).toEqual([]);
      } finally {
        indexerServer.setSecureContext({ key: idxCert.key, cert: idxCert.cert });
      }
    });

    it("pins exactly the leaf: another certificate for the same name is refused", async () => {
      const c = await addConnection({ managerPinned: otherFingerprint });
      const result = await sync(c);
      expect(result.error).toContain("certificate of the Wazuh manager API changed");
      expect(log).toEqual([]);
    });

    it("accepts a certificate authority instead of a pin, and checks chain and host name", async () => {
      // The throw-away certificate is its own authority.
      const c = await addConnection({
        managerCa: mgrCert.cert,
        indexerCa: idxCert.cert,
        managerPinned: null,
        indexerPinned: null,
      });
      await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
      await wz.readCertificate(c.endpoints.indexer, { resolve: resolveLocal });
      expect((await endpoint(c.endpoints.manager)).certStatus).toBe("confirmed");
      expect((await endpoint(c.endpoints.indexer)).certStatus).toBe("confirmed");
      const result = await sync(c);
      expect(result.state).toBe("succeeded");
      expect((await agents(c.id)).length).toBe(7);
    });

    it("rejects an endpoint that does not chain to the uploaded authority", async () => {
      const c = await addConnection({
        managerCa: other.cert,
        indexerCa: idxCert.cert,
        managerPinned: null,
        indexerPinned: null,
      });
      await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
      const m = await endpoint(c.endpoints.manager);
      expect(m.certStatus).toBe("pending");
      expect(m.lastError).toBe(
        "The certificate of the Wazuh manager API is not signed by the certificate authority you uploaded, or does not match its address.",
      );
      const result = await sync(c);
      expect(result.state).toBe("failed");
      expect(log).toEqual([]);
    });

    it("a certificate authority that is right but a host name that is wrong is refused", async () => {
      const c = await addConnection({ managerCa: mgrCert.cert, managerPinned: null });
      await conn.db
        .update(schema.wazuhEndpoint)
        .set({ host: "wrong-name.example.test" })
        .where(eq(schema.wazuhEndpoint.id, c.endpoints.manager));
      await wz.readCertificate(c.endpoints.manager, { resolve: resolveLocal });
      expect((await endpoint(c.endpoints.manager)).lastError).toContain(
        "not signed by the certificate authority",
      );
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("read-only clients", () => {
    const manager = (over: Record<string, unknown> = {}) =>
      new http.ManagerClient({
        endpoint: { host: MANAGER_HOST, port: managerPort, address: "127.0.0.1" },
        trust: { mode: "pin", fingerprint: mgrFingerprint },
        username: MANAGER_USER,
        password: MANAGER_PASSWORD,
        gapMs: 0,
        test: { ca: mgrCert.cert },
        ...over,
      });
    const indexer = (over: Record<string, unknown> = {}) =>
      new http.IndexerClient({
        endpoint: { host: INDEXER_HOST, port: indexerPort, address: "127.0.0.1" },
        trust: { mode: "pin", fingerprint: idxFingerprint },
        username: INDEXER_USER,
        password: INDEXER_PASSWORD,
        gapMs: 0,
        test: { ca: idxCert.cert },
        ...over,
      });
    /** The low-level entry every request goes through (protected: only tests reach it). */
    const send = (client: object, method: string, path: string, input: Record<string, unknown> = {}) =>
      (
        client as unknown as { send: (m: string, p: string, i: Record<string, unknown>) => Promise<unknown> }
      ).send(method, path, { authorization: "Bearer x", ...input });

    it("logs in with POST and basic auth, then reads with the bearer token only", async () => {
      const c = manager();
      try {
        log.length = 0;
        const root = await c.get("/");
        expect(root).toMatchObject({ data: { api_version: "4.12.0" } });
        expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
          "POST /security/user/authenticate",
          "GET /",
        ]);
        expect(log[0]).toMatchObject({
          authorization: basicOf(MANAGER_USER, MANAGER_PASSWORD),
          host: `${MANAGER_HOST}:${managerPort}`,
          body: "",
        });
        expect(log[1]?.authorization).toBe(`Bearer ${TOKEN}`);
        // The password is sent once, with the login; later requests carry only the token.
        await c.get("/security/users/me/policies");
        expect(log.filter((l) => l.authorization?.startsWith("Basic "))).toHaveLength(1);
        expect(logins.n).toBeGreaterThan(0);
      } finally {
        c.close();
      }
    });

    it("asks for a new token once when the manager says it expired, and not again", async () => {
      const c = manager();
      try {
        await c.login();
        const before = logins.n;
        state.expireTokens = 1;
        log.length = 0;
        expect(await c.get("/")).toMatchObject({ data: { api_version: "4.12.0" } });
        expect(logins.n).toBe(before + 1);
        // A manager that keeps saying 401 is an error, not a login loop.
        state.expireTokens = 5;
        log.length = 0;
        await expect(c.get("/")).rejects.toMatchObject({ code: "loginRejected" });
        expect(log.filter((l) => l.method === "POST")).toHaveLength(1);
      } finally {
        state.expireTokens = 0;
        c.close();
      }
    });

    it("a rejected password is a login error, not a token", async () => {
      const c = manager({ password: "not the password at all 1" });
      try {
        await expect(c.login()).rejects.toMatchObject({
          code: "loginRejected",
          message: "The Wazuh manager API rejected the user name or password.",
        });
        await expect(c.get("/")).rejects.toMatchObject({ code: "loginRejected" });
      } finally {
        c.close();
      }
    });

    it("refuses every method but GET (and the login POST) before it connects", async () => {
      const c = manager();
      try {
        const before = connections.n;
        log.length = 0;
        for (const method of ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get", ""]) {
          await expect(send(c, method, "/agents", { query: agentsQuery(0) })).rejects.toThrow(/allow-list/);
        }
        await expect(send(c, "POST", "/agents/001/restart")).rejects.toThrow(/allow-list/);
        await expect(send(c, "POST", "/active-response")).rejects.toThrow(/allow-list/);
        await expect(
          send(c, "POST", "/security/user/authenticate", { query: { raw: "true" } }),
        ).rejects.toThrow(/allow-list/);
        expect(log).toEqual([]);
        expect(connections.n).toBe(before);
        expect(c.requests).toBe(0);
      } finally {
        c.close();
      }
    });

    it("refuses paths outside the allow-list, in particular the key of an agent", async () => {
      const c = manager();
      try {
        for (const path of [
          "/agents/001/key",
          "/agents/001/config/syscheck/syscheck",
          "/security/users",
          "/security/roles",
          "/cluster/nodes",
          "/manager/configuration",
          "/syscollector/001/packages",
          "//agents",
          "/agents/",
        ]) {
          await expect(c.get(path), path).rejects.toThrow(/allow-list/);
        }
        await expect(c.get("/agents", { select: "id,key" })).rejects.toThrow(/allow-list/);
        await expect(c.get("/agents", { ...agentsQuery(0), limit: "100000" })).rejects.toThrow(/allow-list/);
        expect(log.filter((l) => l.server === "manager" && l.method !== "POST")).toEqual([]);
      } finally {
        c.close();
      }
    });

    it("the indexer client sends only fixed questions: GET three paths, POST search and count", async () => {
      const c = indexer();
      try {
        log.length = 0;
        expect(await c.get("/")).toMatchObject({ cluster_name: "wazuh-cluster" });
        await c.get("/_plugins/_security/authinfo");
        await c.run(ADAPTERS.wazuh4, { kind: "alertStats", window: "24h" });
        await c.run(ADAPTERS.wazuh4, { kind: "fimLatest" });
        await c.run(ADAPTERS.wazuh4, { kind: "vulnerabilityStats" });
        expect(log.map((l) => `${l.method} ${l.path}`)).toEqual([
          "GET /",
          "GET /_plugins/_security/authinfo",
          "POST /wazuh-alerts-*/_search",
          "POST /wazuh-alerts-*/_search",
          "POST /wazuh-states-vulnerabilities-*/_search",
        ]);
        for (const entry of log.filter((l) => l.method === "POST")) {
          expect(JSON.parse(entry.body)).toBeTruthy();
          expect(
            questions.has(JSON.stringify({ method: "POST", path: entry.path, body: JSON.parse(entry.body) })),
          ).toBe(true);
          expect(entry.authorization).toBe(basicOf(INDEXER_USER, INDEXER_PASSWORD));
        }
      } finally {
        c.close();
      }
    });

    it("refuses writes, deletes and other indices on the indexer before it connects", async () => {
      const c = indexer();
      try {
        const before = connections.n;
        log.length = 0;
        const refused: [string, string][] = [
          ["PUT", "/wazuh-alerts-*/_doc/1"],
          ["DELETE", "/wazuh-alerts-*"],
          ["DELETE", "/_all"],
          ["POST", "/wazuh-alerts-*/_delete_by_query"],
          ["POST", "/wazuh-alerts-*/_bulk"],
          ["POST", "/_search"],
          ["POST", "/.opendistro_security/_search"],
          ["POST", "/wazuh-states-inventory-*/_search"],
          ["POST", "/_plugins/_security/api/internalusers/admin"],
          ["PATCH", "/_plugins/_security/api/internalusers"],
          ["GET", "/_cat/indices"],
          ["GET", "/_plugins/_security/api/internalusers"],
          ["GET", "/wazuh-alerts-*/_search"],
        ];
        for (const [method, path] of refused) {
          await expect(
            send(c, method, path, { body: { query: { match_all: {} } } }),
            `${method} ${path}`,
          ).rejects.toThrow(/allow-list/);
        }
        expect(log).toEqual([]);
        expect(connections.n).toBe(before);
        expect(c.requests).toBe(0);
      } finally {
        c.close();
      }
    });

    it("does not follow redirects", async () => {
      overrides.set("indexer:/", (res) => void res.writeHead(302, { location: "/_cat/indices" }).end());
      const c = indexer();
      try {
        log.length = 0;
        await expect(c.get("/")).rejects.toMatchObject({ code: "redirected" });
        expect(log.map((l) => l.path)).toEqual(["/"]);
      } finally {
        overrides.delete("indexer:/");
        c.close();
      }
    });

    it.each([
      [429, "rateLimited", "The Wazuh indexer is limiting requests. The next sync tries again."],
      [403, "forbidden", "The user of the Wazuh indexer may not read what GarnetOps needs. Check its role."],
      [401, "loginRejected", "The Wazuh indexer rejected the user name or password."],
      [503, "serverError", "The Wazuh indexer reported an error. Check the server."],
      [404, "notWazuh", "The server did not answer like the Wazuh indexer."],
    ])("maps HTTP %s to a short code without quoting the answer", async (status, code, message) => {
      overrides.set(
        "indexer:/",
        (res) => void res.writeHead(status).end('{"error":"leaked /srv/secret path and stack trace"}'),
      );
      const c = indexer();
      try {
        const error = await c.get("/").catch((e: Error) => e);
        expect(error).toMatchObject({ code, status, message });
        expect((error as Error).message).not.toContain("leaked");
      } finally {
        overrides.delete("indexer:/");
        c.close();
      }
    });

    it("refuses an answer that is too large, declared or streamed, and one that is not JSON", async () => {
      const c = indexer({ maxBytes: 2048 });
      try {
        overrides.set(
          "indexer:/",
          (res) => void res.writeHead(200, { "content-length": "999999" }).end("x".repeat(10)),
        );
        await expect(c.get("/")).rejects.toMatchObject({ code: "responseTooLarge" });
        overrides.set("indexer:/", (res) => {
          res.writeHead(200);
          res.write("x".repeat(1500));
          res.write("x".repeat(1500));
          res.end();
        });
        await expect(c.get("/")).rejects.toMatchObject({ code: "responseTooLarge" });
        overrides.set("indexer:/", (res) => void res.writeHead(200).end("<html>not json</html>"));
        await expect(c.get("/")).rejects.toMatchObject({ code: "invalidResponse" });
      } finally {
        overrides.delete("indexer:/");
        c.close();
      }
    });

    it("gives up on a server that does not answer", async () => {
      overrides.set("indexer:/", () => {
        // never answers
      });
      const c = indexer({ timeoutMs: 300 });
      try {
        await expect(c.get("/")).rejects.toMatchObject({ code: "timeout" });
      } finally {
        overrides.delete("indexer:/");
        c.close();
      }
    });

    it("resolves names itself and refuses loopback, link-local and metadata answers", async () => {
      await expect(http.resolveWazuhAddress("127.0.0.1")).rejects.toMatchObject({ code: "addressRefused" });
      await expect(http.resolveWazuhAddress("169.254.169.254")).rejects.toMatchObject({
        code: "addressRefused",
      });
      await expect(http.resolveWazuhAddress("localhost")).rejects.toMatchObject({ code: "addressRefused" });
      await expect(http.resolveWazuhAddress("192.0.2.10")).resolves.toBe("192.0.2.10");
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("sync", () => {
    it("reads Wazuh 4.12: agents, alert aggregations, file integrity, vulnerabilities and source addresses", async () => {
      const c = await addConnection();
      const result = await sync(c);
      expect(result.error).toBeNull();
      expect(result.state).toBe("succeeded");
      expect(result.agentCount).toBe(7);
      expect(result.warnings).toEqual([]);

      const row = await connection(c.id);
      expect(row).toMatchObject({
        adapter: "wazuh4",
        managerVersion: "4.12.0",
        indexerVersion: "7.10.2",
        lastError: null,
      });
      expect(row.lastSyncAt).not.toBeNull();
      expect(row.extraPrivileges).toEqual([]);

      const list = await agents(c.id);
      const web = list.find((a) => a.agentId === "001");
      expect(web).toMatchObject({
        name: "web-01",
        ip: "192.0.2.11",
        osName: "Ubuntu",
        version: "4.12.0",
        status: "active",
        groups: ["default", "web"],
        isManager: false,
        vulnCritical: 2,
        vulnHigh: 9,
        vulnMedium: 20,
        vulnLow: 4,
      });
      expect(list.find((a) => a.agentId === "000")?.isManager).toBe(true);
      // An agent the indexer does not list has no vulnerability data (null), not zero.
      expect(list.find((a) => a.agentId === "005")).toMatchObject({
        vulnCritical: null,
        status: "never_connected",
      });
      expect(list.find((a) => a.agentId === "004")).toMatchObject({ vulnCritical: 0, vulnLow: 0 });

      const [snapshot] = await conn.db
        .select()
        .from(schema.wazuhSnapshot)
        .where(eq(schema.wazuhSnapshot.connectionId, c.id));
      const data = snapshot?.data as {
        windows: Record<
          string,
          {
            total: number;
            bySeverity: Record<string, number>;
            previous: { total: number } | null;
            fim: number;
          }
        >;
        vulnerabilities: Record<string, number>;
      };
      expect(Object.keys(data.windows).sort()).toEqual(["24h", "30d", "7d"]);
      expect(data.windows["24h"]).toMatchObject({
        total: 2056,
        bySeverity: { critical: 6, high: 30, medium: 120, low: 1900 },
        previous: { total: 1645 },
        fim: 18,
      });
      expect(data.vulnerabilities).toMatchObject({
        critical: 2,
        high: 10,
        medium: 21,
        low: 16,
        agentsAffected: 3,
      });

      const fim = await conn.db
        .select()
        .from(schema.wazuhFimEvent)
        .where(eq(schema.wazuhFimEvent.connectionId, c.id));
      expect(fim).toHaveLength(5);
      expect(fim.map((f) => f.path)).toContain("/etc/passwd");
      expect(fim.find((f) => f.path.includes("evil"))?.path).toBe(
        "/tmp/evil.txt https://evil.example/<img src=x onerror=alert(1)>",
      );

      const sources = await conn.db
        .select()
        .from(schema.wazuhSourceIp)
        .where(eq(schema.wazuhSourceIp.connectionId, c.id));
      expect(sources).toHaveLength(9);
      expect(sources.find((s) => s.window === "24h" && s.ip === "198.51.100.77")).toMatchObject({
        count: 55,
        groups: ["authentication_failed", "authentication_failures"],
        firstSeenAt: new Date("2026-10-21T08:15:00Z"),
        lastSeenAt: new Date("2026-10-22T07:58:00Z"),
        agents: [
          { agentId: "001", name: "web-01", count: 50 },
          { agentId: "002", name: "db-01", count: 5 },
        ],
      });

      // The attack numbers of the overview (ADR 0016), with the previous period and its addresses.
      const attack = await conn.db
        .select()
        .from(schema.wazuhAttackWindow)
        .where(eq(schema.wazuhAttackWindow.connectionId, c.id));
      expect(attack.map((x) => x.window).sort()).toEqual(["24h", "30d", "7d"]);
      expect(attack.find((x) => x.window === "24h")).toMatchObject({
        attackAlerts: 82,
        distinctSources: 5,
        previousAttackAlerts: 60,
        previousDistinctSources: 3,
        previousSources: [
          { ip: "198.51.100.77", count: 40 },
          { ip: "203.0.113.9", count: 15 },
          { ip: "192.0.2.200", count: 5 },
        ],
        agents: [
          { agentId: "001", name: "web-01", count: 76 },
          { agentId: "002", name: "db-01", count: 5 },
        ],
      });
      // The snapshot holds numbers only: no address ever goes into it.
      const [snap] = await conn.db
        .select()
        .from(schema.wazuhSnapshot)
        .where(eq(schema.wazuhSnapshot.connectionId, c.id));
      expect(JSON.stringify(snap?.data)).not.toMatch(/198\.51\.100|203\.0\.113|2001:db8/);
    });

    it("replaces the addresses of a window on every sync and never lets old ones pile up", async () => {
      const c = await addConnection();
      await sync(c);
      await conn.db.insert(schema.wazuhSourceIp).values({
        id: "wzs_stale000000000001",
        organizationId: c.orgId,
        connectionId: c.id,
        window: "24h",
        ip: "192.0.2.99",
        count: 1,
        seenAt: new Date("2026-01-01T00:00:00Z"),
      });
      await sync(c);
      const rows = await conn.db
        .select()
        .from(schema.wazuhSourceIp)
        .where(eq(schema.wazuhSourceIp.connectionId, c.id));
      expect(rows).toHaveLength(9);
      expect(rows.map((r) => r.ip)).not.toContain("192.0.2.99");
    });

    it("reads Wazuh 5.0 with the preview adapter", async () => {
      state.set = "wazuh5";
      try {
        const c = await addConnection();
        const result = await sync(c);
        expect(result.state).toBe("succeeded");
        const row = await connection(c.id);
        expect(row).toMatchObject({ adapter: "wazuh5", managerVersion: "5.0.0", indexerVersion: "2.19.1" });
        expect((await agents(c.id)).find((a) => a.agentId === "001")?.version).toBe("5.0.0");
      } finally {
        state.set = "wazuh4";
      }
    });

    it("sends only allow-listed requests, all fixed questions, and the password only with the login", async () => {
      const c = await addConnection();
      const result = await sync(c);
      expect(result.state).toBe("succeeded");
      const manager = log.filter((l) => l.server === "manager");
      const idx = log.filter((l) => l.server === "indexer");
      expect(manager.map((l) => `${l.method} ${l.path}`)).toEqual([
        "POST /security/user/authenticate",
        "GET /",
        "GET /security/users/me/policies",
        "GET /agents",
      ]);
      for (const entry of manager) {
        const query = Object.fromEntries(new URLSearchParams(entry.query));
        expect(
          isManagerRequestAllowed(entry.method, entry.path, query),
          `${entry.method} ${entry.path}`,
        ).toBe(true);
      }
      expect(manager.filter((l) => l.authorization?.startsWith("Basic "))).toHaveLength(1);
      for (const entry of idx) {
        expect(isIndexerRequestAllowed(entry.method, entry.path, {}), `${entry.method} ${entry.path}`).toBe(
          true,
        );
        if (entry.method === "POST") {
          // Exactly one of the built-in templates, nothing else.
          expect(
            questions.has(JSON.stringify({ method: "POST", path: entry.path, body: JSON.parse(entry.body) })),
          ).toBe(true);
        }
      }
      expect(idx).toHaveLength(2 + 1 + 1 + 6 + 1 + 1);
      expect(result.requestCount).toBe(manager.length + idx.length);
      // No agent key, no configuration, nothing under /agents/{id}.
      expect(log.some((l) => /\/agents\/|\/key|configuration|_bulk|_delete/.test(l.path))).toBe(false);
    });

    it("blocks on a user that can do more than read, before any data is read, until an admin acknowledges", async () => {
      state.policies = "manager-policies-admin";
      try {
        const c = await addConnection();
        const blocked = await sync(c);
        expect(blocked.state).toBe("failed");
        expect(blocked.error).toBe(
          "The Wazuh users can do more than read. An admin must acknowledge this before anything is synced.",
        );
        // Only the login, the version and the permissions were read: no agents, no alerts.
        expect(log.map((l) => `${l.server} ${l.method} ${l.path}`)).toEqual([
          "manager POST /security/user/authenticate",
          "manager GET /",
          "indexer GET /",
          "manager GET /security/users/me/policies",
          "indexer GET /_plugins/_security/authinfo",
          "indexer GET /_plugins/_security/api/permissionsinfo",
        ]);
        expect(await agents(c.id)).toEqual([]);
        const row = await connection(c.id);
        expect(row.extraPrivileges).toEqual(["api:agent:restart", "api:security:create"]);
        const audit = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
        expect(audit.map((a) => a.action)).toEqual(["xdr.privileges_detected"]);

        // A partial acknowledgement is not enough ...
        await conn.db
          .update(schema.wazuhConnection)
          .set({ acknowledgedPrivileges: ["api:agent:restart"] })
          .where(eq(schema.wazuhConnection.id, c.id));
        expect((await sync(c)).state).toBe("failed");
        // ... all of them are. Even then only reads are sent.
        await conn.db
          .update(schema.wazuhConnection)
          .set({ acknowledgedPrivileges: row.extraPrivileges })
          .where(eq(schema.wazuhConnection.id, c.id));
        const ok = await sync(c);
        expect(ok.state).toBe("succeeded");
        expect(
          log.every(
            (l) =>
              l.method === "GET" || l.path.endsWith("/authenticate") || /\/_(search|count)$/.test(l.path),
          ),
        ).toBe(true);
        // The same privileges are not reported twice.
        const again = await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, c.id));
        expect(again).toHaveLength(1);
      } finally {
        state.policies = "manager-policies-readonly";
      }
    });

    it("warns about an indexer user with an administrative role, too", async () => {
      state.authinfo = "indexer-authinfo-admin";
      state.permissions = "indexer-permissionsinfo-admin";
      try {
        const c = await addConnection();
        const blocked = await sync(c);
        expect(blocked.state).toBe("failed");
        expect((await connection(c.id)).extraPrivileges).toEqual([
          "indexer:role:all_access",
          "indexer:security-api",
        ]);
        expect(log.some((l) => l.path === "/agents")).toBe(false);
      } finally {
        state.authinfo = "indexer-authinfo-readonly";
        state.permissions = "indexer-permissionsinfo-readonly";
      }
    });

    it("stops on a Wazuh version GarnetOps does not read", async () => {
      for (const version of ["3.13.6", "6.0.0"]) {
        state.managerRoot = JSON.stringify({ data: { api_version: version }, error: 0 });
        try {
          const c = await addConnection();
          const result = await sync(c);
          expect(result.state).toBe("failed");
          expect(result.error).toBe(`Wazuh ${version} is not supported. GarnetOps reads Wazuh 4.x and 5.x.`);
          expect(log.some((l) => l.path === "/agents")).toBe(false);
        } finally {
          state.managerRoot = null;
        }
      }
    });

    it("does not take something else for Wazuh", async () => {
      state.managerRoot = JSON.stringify({ hello: "world" });
      try {
        const c = await addConnection();
        const result = await sync(c);
        expect(result.error).toBe("The server did not answer like the Wazuh manager API.");
      } finally {
        state.managerRoot = null;
      }
    });

    it("a broken or empty agent list never empties what is stored", async () => {
      const c = await addConnection();
      expect((await sync(c)).state).toBe("succeeded");
      expect(await agents(c.id)).toHaveLength(7);
      for (const broken of [
        '{"data":{"affected_items":[],"total_affected_items":0},"error":0}',
        '{"data":"nope"}',
        "[]",
      ]) {
        state.agents = broken;
        try {
          const result = await sync(c);
          expect(result.state).toBe("failed");
          expect(result.error).toBe("The Wazuh manager API returned an answer in an unexpected format.");
          expect(await agents(c.id)).toHaveLength(7);
        } finally {
          state.agents = null;
        }
      }
    });

    it("forgets agents that are gone, keeps the link of those that stay, and keeps the first-seen time", async () => {
      const c = await addConnection();
      await sync(c);
      const host = `hst_wz${counter}`;
      await conn.db
        .insert(schema.host)
        .values({ id: host, organizationId: c.orgId, name: "linked-server", address: "192.0.2.200" });
      const first = (await agents(c.id)).find((a) => a.agentId === "001");
      await conn.db
        .update(schema.wazuhAgent)
        .set({ hostId: host, linkedAt: new Date() })
        .where(eq(schema.wazuhAgent.id, first?.id as string));
      const fewer = JSON.parse(fixture("manager-agents"));
      fewer.data.affected_items = fewer.data.affected_items.filter((a: { id: string }) => a.id !== "003");
      state.agents = JSON.stringify(fewer);
      try {
        expect((await sync(c)).state).toBe("succeeded");
        const list = await agents(c.id);
        expect(list.find((a) => a.agentId === "003")).toBeUndefined();
        const again = list.find((a) => a.agentId === "001");
        expect(again?.hostId).toBe(host);
        expect(again?.id).toBe(first?.id);
        expect(again?.firstSeenAt.getTime()).toBe(first?.firstSeenAt.getTime());
      } finally {
        state.agents = null;
      }
    });

    it("suggests the server behind an agent but never links it by itself", async () => {
      const c = await addConnection();
      const n = counter;
      const h = schema.host;
      await conn.db.insert(h).values([
        { id: `hst_s1${n}`, organizationId: c.orgId, name: "web-01", address: "192.0.2.11" },
        { id: `hst_s2${n}`, organizationId: c.orgId, name: "db-01.example.lan", address: "192.0.2.77" },
        { id: `hst_s3${n}`, organizationId: c.orgId, name: "dup-01.a.example.lan", address: "192.0.2.78" },
        { id: `hst_s4${n}`, organizationId: c.orgId, name: "dup-01.b.example.lan", address: "192.0.2.79" },
      ]);
      await sync(c);
      const list = await agents(c.id);
      const web = list.find((a) => a.agentId === "001");
      expect(web).toMatchObject({ suggestedHostId: `hst_s1${n}`, suggestionReason: "address", hostId: null });
      expect(list.find((a) => a.agentId === "002")).toMatchObject({
        suggestedHostId: `hst_s2${n}`,
        suggestionReason: "hostname",
        hostId: null,
      });
      expect(list.filter((a) => a.hostId !== null)).toEqual([]);
    });

    it("keeps earlier aggregates when the indexer cannot be read, and says so", async () => {
      const c = await addConnection();
      expect((await sync(c)).state).toBe("succeeded");
      overrides.set("indexer:/wazuh-alerts-*/_count", (res) => void res.writeHead(403).end("{}"));
      overrides.set(
        "indexer:/wazuh-states-vulnerabilities-*/_search",
        (res) => void res.writeHead(404).end("{}"),
      );
      try {
        const result = await sync(c);
        expect(result.state).toBe("succeeded");
        expect(result.warnings.sort()).toEqual(["alertsUnreadable", "vulnerabilitiesUnreadable"]);
        const [snapshot] = await conn.db
          .select()
          .from(schema.wazuhSnapshot)
          .where(eq(schema.wazuhSnapshot.connectionId, c.id));
        expect(Object.keys(windowsOf(snapshot))).toHaveLength(3);
        // Agents are still current, the vulnerability counts of the earlier sync stay.
        expect((await agents(c.id)).find((a) => a.agentId === "001")?.vulnHigh).toBe(9);
        expect(await conn.db.select().from(schema.wazuhFimEvent)).not.toHaveLength(0);
      } finally {
        overrides.delete("indexer:/wazuh-alerts-*/_count");
        overrides.delete("indexer:/wazuh-states-vulnerabilities-*/_search");
      }
    });

    it("stops when the indexer rate-limits, instead of asking again", async () => {
      const c = await addConnection();
      overrides.set("indexer:/wazuh-alerts-*/_count", (res) => void res.writeHead(429).end("{}"));
      try {
        const result = await sync(c);
        expect(result.state).toBe("failed");
        expect(result.error).toBe("The Wazuh indexer is limiting requests. The next sync tries again.");
        expect(log.filter((l) => l.path.endsWith("/_search"))).toEqual([]);
      } finally {
        overrides.delete("indexer:/wazuh-alerts-*/_count");
      }
    });

    it("stops a sync that would send too many requests, and one that takes too long", async () => {
      const c = await addConnection();
      const tooMany = await sync(c, { maxRequests: 5 });
      expect(tooMany.state).toBe("failed");
      expect(tooMany.error).toBe("The sync was stopped because it would send too many requests.");
      const tooSlow = await sync(c, { budgetMs: -1 });
      expect(tooSlow.error).toBe("The sync took longer than 5 minutes and was stopped.");
    });

    it("only the manager's login failing is reported as a rejected password, and nothing is stored", async () => {
      const c = await addConnection({ managerPassword: "a different password 99" });
      const result = await sync(c);
      expect(result.state).toBe("failed");
      expect(result.error).toBe("The Wazuh manager API rejected the user name or password.");
      expect(log.map((l) => `${l.method} ${l.path}`)).toEqual(["POST /security/user/authenticate"]);
      expect(await agents(c.id)).toEqual([]);
    });

    it("never stores the passwords or the token, in rows or in logs", async () => {
      const c = await addConnection();
      const before = consoleLines.length;
      await sync(c);
      // Provoke the error paths as well.
      await sync(c, { maxRequests: 3 });
      await addConnection({ managerPassword: "a different password 77" }).then(sync);
      const dump: string[] = [];
      for (const table of [
        "wazuh_connection",
        "wazuh_endpoint",
        "wazuh_agent",
        "wazuh_snapshot",
        "wazuh_fim_event",
        "wazuh_source_ip",
        "wazuh_attack_window",
        "attack_settings",
        "attack_osint_result",
        "wazuh_sync_run",
        "wazuh_summary",
        "secret",
        "audit_log",
      ]) {
        const res = await conn.pool.query(`select row_to_json(t)::text as row from ${table} t`);
        dump.push(...res.rows.map((r: { row: string }) => r.row));
      }
      const all = dump.join("\n");
      for (const forbidden of [
        MANAGER_PASSWORD,
        INDEXER_PASSWORD,
        TOKEN,
        "a different password",
        Buffer.from(`${MANAGER_USER}:${MANAGER_PASSWORD}`).toString("base64"),
      ]) {
        expect(all, forbidden).not.toContain(forbidden);
      }
      const secrets = await conn.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.organizationId, c.orgId));
      expect(secrets).toHaveLength(2);
      for (const s of secrets) {
        expect(JSON.stringify(s.sealed)).not.toContain(MANAGER_PASSWORD);
        expect(JSON.stringify(s.sealed)).not.toContain(INDEXER_PASSWORD);
      }
      const logs = consoleLines.slice(before).join("\n");
      for (const forbidden of [MANAGER_PASSWORD, INDEXER_PASSWORD, TOKEN])
        expect(logs).not.toContain(forbidden);
      expect(consoleLines.join("\n")).not.toContain(MANAGER_PASSWORD);
    });

    it("stores hostile text as text: names, paths and tactics from alerts are cleaned and bounded", async () => {
      const c = await addConnection();
      await sync(c);
      const fim = await conn.db
        .select()
        .from(schema.wazuhFimEvent)
        .where(eq(schema.wazuhFimEvent.connectionId, c.id));
      expect(
        fim.every((f) => !f.path.includes("\u0000") && !f.path.includes("\u202e") && f.path.length <= 500),
      ).toBe(true);
      const [snapshot] = await conn.db
        .select()
        .from(schema.wazuhSnapshot)
        .where(eq(schema.wazuhSnapshot.connectionId, c.id));
      expect(JSON.stringify(snapshot?.data)).not.toContain("<script>");
    });

    it("keeps a window's older values when only some windows can be read", async () => {
      const c = await addConnection();
      await sync(c);
      const [first] = await conn.db
        .select()
        .from(schema.wazuhSnapshot)
        .where(eq(schema.wazuhSnapshot.connectionId, c.id));
      const firstRead = windowsOf(first)["30d"]?.readAt;
      // Make the 30 day question fail: an answer without aggregations.
      const key = JSON.stringify(buildIndexerRequest(ADAPTERS.wazuh4, { kind: "alertStats", window: "30d" }));
      const original = questions.get(key);
      questions.set(key, "indexer-fim-latest"); // an answer without aggregations
      try {
        const result = await sync(c);
        expect(result.state).toBe("succeeded");
        expect(result.warnings).toContain("alertsUnreadable");
        const [second] = await conn.db
          .select()
          .from(schema.wazuhSnapshot)
          .where(eq(schema.wazuhSnapshot.connectionId, c.id));
        const windows = windowsOf(second);
        expect(windows["30d"]?.readAt).toBe(firstRead);
        expect(windows["24h"]?.readAt).not.toBe(windowsOf(first)["24h"]?.readAt);
      } finally {
        if (original) questions.set(key, original);
      }
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("schedule", () => {
    it("queues a sync for confirmed, acknowledged and idle connections only", async () => {
      await conn.db.delete(schema.wazuhConnection);
      const due = await addConnection();
      const disabled = await addConnection({ connection: { enabled: false } });
      const unconfirmed = await addConnection({ managerPinned: null });
      const changed = await addConnection({ indexerStatus: "changed" });
      const busy = await addConnection();
      await queueRun(busy.id, busy.orgId);
      const unacknowledged = await addConnection({ connection: { extraPrivileges: ["api:agent:restart"] } });
      const sent: { name: string; data: Record<string, string>; options: Record<string, unknown> }[] = [];
      const boss = {
        send: async (name: string, data: Record<string, string>, options: Record<string, unknown>) => {
          sent.push({ name, data, options });
          return "job";
        },
      };
      await wz.wazuhTick(boss as never);
      const runs = await conn.db.select().from(schema.wazuhSyncRun);
      const queuedFor = (c: { id: string }) =>
        runs.filter((r) => r.connectionId === c.id && r.trigger === "schedule");
      expect(queuedFor(due)).toHaveLength(1);
      for (const skipped of [disabled, unconfirmed, changed, busy, unacknowledged]) {
        expect(queuedFor(skipped), skipped.id).toHaveLength(0);
      }
      expect(sent.find((s) => s.data.runId === queuedFor(due)[0]?.id)).toMatchObject({
        name: "xdr.sync",
        options: { retryLimit: 0, singletonKey: due.id },
      });
      // An endpoint whose certificate changed is looked at again.
      expect(sent.filter((x) => x.name === "xdr.certificate").map((x) => x.data.endpointId)).toEqual([
        changed.endpoints.indexer,
      ]);
      // A second tick right away does not queue it again.
      await wz.wazuhTick(boss as never);
      expect(
        (await conn.db.select().from(schema.wazuhSyncRun)).filter(
          (r) => r.connectionId === due.id && r.trigger === "schedule",
        ),
      ).toHaveLength(1);
    });
  });

  it("the endpoint rows hold no credential", async () => {
    const c = await addConnection();
    const rows = await conn.db
      .select()
      .from(schema.wazuhEndpoint)
      .where(and(eq(schema.wazuhEndpoint.connectionId, c.id)));
    for (const row of rows) {
      expect(JSON.stringify(row)).not.toMatch(/password for tests/);
      expect(row.secretId).toMatch(/^sec_/);
    }
  });
});
