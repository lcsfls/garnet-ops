/**
 * The live attack feed in the worker (ADR 0021) against a local HTTPS server that plays the Wazuh indexer with
 * synthetic answers: the first poll and the cursor, the page cap and the catch-up, reading the same alert twice,
 * the bounded table, errors and their backoff, the connections that must not be polled, a certificate that changed,
 * hostile text, no log line stored, NOTIFY to the organisation's channel, and the retention sweep. A throw-away
 * PostgreSQL database on the development server and a real vault key stand in for the installation. Skipped without
 * openssl or the development PostgreSQL. Nothing leaves the machine.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { liveChannel } from "@garnetops/core/attack-live";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

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
const openssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;

const INDEXER_HOST = "wazuh-idx.example.test";
const MANAGER_HOST = "wazuh-api.example.test";
const INDEXER_USER = "garnetops-idx";
/** A made-up password. It must never appear in a row, a log line or an error. */
const INDEXER_PASSWORD = "indexer password for live tests 0815";
const basic = `Basic ${Buffer.from(`${INDEXER_USER}:${INDEXER_PASSWORD}`).toString("base64")}`;

interface Logged {
  method: string;
  path: string;
  authorization: string | undefined;
  body: Record<string, unknown> | null;
}

describe.skipIf(!openssl || !adminUrl)("live attack feed: poll, store, notify", () => {
  const dbName = `garnetops_live_test_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let listenerDb: ReturnType<typeof createDb>;
  let listener: {
    query(sql: string): Promise<unknown>;
    on(event: "notification", handler: (m: { channel: string; payload?: string }) => void): unknown;
    release(destroy?: boolean): void;
  };
  let workDir: string;
  let server: Server;
  let port = 0;
  let cert = { key: "", cert: "" };
  let fingerprint = "";
  let live: typeof import("./wazuh-live.ts");
  let attacks: typeof import("./attacks.ts");
  let counter = 0;
  const log: Logged[] = [];
  const consoleLines: string[] = [];
  const notices: { channel: string; payload: string }[] = [];
  /** What the fake indexer answers: a function of the request, so a test can vary it. */
  const answer: { status: number; body: () => unknown } = {
    status: 200,
    body: () => ({ hits: { hits: [] } }),
  };

  const fixture = (name: string) =>
    JSON.parse(readFileSync(join(fixtures, "wazuh4", `${name}.json`), "utf8"));
  const deps = (extra: Record<string, unknown> = {}) => ({
    resolve: async () => "127.0.0.1",
    gapMs: 0,
    ...extra,
  });

  /** A hit as the indexer returns it. */
  const hit = (id: string, at: string, over: Record<string, unknown> = {}) => ({
    _id: id,
    _source: {
      "@timestamp": at,
      rule: { id: "5710", level: 10, description: "sshd: login failed", groups: ["authentication_failed"] },
      agent: { id: "001", name: "web-01" },
      data: { srcip: "198.51.100.77" },
      full_log: `raw log line of ${id} that must never be stored`,
      ...over,
    },
  });
  const hitsBody = (hits: unknown[]) => ({ hits: { total: { value: hits.length }, hits } });

  async function addConnection(
    options: {
      connection?: Partial<typeof schema.wazuhConnection.$inferInsert>;
      indexerPinned?: string;
      indexerStatus?: "pending" | "confirmed" | "changed";
      managerStatus?: "pending" | "confirmed" | "changed";
      adapter?: "wazuh4" | "wazuh5" | null;
      indexerPassword?: string;
      live?: Partial<typeof schema.wazuhLiveState.$inferInsert> | null;
    } = {},
  ) {
    const n = ++counter;
    const orgId = `org_lv${String(n).padStart(6, "0")}`;
    await conn.db.insert(schema.organization).values({ id: orgId, name: `Live Test ${n}` });
    const id = `wzc_live${String(n).padStart(12, "0")}`;
    await conn.db.insert(schema.wazuhConnection).values({
      id,
      organizationId: orgId,
      name: `Lab ${n}`,
      adapter: options.adapter === undefined ? "wazuh4" : options.adapter,
      ...options.connection,
    });
    const { env } = await import("./env.ts");
    const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
    for (const kind of ["manager", "indexer"] as const) {
      const purpose = kind === "manager" ? "wazuh-api-password" : "wazuh-indexer-password";
      const secretId = `sec_lv${kind[0]}${String(n).padStart(10, "0")}`;
      await conn.db.insert(schema.secret).values({
        id: secretId,
        organizationId: orgId,
        purpose,
        sealed: seal(
          kind === "manager"
            ? "manager password, never used by the live feed"
            : (options.indexerPassword ?? INDEXER_PASSWORD),
          { organizationId: orgId, recordId: secretId, purpose },
          vaultPublicKeyOf(vault),
        ),
        vaultKeyId: vault.id,
      });
      await conn.db.insert(schema.wazuhEndpoint).values({
        id: `wze_lv${kind[0]}${String(n).padStart(12, "0")}`,
        organizationId: orgId,
        connectionId: id,
        kind,
        apiUrl: `https://${kind === "manager" ? MANAGER_HOST : INDEXER_HOST}:${kind === "manager" ? 55000 : port}`,
        host: kind === "manager" ? MANAGER_HOST : INDEXER_HOST,
        port: kind === "manager" ? 55000 : port,
        username: kind === "manager" ? "garnetops-api" : INDEXER_USER,
        secretId,
        trustMode: "pin",
        certStatus: (kind === "manager" ? options.managerStatus : options.indexerStatus) ?? "confirmed",
        certFingerprint: kind === "indexer" ? (options.indexerPinned ?? fingerprint) : fingerprint,
      });
    }
    if (options.live !== null) {
      await conn.db
        .insert(schema.wazuhLiveState)
        .values({ connectionId: id, organizationId: orgId, ...options.live });
    }
    return { id, orgId };
  }

  const state = async (id: string) =>
    (
      await conn.db.select().from(schema.wazuhLiveState).where(eq(schema.wazuhLiveState.connectionId, id))
    )[0] as typeof schema.wazuhLiveState.$inferSelect;
  const events = async (id: string) =>
    conn.db
      .select()
      .from(schema.wazuhAttackEvent)
      .where(eq(schema.wazuhAttackEvent.connectionId, id))
      .orderBy(schema.wazuhAttackEvent.seq);
  const seconds = async (id: string) =>
    Number(
      (
        await conn.pool.query(
          "select extract(epoch from (next_poll_at - now())) as s from wazuh_live_state where connection_id = $1",
          [id],
        )
      ).rows[0].s,
    );
  const poll = async (id: string, extra: Record<string, unknown> = {}) => {
    log.length = 0;
    return live.pollConnection(id, deps({ force: true, ...extra }));
  };

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-live-test-"));
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

    const keyPath = join(workDir, "i.key");
    const certPath = join(workDir, "i.pem");
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
        `/CN=${INDEXER_HOST}`,
        "-addext",
        `subjectAltName=DNS:${INDEXER_HOST}`,
        "-keyout",
        keyPath,
        "-out",
        certPath,
      ],
      { stdio: "ignore" },
    );
    cert = { key: readFileSync(keyPath, "utf8"), cert: readFileSync(certPath, "utf8") };
    const { X509Certificate } = await import("node:crypto");
    fingerprint = new X509Certificate(cert.cert).fingerprint256;

    server = createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        log.push({
          method: req.method ?? "",
          path: (req.url ?? "").split("?")[0] ?? "",
          authorization: req.headers.authorization,
          body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        });
        if (req.headers.authorization !== basic) return void res.writeHead(401).end("{}");
        res
          .writeHead(answer.status, { "content-type": "application/json" })
          .end(JSON.stringify(answer.body()));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;

    listenerDb = createDb(url.toString(), { max: 1 });
    listener = (await listenerDb.pool.connect()) as unknown as typeof listener;
    listener.on("notification", (m) => notices.push({ channel: m.channel, payload: m.payload ?? "" }));

    for (const method of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      });
    }
    live = await import("./wazuh-live.ts");
    attacks = await import("./attacks.ts");
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    server?.close();
    server?.closeAllConnections();
    listener?.release(true);
    await listenerDb?.pool.end().catch(() => {});
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

  beforeEach(() => {
    answer.status = 200;
    answer.body = () => hitsBody([]);
    notices.length = 0;
  });

  /* ------------------------------------------------------------------------ */

  it("asks once, read-only, with the fixed template; starts five minutes back; stores what the page shows", async () => {
    const c = await addConnection();
    await listener.query(`LISTEN "${liveChannel(c.orgId)}"`);
    answer.body = () => fixture("indexer-live-alerts");
    const now = new Date("2026-10-21T08:03:00.000Z");
    const outcome = await poll(c.id, { now });
    expect(outcome).toEqual({ status: "polled", read: 4, stored: 4, fullPage: false });

    // One request: POST _search on the alert index, authenticated as the indexer user, nothing else.
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ method: "POST", path: "/wazuh-alerts-*/_search", authorization: basic });
    const body = log[0]?.body as { size: number; _source: string[]; query: { bool: { filter: unknown[] } } };
    expect(body.size).toBe(50);
    expect(body._source).not.toContain("full_log");
    expect(JSON.stringify(body)).toContain("2026-10-21T07:58:00.000Z"); // now - 5 minutes
    expect(JSON.stringify(body.query.bool.filter)).toContain('"rule.level":{"gte":7}');

    const rows = await events(c.id);
    expect(rows.map((r) => r.docId)).toEqual(["live-a1", "live-a2", "live-a3", "live-a5"]);
    expect(rows[0]).toMatchObject({
      organizationId: c.orgId,
      ip: "198.51.100.77",
      ruleId: "5710",
      ruleLevel: 10,
      agentId: "001",
      agentName: "web-01",
      groups: ["invalid_login", "authentication_failed"],
    });
    // No raw log line, port or user name anywhere in the stored rows.
    const dump = JSON.stringify(rows) + JSON.stringify(await state(c.id));
    for (const leaked of ["full_log", "Invalid user", "40022", "dstuser", "wp-login", "raw log"]) {
      expect(dump, leaked).not.toContain(leaked);
    }
    // Hostile text is stored as text, cleaned.
    expect(rows[2]?.description).toContain("<img src=x");
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the point is that none is left
    expect(rows[2]?.description).not.toMatch(/[\u0000-\u0008\u000b-\u001f‪-‮]/);
    expect(rows[3]?.agentName).toBe("<script>alert(1)</script>");

    // The cursor follows the newest alert; the state says when the newest event happened.
    const s = await state(c.id);
    expect(s.cursorAt?.toISOString()).toBe("2026-10-21T08:00:12.000Z");
    expect(s.cursorId).toBe("live-a5");
    expect(s.lastEventAt?.toISOString()).toBe("2026-10-21T08:00:12.000Z");
    expect(s.lastError).toBeNull();
    expect(s.failures).toBe(0);
    expect(await seconds(c.id)).toBeGreaterThan(25); // the 30 second default

    // The browsers of this organisation (and only this organisation's channel) were told, with a number only.
    await listener.query("select 1");
    expect(notices).toHaveLength(1);
    expect(notices[0]?.channel).toBe(liveChannel(c.orgId));
    expect(JSON.parse(notices[0]?.payload ?? "{}")).toEqual({ s: rows.at(-1)?.seq });
    expect(notices[0]?.payload).not.toContain("198.51.100");
  });

  it("continues at the cursor, reads the same alert once, and says nothing when nothing is new", async () => {
    const c = await addConnection();
    await listener.query(`LISTEN "${liveChannel(c.orgId)}"`);
    answer.body = () => hitsBody([hit("same", "2026-10-21T08:00:00.000Z")]);
    await poll(c.id, { now: new Date("2026-10-21T08:01:00.000Z") });
    await listener.query("select 1");
    notices.length = 0;

    // The query now starts at the cursor itself (alerts of the same millisecond are not lost) ...
    answer.body = () =>
      hitsBody([hit("same", "2026-10-21T08:00:00.000Z"), hit("next", "2026-10-21T08:00:30.000Z")]);
    const outcome = await poll(c.id, { now: new Date("2026-10-21T08:01:00.000Z") });
    expect(JSON.stringify(log[0]?.body)).toContain('"gte":"2026-10-21T08:00:00.000Z"');
    // ... and an alert that is read again is stored once.
    expect(outcome).toMatchObject({ status: "polled", read: 2, stored: 1 });
    expect((await events(c.id)).map((r) => r.docId)).toEqual(["same", "next"]);
    expect((await state(c.id)).cursorAt?.toISOString()).toBe("2026-10-21T08:00:30.000Z");
    await listener.query("select 1");
    expect(notices).toHaveLength(1);

    // Nothing new: no notice, the cursor stays.
    notices.length = 0;
    answer.body = () => hitsBody([hit("next", "2026-10-21T08:00:30.000Z")]);
    expect(await poll(c.id, { now: new Date("2026-10-21T08:01:00.000Z") })).toMatchObject({ stored: 0 });
    await listener.query("select 1");
    expect(notices).toEqual([]);
    expect((await state(c.id)).cursorAt?.toISOString()).toBe("2026-10-21T08:00:30.000Z");
  });

  it("never reaches back more than fifteen minutes, however old the cursor is", async () => {
    const c = await addConnection({ live: { cursorAt: new Date("2026-10-20T00:00:00.000Z") } });
    await poll(c.id, { now: new Date("2026-10-21T08:00:00.000Z") });
    expect(JSON.stringify(log[0]?.body)).toContain('"gte":"2026-10-21T07:45:00.000Z"');
  });

  it("uses the rule level an admin chose", async () => {
    const c = await addConnection({ live: { minLevel: 12 } });
    await poll(c.id);
    expect(JSON.stringify(log[0]?.body)).toContain('"rule.level":{"gte":12}');
  });

  it("reads at most one page of 50, even if the indexer sends more, and comes back sooner after a full page", async () => {
    const c = await addConnection({ live: { intervalSeconds: 120 } });
    answer.body = () =>
      hitsBody(
        Array.from({ length: 60 }, (_, i) =>
          hit(`bulk-${String(i).padStart(2, "0")}`, new Date(Date.UTC(2026, 9, 21, 8, 0, i)).toISOString()),
        ),
      );
    const outcome = await poll(c.id);
    expect(outcome).toMatchObject({ status: "polled", read: 50, stored: 50, fullPage: true });
    expect(await events(c.id)).toHaveLength(50);
    expect(log).toHaveLength(1);
    // Catching up: the next poll is a few seconds away, not two minutes.
    expect(await seconds(c.id)).toBeLessThan(10);
  });

  it("keeps the newest 500 events of a connection", async () => {
    const c = await addConnection();
    let sequence = 0;
    for (let page = 0; page < 11; page++) {
      answer.body = () =>
        hitsBody(
          Array.from({ length: 50 }, () => {
            const i = sequence++;
            return hit(
              `keep-${String(i).padStart(4, "0")}`,
              new Date(Date.UTC(2026, 9, 21, 8, 0, 0) + i * 1000).toISOString(),
            );
          }),
        );
      await poll(c.id, { now: new Date("2026-10-21T09:00:00.000Z") });
    }
    const rows = await events(c.id);
    expect(rows).toHaveLength(500);
    expect(rows[0]?.docId).toBe("keep-0050");
    expect(rows.at(-1)?.docId).toBe("keep-0549");
  });

  it("cuts long text, and keeps a hit it cannot use from blocking the feed", async () => {
    const c = await addConnection();
    answer.body = () =>
      hitsBody([
        hit("long", "2026-10-21T08:00:00.000Z", {
          rule: { id: "1", level: 9, description: "x".repeat(5000), groups: ["attack"] },
          agent: { id: "001", name: "n".repeat(500) },
        }),
        hit("bad-ip", "2026-10-21T08:00:05.000Z", { data: { srcip: "not an address" } }),
      ]);
    expect(await poll(c.id)).toMatchObject({ read: 1, stored: 1 });
    const [row] = await events(c.id);
    expect(row?.description).toHaveLength(200);
    expect(row?.agentName).toHaveLength(128);
    // The unusable hit still moved the cursor.
    expect((await state(c.id)).cursorAt?.toISOString()).toBe("2026-10-21T08:00:05.000Z");
  });

  describe("errors", () => {
    it("backs off, doubling, and recovers on the first good answer", async () => {
      const c = await addConnection();
      answer.status = 500;
      expect(await poll(c.id)).toEqual({ status: "failed", code: "serverError" });
      let s = await state(c.id);
      expect(s).toMatchObject({ failures: 1, lastError: "serverError" });
      expect(await seconds(c.id)).toBeGreaterThan(50); // 2 x 30 s
      expect(await seconds(c.id)).toBeLessThan(61);

      expect(await poll(c.id)).toMatchObject({ status: "failed" });
      s = await state(c.id);
      expect(s.failures).toBe(2);
      expect(await seconds(c.id)).toBeGreaterThan(110); // 4 x 30 s

      for (let i = 0; i < 6; i++) await poll(c.id);
      expect(await seconds(c.id)).toBeLessThanOrEqual(600); // capped at ten minutes
      expect(await seconds(c.id)).toBeGreaterThan(590);

      answer.status = 200;
      answer.body = () => hitsBody([hit("back", "2026-10-21T08:00:00.000Z")]);
      expect(await poll(c.id)).toMatchObject({ status: "polled", stored: 1 });
      s = await state(c.id);
      expect(s).toMatchObject({ failures: 0, lastError: null });
      expect(await seconds(c.id)).toBeLessThanOrEqual(30);
    });

    it("treats a rejected password, a rate limit and an answer that is not a result list as errors with a short code", async () => {
      const c = await addConnection();
      answer.status = 429;
      expect(await poll(c.id)).toEqual({ status: "failed", code: "rateLimited" });
      answer.status = 200;
      answer.body = () => ({ unexpected: "shape" });
      expect(await poll(c.id)).toEqual({ status: "failed", code: "invalidResponse" });
    });

    it("reports a rejected password as such and backs off", async () => {
      const c = await addConnection({ indexerPassword: "another password that the indexer does not know" });
      expect(await poll(c.id)).toEqual({ status: "failed", code: "loginRejected" });
      expect(await seconds(c.id)).toBeGreaterThan(50);
    });

    it("never writes a password, an alert text or a message of an error into a log line or the state", async () => {
      const c = await addConnection();
      answer.status = 500;
      await poll(c.id);
      answer.status = 200;
      answer.body = () => fixture("indexer-live-alerts");
      await poll(c.id);
      const everything = consoleLines.join("\n") + JSON.stringify(await state(c.id));
      expect(everything).not.toContain(INDEXER_PASSWORD);
      expect(everything).not.toContain("pwned");
      expect(everything).not.toContain("198.51.100.77");
    });

    it("blocks a certificate that is not the pinned one before the password is sent, and flags the endpoint", async () => {
      const other = `${"AA:".repeat(31)}AA`;
      const c = await addConnection({ indexerPinned: other });
      expect(await poll(c.id)).toEqual({ status: "failed", code: "certificateChanged" });
      // Not one request reached the server: the password was never sent.
      expect(log).toEqual([]);
      const indexer = (
        await conn.db.select().from(schema.wazuhEndpoint).where(eq(schema.wazuhEndpoint.connectionId, c.id))
      ).find((e) => e.kind === "indexer");
      expect(indexer?.certStatus).toBe("changed");
      expect(indexer?.candidateFingerprint).toBe(fingerprint);
      // The next tick sees a blocked connection and sends nothing either.
      expect(await poll(c.id)).toEqual({ status: "blocked", reason: "certificate" });
      expect(log).toEqual([]);
    });
  });

  describe("connections that are not polled", () => {
    it.each([
      ["a connection that is switched off", { connection: { enabled: false } }, "disabled"],
      ["a feed an admin switched off", { live: { enabled: false } }, "off"],
      ["an indexer certificate nobody confirmed", { indexerStatus: "pending" as const }, "certificate"],
      ["a manager certificate that changed", { managerStatus: "changed" as const }, "certificate"],
      ["a connection that was never synced", { adapter: null }, "no-sync"],
      [
        "extra privileges nobody acknowledged",
        { connection: { extraPrivileges: ["agent:restart"], acknowledgedPrivileges: [] } },
        "privileges",
      ],
    ])("%s", async (_name, options, reason) => {
      const c = await addConnection(options as never);
      expect(await poll(c.id)).toEqual({ status: "blocked", reason });
      expect(log).toEqual([]);
      expect(await events(c.id)).toEqual([]);
      // It is looked at again later, not in a tight loop.
      expect(await seconds(c.id)).toBeGreaterThan(30);
    });

    it("polls once the extra privileges are acknowledged", async () => {
      const c = await addConnection({
        connection: { extraPrivileges: ["agent:restart"], acknowledgedPrivileges: ["agent:restart"] },
      });
      expect(await poll(c.id)).toMatchObject({ status: "polled" });
    });
  });

  describe("the tick", () => {
    it("creates the state of a connection that has none, polls what is due and leaves the rest", async () => {
      const fresh = await addConnection({ live: null });
      const later = await addConnection({ live: {} });
      await conn.pool.query(
        "update wazuh_live_state set next_poll_at = now() + interval '1 hour' where connection_id = $1",
        [later.id],
      );
      answer.body = () => hitsBody([hit("tick", "2026-10-21T08:00:00.000Z")]);
      log.length = 0;
      await conn.pool.query(
        "update wazuh_live_state set next_poll_at = now() + interval '1 hour' where connection_id not in ($1, $2)",
        [fresh.id, later.id],
      );
      const polled = await live.liveTick(deps());
      expect(polled).toBe(1);
      expect(await events(fresh.id)).toHaveLength(1);
      expect(await events(later.id)).toHaveLength(0);
      expect((await state(fresh.id)).enabled).toBe(true);
      expect((await state(fresh.id)).intervalSeconds).toBe(30);
      expect((await state(fresh.id)).minLevel).toBe(7);
    });

    it("does not poll the same connection twice at once: the lease is taken atomically", async () => {
      const c = await addConnection({ live: {} });
      await conn.pool.query("update wazuh_live_state set next_poll_at = now() where connection_id = $1", [
        c.id,
      ]);
      log.length = 0;
      const results = await Promise.all([
        live.pollConnection(c.id, deps()),
        live.pollConnection(c.id, deps()),
        live.pollConnection(c.id, deps()),
      ]);
      expect(results.filter((r) => r.status !== "not-due")).toHaveLength(1);
      expect(log).toHaveLength(1);
    });
  });

  it("keeps the database constraints on interval and level", async () => {
    const c = await addConnection();
    await expect(
      conn.pool.query("update wazuh_live_state set interval_seconds = 5 where connection_id = $1", [c.id]),
    ).rejects.toThrow();
    await expect(
      conn.pool.query("update wazuh_live_state set min_level = 16 where connection_id = $1", [c.id]),
    ).rejects.toThrow();
  });

  it("is deleted with the connection and swept after the retention period of the attack overview", async () => {
    const c = await addConnection();
    const day = 24 * 3600 * 1000;
    const now = new Date("2026-10-21T08:00:00.000Z");
    await conn.db.insert(schema.attackSettings).values({ organizationId: c.orgId, retentionDays: 7 });
    await conn.db.insert(schema.wazuhAttackEvent).values(
      [
        ["old", new Date(now.getTime() - 10 * day)],
        ["new", new Date(now.getTime() - 1 * day)],
      ].map(([docId, at]) => ({
        organizationId: c.orgId,
        connectionId: c.id,
        docId: docId as string,
        at: at as Date,
        ip: "198.51.100.1",
        ruleId: "1",
        ruleLevel: 8,
        description: "x",
        agentId: "001",
        agentName: "web-01",
      })),
    );
    const swept = await attacks.retentionSweep(now);
    expect(swept.attackEvents).toBeGreaterThanOrEqual(1);
    expect((await events(c.id)).map((r) => r.docId)).toEqual(["new"]);
    await conn.db.delete(schema.wazuhConnection).where(eq(schema.wazuhConnection.id, c.id));
    expect(await events(c.id)).toEqual([]);
    expect(
      await conn.db.select().from(schema.wazuhLiveState).where(eq(schema.wazuhLiveState.connectionId, c.id)),
    ).toEqual([]);
  });
});
