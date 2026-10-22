/**
 * The attack overview in the worker (ADR 0016): the opt-in monthly GeoIP download, the optional
 * OSINT lookups and the retention sweep, against local HTTPS servers with throw-away self-signed
 * certificates (made with openssl, like the notification, Proxmox and Wazuh tests) that stand in
 * for download.db-ip.com and api.abuseipdb.com. A throw-away PostgreSQL database on the development
 * server and a real vault key stand in for the installation. Skipped without openssl or the
 * development PostgreSQL. Nothing leaves the machine; no real data is used.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync, constants as zlibConstants } from "node:zlib";
import { monthOf, previousMonth } from "@garnetops/core/geoip";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));

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

const API_KEY = ["abcdef0123456789", "abcdef0123456789abcdef01"].join("");
const NOW = new Date("2026-10-22T10:00:00Z");

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
      `/CN=${host}`,
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

interface Logged {
  host: "dbip" | "abuse";
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

describe.skipIf(!openssl || !adminUrl)("attack overview worker", () => {
  const dbName = `garnetops_attacks_test_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let dbipServer: Server;
  let abuseServer: Server;
  let dbipPort = 0;
  let abusePort = 0;
  const dbipCert = { key: "", cert: "" };
  const abuseCert = { key: "", cert: "" };
  let attacks: typeof import("./attacks.ts");
  let outbound: typeof import("./outbound.ts");
  let counter = 0;
  const log: Logged[] = [];
  const consoleLines: string[] = [];

  /** What each fake server answers; tests replace entries. */
  const dbip = {
    handler: (
      _url: string,
    ): { status: number; headers?: Record<string, string>; body?: Buffer | string } => ({
      status: 404,
    }),
  };
  const abuse = {
    handler: (
      _ip: string,
      _key: string | undefined,
    ): { status: number; headers?: Record<string, string>; body?: string } => ({
      status: 500,
    }),
  };

  const toLocal =
    (port: number) =>
    (
      _host: string,
      options: object,
      callback: (e: null, a: string | { address: string; family: number }[], f?: number) => void,
    ) => {
      if ((options as { all?: boolean }).all) callback(null, [{ address: "127.0.0.1", family: 4 }]);
      else callback(null, "127.0.0.1", 4);
      void port;
    };
  const dbipTest = () => ({ lookup: toLocal(dbipPort) as never, ca: dbipCert.cert, port: dbipPort });
  const abuseTest = () => ({ lookup: toLocal(abusePort) as never, ca: abuseCert.cert, port: abusePort });

  const countryCsv = (cc: string) =>
    gzipSync(Buffer.from(`198.51.100.0,198.51.100.255,${cc}\n203.0.113.0,203.0.113.255,FR\n`));
  /** Tens of thousands of valid, sorted ranges: small compressed, large inflated. */
  const bomb = () => {
    const v4 = (n: number) => [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join(".");
    const lines = Array.from(
      { length: 60_000 },
      (_, i) => `${v4(16_777_216 + i * 256)},${v4(16_777_216 + i * 256 + 255)},DE`,
    );
    return gzipSync(Buffer.from(`${lines.join("\n")}\n`), { level: zlibConstants.Z_BEST_COMPRESSION });
  };
  const asnCsv = gzipSync(Buffer.from('198.51.100.0,198.51.100.255,64500,"Example Hosting, Inc."\n'));

  async function newOrg() {
    const n = ++counter;
    const orgId = `org_atk${String(n).padStart(6, "0")}`;
    await conn.db.insert(schema.organization).values({ id: orgId, name: `Attacks Test ${n}` });
    const connectionId = `wzc_atk${String(n).padStart(12, "0")}`;
    await conn.db
      .insert(schema.wazuhConnection)
      .values({ id: connectionId, organizationId: orgId, name: `Lab ${n}` });
    return { orgId, connectionId };
  }
  async function addSources(
    o: { orgId: string; connectionId: string },
    rows: { ip: string; count: number; window?: "24h" | "7d" | "30d" }[],
  ) {
    await conn.db.insert(schema.wazuhSourceIp).values(
      rows.map((r) => ({
        id: `wzs_atk${String(++counter).padStart(12, "0")}`,
        organizationId: o.orgId,
        connectionId: o.connectionId,
        window: r.window ?? "24h",
        ip: r.ip,
        count: r.count,
        seenAt: new Date(),
      })),
    );
  }
  async function enableOsint(
    o: { orgId: string },
    over: Partial<typeof schema.attackSettings.$inferInsert> = {},
    key: string | null = API_KEY,
  ) {
    const { env } = await import("./env.ts");
    const vault = loadVaultPrivateKey(readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"));
    let secretId: string | null = null;
    if (key) {
      secretId = `sec_osint${String(++counter).padStart(10, "0")}`;
      await conn.db.insert(schema.secret).values({
        id: secretId,
        organizationId: o.orgId,
        purpose: "osint-api-key",
        sealed: seal(
          key,
          { organizationId: o.orgId, recordId: secretId, purpose: "osint-api-key" },
          vaultPublicKeyOf(vault),
        ),
        vaultKeyId: vault.id,
      });
    }
    await conn.db.insert(schema.attackSettings).values({
      organizationId: o.orgId,
      osintEnabled: true,
      osintProvider: "abuseipdb",
      osintSecretId: secretId,
      osintAcknowledgedAt: new Date(),
      ...over,
    });
  }
  const settingsOf = async (orgId: string) =>
    (
      await conn.db
        .select()
        .from(schema.attackSettings)
        .where(eq(schema.attackSettings.organizationId, orgId))
    )[0] as typeof schema.attackSettings.$inferSelect;
  const results = async (orgId: string) =>
    conn.db.select().from(schema.attackOsintResult).where(eq(schema.attackOsintResult.organizationId, orgId));
  const datasets = async () => conn.db.select().from(schema.geoipDataset);
  const loaded = async () => (await datasets()).filter((d) => d.state === "active");
  const abuseAnswer = (ip: string, score = 80) =>
    JSON.stringify({
      data: {
        ipAddress: ip,
        abuseConfidenceScore: score,
        totalReports: 12,
        lastReportedAt: "2026-10-22T06:00:00+00:00",
        isp: "<b>x</b>",
      },
    });

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-attacks-test-"));
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

    Object.assign(dbipCert, selfSigned(workDir, "dbip", "download.db-ip.com"));
    Object.assign(abuseCert, selfSigned(workDir, "abuse", "api.abuseipdb.com"));
    dbipServer = createServer({ key: dbipCert.key, cert: dbipCert.cert }, (req, res) => {
      log.push({ host: "dbip", method: req.method ?? "", url: req.url ?? "", headers: req.headers });
      const a = dbip.handler(req.url ?? "");
      res.writeHead(a.status, a.headers ?? {}).end(a.body);
    });
    abuseServer = createServer({ key: abuseCert.key, cert: abuseCert.cert }, (req, res) => {
      log.push({ host: "abuse", method: req.method ?? "", url: req.url ?? "", headers: req.headers });
      const ip = new URL(req.url ?? "/", "https://x").searchParams.get("ipAddress") ?? "";
      const a = abuse.handler(ip, req.headers.key as string | undefined);
      res.writeHead(a.status, { "content-type": "application/json", ...(a.headers ?? {}) }).end(a.body);
    });
    await new Promise<void>((r) => dbipServer.listen(0, "127.0.0.1", r));
    await new Promise<void>((r) => abuseServer.listen(0, "127.0.0.1", r));
    dbipPort = (dbipServer.address() as AddressInfo).port;
    abusePort = (abuseServer.address() as AddressInfo).port;

    for (const method of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      });
    }
    attacks = await import("./attacks.ts");
    outbound = await import("./outbound.ts");
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    for (const s of [dbipServer, abuseServer]) {
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

  describe("GeoIP download", () => {
    const month = monthOf(NOW);
    const last = previousMonth(month);
    const reset = async () => {
      log.length = 0;
      await conn.db.delete(schema.geoipDataset);
      await conn.db.delete(schema.attackSettings);
      await conn.db.delete(schema.auditLog);
    };
    const settingsRow = async (
      orgId: string,
      over: Partial<typeof schema.attackSettings.$inferInsert> = {},
    ) => {
      await conn.db
        .insert(schema.attackSettings)
        .values({ organizationId: orgId, geoipDownloadEnabled: true, ...over });
      return settingsOf(orgId);
    };
    const serveBoth = () => {
      dbip.handler = (url) =>
        url.includes("country")
          ? { status: 200, body: countryCsv("DE") }
          : url.includes("asn")
            ? { status: 200, body: asnCsv }
            : { status: 404 };
    };

    it("sends nothing at all while the download is off, however often the tick runs", async () => {
      await reset();
      const o = await newOrg();
      await conn.db
        .insert(schema.attackSettings)
        .values({ organizationId: o.orgId, geoipDownloadEnabled: false });
      serveBoth();
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect(log).toEqual([]);
      expect(await datasets()).toEqual([]);
      // Not even a setting row (the default state) makes a request.
      await conn.db.delete(schema.attackSettings);
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect(log).toEqual([]);
    });

    it("downloads this month's files from the one fixed URL, loads them and records everything", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      serveBoth();
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect(log.map((l) => `${l.method} ${l.url}`)).toEqual([
        `GET /free/dbip-country-lite-${month}.csv.gz`,
        `GET /free/dbip-asn-lite-${month}.csv.gz`,
      ]);
      // Nothing but a plain GET: no cookie, no credentials, no custom headers.
      for (const l of log) {
        expect(l.headers.host).toMatch(/^download\.db-ip\.com:\d+$/);
        expect(l.headers.cookie).toBeUndefined();
        expect(l.headers.authorization).toBeUndefined();
      }
      const stored = await datasets();
      expect(stored.map((d) => [d.kind, d.state, d.source, d.datasetMonth, d.rowCount]).sort()).toEqual([
        ["asn", "active", "download", month, 1],
        ["country", "active", "download", month, 2],
      ]);
      expect(stored.every((d) => /^[0-9a-f]{64}$/.test(d.sha256 ?? ""))).toBe(true);
      const s = await settingsOf(o.orgId);
      expect(s.geoipDownloadLastError).toBeNull();
      expect(s.geoipDownloadLastAttemptAt).not.toBeNull();
      const audit = await conn.db.select().from(schema.auditLog);
      expect(audit.map((a) => a.action).sort()).toEqual([
        "attacks.geoip_downloaded",
        "attacks.geoip_downloaded",
      ]);
      expect(audit[0]?.organizationId).toBe(o.orgId);
    });

    it("asks again at most every twelve hours, and never when the month is already loaded", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      serveBoth();
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      log.length = 0;
      await attacks.geoipDownloadTick({ test: dbipTest(), now: new Date(NOW.getTime() + 13 * 3_600_000) });
      expect(log).toEqual([]);
      // A new month: due again.
      const next = new Date("2026-11-02T10:00:00Z");
      dbip.handler = (url) =>
        url.includes("country") ? { status: 200, body: countryCsv("NL") } : { status: 200, body: asnCsv };
      await attacks.geoipDownloadTick({ test: dbipTest(), now: next });
      expect(log).toHaveLength(2);
      expect(log[0]?.url).toContain("2026-11");
      const country = (await datasets()).find((d) => d.kind === "country");
      expect(country?.datasetMonth).toBe("2026-11");
      expect((await datasets()).filter((d) => d.state === "active")).toHaveLength(2);
    });

    it("falls back to last month while DB-IP has not published this month's file, and says so when nothing is there", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      dbip.handler = (url) =>
        url.includes(month)
          ? { status: 404 }
          : url.includes("country")
            ? { status: 200, body: countryCsv("DE") }
            : { status: 200, body: asnCsv };
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect((await loaded()).map((d) => d.datasetMonth)).toEqual([last, last]);

      await reset();
      await settingsRow(o.orgId);
      dbip.handler = () => ({ status: 404 });
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect(await loaded()).toEqual([]);
      expect((await settingsOf(o.orgId)).geoipDownloadLastError).toBe("notFound");
    });

    it("refuses redirects: the target is never contacted", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      dbip.handler = () => ({
        status: 302,
        headers: { location: `https://download.db-ip.com:${dbipPort}/elsewhere.csv.gz` },
      });
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      expect(log.some((l) => l.url.includes("elsewhere"))).toBe(false);
      expect(await loaded()).toEqual([]);
      expect((await settingsOf(o.orgId)).geoipDownloadLastError).toBe("redirected");
      const audit = await conn.db.select().from(schema.auditLog);
      expect(audit.some((a) => a.action === "attacks.geoip_download_failed")).toBe(true);
    });

    it("keeps the last good dataset when a download is too large, a bomb, damaged or the wrong file", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      serveBoth();
      await attacks.geoipDownloadTick({ test: dbipTest(), now: NOW });
      const before = (await datasets())
        .filter((d) => d.state === "active")
        .map((d) => d.id)
        .sort();
      expect(before).toHaveLength(2);

      const next = new Date("2026-11-02T10:00:00Z");
      const cases: [
        string,
        () => { status: number; headers?: Record<string, string>; body?: Buffer | string },
        Record<string, number>,
        string,
      ][] = [
        [
          "declared too large",
          () => ({ status: 200, headers: { "content-length": "999999999" }, body: "x" }),
          {},
          "tooLarge",
        ],
        [
          "streamed too large",
          () => ({
            status: 200,
            body: gzipSync(Buffer.from("198.51.100.0,198.51.100.255,DE\n".repeat(20_000))),
          }),
          { maxCompressedBytes: 500 },
          "tooLarge",
        ],
        [
          "a bomb of valid ranges",
          () => ({ status: 200, body: bomb() }),
          { maxDecompressedBytes: 1024 * 1024 },
          "decompressedTooLarge",
        ],
        [
          "a bomb of zeros",
          () => ({
            status: 200,
            body: gzipSync(Buffer.alloc(40 * 1024 * 1024), { level: zlibConstants.Z_BEST_COMPRESSION }),
          }),
          {},
          "lineTooLong",
        ],
        ["not gzip", () => ({ status: 200, body: "<html>maintenance</html>" }), {}, "notGzip"],
        ["the other kind", () => ({ status: 200, body: asnCsv }), {}, "wrongKind"],
        ["a server error", () => ({ status: 500 }), {}, "unreachable"],
      ];
      for (const [name, answer, limits, code] of cases) {
        await conn.db.update(schema.attackSettings).set({ geoipDownloadLastAttemptAt: null });
        dbip.handler = (url) => (url.includes("country") ? answer() : { status: 404 });
        await attacks.geoipDownloadTick({ test: dbipTest(), now: next, ...limits });
        const active = (await datasets()).filter((d) => d.state === "active" && d.kind === "country");
        expect(
          active.map((d) => d.id),
          name,
        ).toEqual(before.filter((id) => active.some((a) => a.id === id)));
        expect(active, name).toHaveLength(1);
        expect(active[0]?.datasetMonth, name).toBe(month);
        const failed = (await datasets()).find((d) => d.kind === "country" && d.state === "failed");
        expect(failed?.error, name).toBe(code);
        expect((await settingsOf(o.orgId)).geoipDownloadLastError, name).toBe(code);
      }
    });

    it("refuses a server whose certificate is not trusted", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      serveBoth();
      await attacks.geoipDownloadTick({ test: { ...dbipTest(), ca: abuseCert.cert }, now: NOW });
      expect(log).toEqual([]);
      expect(await loaded()).toEqual([]);
      expect((await settingsOf(o.orgId)).geoipDownloadLastError).toBe("tls");
    });

    it("refuses names that resolve to private, loopback or link-local addresses before connecting", async () => {
      for (const host of ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.1", "[::1]"]) {
        await expect(
          outbound.httpsGet({ host: host.replace(/^\[|\]$/g, ""), path: "/x", timeoutMs: 2000 }),
          host,
        ).rejects.toMatchObject({
          name: "OutboundError",
          code: expect.stringMatching(/refusedAddress|unreachable/),
        });
      }
      const refused = await outbound
        .httpsGet({ host: "localhost", path: "/x", timeoutMs: 2000 })
        .catch((e) => e);
      expect(refused.code).toBe("refusedAddress");
      expect(log.filter((l) => l.url === "/x")).toEqual([]);
    });

    it("gives up on a server that stops sending", async () => {
      await reset();
      const o = await newOrg();
      await settingsRow(o.orgId);
      dbip.handler = () => ({ status: 200, headers: { "content-length": "100" } });
      const slow = createServer({ key: dbipCert.key, cert: dbipCert.cert }, (_req, res) => {
        res.writeHead(200, { "content-type": "application/gzip" });
        res.write(Buffer.from([0x1f, 0x8b]));
        // never ends
      });
      await new Promise<void>((r) => slow.listen(0, "127.0.0.1", r));
      const port = (slow.address() as AddressInfo).port;
      try {
        const started = Date.now();
        await attacks.geoipDownloadTick({
          test: { lookup: toLocal(port) as never, ca: dbipCert.cert, port },
          now: NOW,
          timeoutMs: 600,
        });
        expect(Date.now() - started).toBeLessThan(10_000);
        expect(await loaded()).toEqual([]);
        expect((await settingsOf(o.orgId)).geoipDownloadLastError).toBe("timeout");
      } finally {
        slow.close();
        slow.closeAllConnections();
      }
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("OSINT", () => {
    const publicIps = (n: number) => Array.from({ length: n }, (_, i) => `198.51.100.${i + 1}`);
    const fast = () => ({ test: abuseTest(), now: NOW, gapMs: 0, timeoutMs: 3000 });
    const answerAll = () => {
      abuse.handler = (ip, key) =>
        key === API_KEY ? { status: 200, body: abuseAnswer(ip) } : { status: 403, body: "{}" };
    };
    const reset = async () => {
      log.length = 0;
      await conn.db.delete(schema.attackSettings);
      await conn.db.delete(schema.attackOsintResult);
    };

    it("sends nothing while OSINT is off, not acknowledged, without a key or without a provider", async () => {
      await reset();
      answerAll();
      const off = await newOrg();
      await addSources(
        off,
        publicIps(5).map((ip, i) => ({ ip, count: 10 - i })),
      );
      expect(await attacks.enrichOsint(off.orgId, fast())).toEqual({ checked: 0, cached: 0, error: null });
      await conn.db.insert(schema.attackSettings).values({ organizationId: off.orgId, osintEnabled: false });
      await attacks.enrichOsint(off.orgId, fast());

      const unack = await newOrg();
      await addSources(
        unack,
        publicIps(3).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(unack, { osintAcknowledgedAt: null });
      await attacks.enrichOsint(unack.orgId, fast());

      const noProvider = await newOrg();
      await addSources(
        noProvider,
        publicIps(3).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(noProvider, { osintProvider: null });
      await attacks.enrichOsint(noProvider.orgId, fast());
      expect(log).toEqual([]);

      const noKey = await newOrg();
      await addSources(
        noKey,
        publicIps(3).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(noKey, {}, null);
      expect((await attacks.enrichOsint(noKey.orgId, fast())).error).toBe("credentialsMissing");
      expect(log).toEqual([]);
    });

    it("looks up only the busiest public addresses, at most N, with the key in a header and nowhere else", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(o, [
        ...publicIps(6).map((ip, i) => ({ ip, count: 100 - i })),
        { ip: "10.0.0.5", count: 5000 },
        { ip: "192.168.1.1", count: 4000 },
        { ip: "127.0.0.1", count: 3000 },
        { ip: "fd00::1", count: 2000 },
        { ip: "198.51.100.1", count: 7, window: "7d" },
        { ip: "2001:db8::bad", count: 50 },
      ]);
      await enableOsint(o, { osintTopN: 4 });
      const run = await attacks.enrichOsint(o.orgId, fast());
      expect(run).toEqual({ checked: 4, cached: 0, error: null });
      // The busiest public addresses: 198.51.100.1 (100), .2 (99), .3 (98), .4 (97); internal ones were skipped.
      expect(log.map((l) => new URL(l.url, "https://x").searchParams.get("ipAddress"))).toEqual([
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
        "198.51.100.4",
      ]);
      for (const l of log) {
        expect(l.method).toBe("GET");
        expect(l.headers.key).toBe(API_KEY);
        expect(l.url).not.toContain(API_KEY);
        expect(l.url.startsWith("/api/v2/check?ipAddress=")).toBe(true);
        expect(l.headers.host).toMatch(/^api\.abuseipdb\.com:\d+$/);
        expect(l.headers.cookie).toBeUndefined();
      }
      const stored = await results(o.orgId);
      expect(stored).toHaveLength(4);
      expect(stored[0]).toMatchObject({ provider: "abuseipdb", score: 80, reports: 12 });
      // Only a score, a count and a date: whatever else the answer said is gone.
      expect(JSON.stringify(stored)).not.toContain("<b>");
      const s = await settingsOf(o.orgId);
      expect(s).toMatchObject({ osintUsageDay: "2026-10-22", osintUsageCount: 4, osintLastError: null });
    });

    it("reuses results for 24 hours, then asks again", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(
        o,
        publicIps(3).map((ip) => ({ ip, count: 10 })),
      );
      await enableOsint(o, { osintTopN: 3 });
      await attacks.enrichOsint(o.orgId, fast());
      log.length = 0;
      const again = await attacks.enrichOsint(o.orgId, {
        ...fast(),
        now: new Date(NOW.getTime() + 23 * 3_600_000),
      });
      expect(again).toEqual({ checked: 0, cached: 3, error: null });
      expect(log).toEqual([]);
      const later = await attacks.enrichOsint(o.orgId, {
        ...fast(),
        now: new Date(NOW.getTime() + 25 * 3_600_000),
      });
      expect(later.checked).toBe(3);
      expect(log).toHaveLength(3);
      expect(await results(o.orgId)).toHaveLength(3);
    });

    it("stops at the daily budget, counts across runs and starts over the next day", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(
        o,
        publicIps(10).map((ip, i) => ({ ip, count: 100 - i })),
      );
      await enableOsint(o, { osintTopN: 10, osintDailyBudget: 4 });
      const first = await attacks.enrichOsint(o.orgId, fast());
      expect(first).toEqual({ checked: 4, cached: 0, error: "budgetReached" });
      expect(log).toHaveLength(4);
      log.length = 0;
      const second = await attacks.enrichOsint(o.orgId, {
        ...fast(),
        now: new Date(NOW.getTime() + 3_600_000),
      });
      expect(second.error).toBe("budgetReached");
      expect(log).toEqual([]);
      const nextDay = await attacks.enrichOsint(o.orgId, {
        ...fast(),
        now: new Date("2026-10-23T01:00:00Z"),
      });
      expect(nextDay.checked).toBe(4);
      expect((await settingsOf(o.orgId)).osintUsageDay).toBe("2026-10-23");
    });

    it("stays below the provider's free tier whatever the setting says", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(
        o,
        publicIps(5).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(o, {
        osintTopN: 5,
        osintDailyBudget: 100_000,
        osintUsageDay: "2026-10-22",
        osintUsageCount: 999,
      });
      const run = await attacks.enrichOsint(o.orgId, fast());
      expect(run.checked).toBe(0);
      expect(run.error).toBe("budgetReached");
      expect(log).toEqual([]);
    });

    it("stops on a rejected key, on a rate limit and on a redirect, and says which", async () => {
      for (const [status, code] of [
        [401, "keyRejected"],
        [403, "keyRejected"],
        [429, "rateLimited"],
        [302, "redirected"],
      ] as const) {
        await reset();
        abuse.handler = () => ({
          status,
          headers:
            status === 302
              ? { location: "https://api.abuseipdb.com/elsewhere" }
              : ({} as Record<string, string>),
          body: "{}",
        });
        const o = await newOrg();
        await addSources(
          o,
          publicIps(5).map((ip) => ({ ip, count: 5 })),
        );
        await enableOsint(o);
        const run = await attacks.enrichOsint(o.orgId, fast());
        expect(run.error, String(status)).toBe(code);
        expect(log, String(status)).toHaveLength(1);
        expect((await settingsOf(o.orgId)).osintLastError).toBe(code);
        expect(await results(o.orgId)).toEqual([]);
      }
    });

    it("does not store an answer that is not about the address, not JSON, too large or incomplete", async () => {
      const bodies: [string, (ip: string) => { status: number; body: string }][] = [
        ["another address", () => ({ status: 200, body: abuseAnswer("203.0.113.9") })],
        ["not JSON", () => ({ status: 200, body: "<html>captcha</html>" })],
        ["too large", () => ({ status: 200, body: JSON.stringify({ data: { pad: "x".repeat(50_000) } }) })],
        ["no score", (ip) => ({ status: 200, body: JSON.stringify({ data: { ipAddress: ip } }) })],
        ["a score out of range", (ip) => ({ status: 200, body: abuseAnswer(ip, 4711) })],
        ["a server error", () => ({ status: 500, body: "boom" })],
      ];
      for (const [name, make] of bodies) {
        await reset();
        abuse.handler = (ip) => make(ip);
        const o = await newOrg();
        await addSources(
          o,
          publicIps(5).map((ip) => ({ ip, count: 5 })),
        );
        await enableOsint(o);
        const run = await attacks.enrichOsint(o.orgId, fast());
        expect(run.checked, name).toBe(0);
        expect(run.error, name).not.toBeNull();
        expect(await results(o.orgId), name).toEqual([]);
        // Three bad answers in a row end the run; it does not hammer the provider.
        expect(log.length, name).toBeLessThanOrEqual(3);
      }
    });

    it("never stores or logs the API key outside the vault", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(
        o,
        publicIps(3).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(o);
      const before = consoleLines.length;
      await attacks.enrichOsint(o.orgId, fast());
      abuse.handler = () => ({ status: 401, body: "{}" });
      await conn.db.delete(schema.attackOsintResult);
      await attacks.enrichOsint(o.orgId, { ...fast(), now: new Date(NOW.getTime() + 26 * 3_600_000) });
      const dump: string[] = [];
      for (const table of [
        "attack_settings",
        "attack_osint_result",
        "wazuh_source_ip",
        "audit_log",
        "geoip_dataset",
        "wazuh_attack_window",
      ]) {
        const res = await conn.pool.query(`select row_to_json(t)::text as row from ${table} t`);
        dump.push(...res.rows.map((r: { row: string }) => r.row));
      }
      expect(dump.join("\n")).not.toContain(API_KEY);
      const secrets = await conn.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.purpose, "osint-api-key"));
      expect(secrets.length).toBeGreaterThan(0);
      for (const s of secrets) expect(JSON.stringify(s.sealed)).not.toContain(API_KEY);
      expect(consoleLines.slice(before).join("\n")).not.toContain(API_KEY);
      expect(consoleLines.join("\n")).not.toContain(API_KEY);
    });

    it("answers with a generic error for a certificate it does not trust, and sends nothing", async () => {
      await reset();
      answerAll();
      const o = await newOrg();
      await addSources(
        o,
        publicIps(2).map((ip) => ({ ip, count: 5 })),
      );
      await enableOsint(o);
      const run = await attacks.enrichOsint(o.orgId, {
        ...fast(),
        test: { ...abuseTest(), ca: dbipCert.cert },
      });
      expect(run.error).toBe("unreachable");
      expect(log).toEqual([]);
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("retention", () => {
    it("deletes what is older than each organisation's period and keeps the rest", async () => {
      await conn.db.delete(schema.attackSettings);
      const now = new Date("2026-10-22T12:00:00Z");
      const day = 86_400_000;
      const keepDefault = await newOrg(); // default: 90 days
      const short = await newOrg(); // 7 days
      await conn.db.insert(schema.attackSettings).values({ organizationId: short.orgId, retentionDays: 7 });

      for (const o of [keepDefault, short]) {
        await conn.db.insert(schema.wazuhSourceIp).values([
          {
            id: `wzs_old${o.orgId.slice(-6)}0001`,
            organizationId: o.orgId,
            connectionId: o.connectionId,
            window: "24h" as const,
            ip: "198.51.100.1",
            count: 1,
            seenAt: new Date(now.getTime() - 100 * day),
          },
          {
            id: `wzs_mid${o.orgId.slice(-6)}0002`,
            organizationId: o.orgId,
            connectionId: o.connectionId,
            window: "7d" as const,
            ip: "198.51.100.2",
            count: 1,
            seenAt: new Date(now.getTime() - 30 * day),
          },
          {
            id: `wzs_new${o.orgId.slice(-6)}0003`,
            organizationId: o.orgId,
            connectionId: o.connectionId,
            window: "30d" as const,
            ip: "198.51.100.3",
            count: 1,
            seenAt: new Date(now.getTime() - 1 * day),
          },
        ]);
        await conn.db.insert(schema.wazuhAttackWindow).values([
          {
            organizationId: o.orgId,
            connectionId: o.connectionId,
            window: "24h",
            attackAlerts: 1,
            distinctSources: 1,
            previousSources: [{ ip: "198.51.100.9", count: 1 }],
            readAt: new Date(now.getTime() - 100 * day),
          },
          {
            organizationId: o.orgId,
            connectionId: o.connectionId,
            window: "7d",
            attackAlerts: 1,
            distinctSources: 1,
            readAt: new Date(now.getTime() - day),
          },
        ]);
        await conn.db.insert(schema.attackOsintResult).values([
          {
            id: `osr_old${o.orgId.slice(-6)}0001`,
            organizationId: o.orgId,
            provider: "abuseipdb",
            ip: "198.51.100.1",
            score: 1,
            reports: 1,
            checkedAt: new Date(now.getTime() - 100 * day),
          },
          {
            id: `osr_new${o.orgId.slice(-6)}0002`,
            organizationId: o.orgId,
            provider: "abuseipdb",
            ip: "198.51.100.3",
            score: 1,
            reports: 1,
            checkedAt: new Date(now.getTime() - 1 * day),
          },
        ]);
      }
      const swept = await attacks.retentionSweep(now);
      expect(swept).toEqual({ sourceAddresses: 3, attackWindows: 2, osintResults: 2, attackEvents: 0 });
      const left = async (orgId: string) =>
        (
          await conn.db
            .select()
            .from(schema.wazuhSourceIp)
            .where(eq(schema.wazuhSourceIp.organizationId, orgId))
        )
          .map((r) => r.ip)
          .sort();
      // Default period (90 days): only the 100 days old row goes. Seven days: the 30 days old row goes too.
      expect(await left(keepDefault.orgId)).toEqual(["198.51.100.2", "198.51.100.3"]);
      expect(await left(short.orgId)).toEqual(["198.51.100.3"]);
      expect(await results(keepDefault.orgId)).toHaveLength(1);
      const windows = await conn.db
        .select()
        .from(schema.wazuhAttackWindow)
        .where(eq(schema.wazuhAttackWindow.organizationId, keepDefault.orgId));
      expect(windows.map((w) => w.window)).toEqual(["7d"]);
      // A second run has nothing left to do.
      expect(await attacks.retentionSweep(now)).toEqual({
        sourceAddresses: 0,
        attackWindows: 0,
        osintResults: 0,
        attackEvents: 0,
      });
    });

    it("runs with nothing stored", async () => {
      await conn.db.delete(schema.wazuhSourceIp);
      await conn.db.delete(schema.wazuhAttackWindow);
      await conn.db.delete(schema.attackOsintResult);
      expect(await attacks.retentionSweep()).toEqual({
        sourceAddresses: 0,
        attackWindows: 0,
        osintResults: 0,
        attackEvents: 0,
      });
    });
  });
});
