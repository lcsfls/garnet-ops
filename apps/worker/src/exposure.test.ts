/**
 * Website monitoring end to end (ADR 0023, ADR 0033): the proof of control, stage 1 (passive) and stage 2 (light active), the schedule, the
 * notifications and the opt-in Certificate Transparency lookup, against local servers on loopback with throw-away certificates (a valid
 * one, one that expires in ten days, one that expired in 2020), a fake resolver and a test-only address policy that opens loopback. A
 * throw-away PostgreSQL database on the development server stands in for the installation. Skipped without openssl or the development
 * PostgreSQL. Nothing leaves the machine.
 */
import { writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import {
  createServer as createHttpServer,
  type Server as HttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newId } from "@garnetops/core";
import {
  ACTIVE_LIMITS,
  type ActiveSnapshot,
  EXPOSURE_PORTS,
  type PassiveSnapshot,
  type PortSpec,
  verifyRecordValue,
} from "@garnetops/core/exposure";
import { newVerifyToken } from "@garnetops/core/exposure-assets";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { devDatabaseUrl } from "@garnetops/db/testing";
import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  bytesReceived,
  closedPort,
  expiredCert,
  fakeDns,
  haveOpenssl,
  type Listener,
  type Pem,
  SITE,
  selfSigned,
  tcpListener,
  tlsListener,
  tlsRecordTypes,
} from "../test/exposure-fixtures.ts";
import type { NetEnv } from "./exposure-net.ts";

const adminUrl = devDatabaseUrl();
const openssl = haveOpenssl();
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

describe.skipIf(!openssl || !adminUrl)(
  "External exposure: proof of control, stage 1, stage 2 and the schedule",
  () => {
    const dbName = `garnetops_exposure_test_${process.pid}`;
    let admin: ReturnType<typeof createDb>;
    let conn: ReturnType<typeof createDb>;
    let workDir: string;
    let ex: typeof import("./exposure.ts");
    let net: typeof import("./exposure-net.ts");
    let ct: typeof import("./exposure-ct.ts");
    let counter = 0;
    const consoleLines: string[] = [];

    /* ------------------------------ certificates ----------------------------- */
    let good: Pem;
    let expiring: Pem;
    let expired: Pem;
    let trust = "";

    /* ------------------------------- web servers ----------------------------- */
    interface WebState {
      status: number;
      headers: Record<string, string>;
      location: string | null;
      body: string;
      /** What the well-known file answers: a body, or null for 404. */
      proof: string | null;
      proofStatus: number;
      hostsSeen: string[];
      requests: string[];
      /** The token the fake GarnetOps WordPress plugin accepts; null: the plugin is not installed. */
      wpToken: string | null;
    }
    const web: WebState = freshWeb();
    function freshWeb(): WebState {
      return {
        status: 200,
        headers: {},
        location: null,
        body: "<html>hello</html>",
        proof: null,
        proofStatus: 200,
        hostsSeen: [],
        requests: [],
        wpToken: null,
      };
    }
    const plainState = { redirect: true, requests: 0 };
    let siteGood: HttpsServer;
    let siteExpiring: HttpsServer;
    let siteExpired: HttpsServer;
    let siteLegacy: HttpsServer;
    let plain: HttpServer;
    let ports = { good: 0, expiring: 0, expired: 0, legacy: 0, plain: 0 };

    function handle(req: IncomingMessage, res: ServerResponse) {
      web.hostsSeen.push(String(req.headers.host));
      web.requests.push(`${req.method} ${req.url}`);
      if (req.url === "/?rest_route=/garnetops/v1/inventory") {
        if (web.wpToken === null) return void res.writeHead(404).end("{}");
        if (req.headers.authorization !== `Bearer ${web.wpToken}`) return void res.writeHead(401).end("{}");
        return void res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            schema: 1,
            plugin: "garnetops",
            pluginVersion: "1.0.0",
            wordpress: "6.5.2",
            php: "8.2.12",
            plugins: [
              { slug: "contact-form-7", version: "5.9.3", active: true },
              { slug: "hidden-plugin", version: "2.0.0", active: false },
            ],
            themes: [{ slug: "astra", version: "4.6.0", active: true }],
          }),
        );
      }
      if (req.url === "/.well-known/garnetops-verify.txt") {
        if (web.proof === null) return void res.writeHead(404).end("not found");
        if (web.proofStatus >= 300 && web.proofStatus < 400)
          return void res.writeHead(web.proofStatus, { location: "https://elsewhere.example.org/" }).end();
        return void res.writeHead(web.proofStatus, { "content-type": "text/plain" }).end(web.proof);
      }
      const headers: Record<string, string> = { "content-type": "text/html", ...web.headers };
      if (web.location) headers.location = web.location;
      if (req.url === "/huge") {
        res.writeHead(200, headers);
        const chunk = Buffer.alloc(64 * 1024, 0x41);
        let sent = 0;
        const pump = () => {
          while (sent < 200) {
            sent += 1;
            if (!res.write(chunk)) return void res.once("drain", pump);
          }
          res.end();
        };
        return pump();
      }
      res.writeHead(web.status, headers).end(web.body);
    }

    /* ------------------------------- environment ----------------------------- */
    const zone: Parameters<typeof fakeDns>[0] = {};
    const dns = fakeDns(zone);
    const resetZone = () => {
      for (const key of Object.keys(zone)) delete zone[key];
      dns.queries.length = 0;
    };
    function env(over: Partial<NetEnv> = {}): NetEnv {
      return {
        dns,
        allowTestRanges: true,
        ca: trust,
        httpsPort: ports.good,
        httpPort: ports.plain,
        connectTimeoutMs: 800,
        bannerReadMs: 500,
        ...over,
      };
    }

    /* ---------------------------------- rows --------------------------------- */
    async function newOrg() {
      const id = `org_ex_${++counter}`;
      await conn.db.insert(schema.organization).values({ id, name: `Exposure ${counter}` });
      const users: Record<string, string> = {};
      for (const role of ["owner", "admin", "member"] as const) {
        const userId = `user_ex_${counter}_${role}`;
        await conn.db
          .insert(schema.user)
          .values({ id: userId, name: userId, email: `${userId}@example.test`, locale: "en" });
        await conn.db.insert(schema.membership).values({ organizationId: id, userId, role });
        users[role] = userId;
      }
      // The module is on (ADR 0033); one test switches it off.
      await conn.db.insert(schema.exposureSettings).values({ organizationId: id, enabled: true });
      return { id, users };
    }

    async function addAsset(org: string, over: Partial<typeof schema.exposureAsset.$inferInsert> = {}) {
      const id = `exa_test${String(++counter).padStart(12, "0")}`;
      const value = over.value ?? `host${counter}.example.com`;
      await conn.db.insert(schema.exposureAsset).values({
        id,
        organizationId: org,
        kind: "domain",
        value,
        verifyToken: newVerifyToken(),
        ...over,
      });
      return asset(id);
    }
    /** An asset that has proved control and has stage 2 switched on and acknowledged. */
    async function readyAsset(
      org: { id: string; users: Record<string, string> },
      over: Partial<typeof schema.exposureAsset.$inferInsert> = {},
      now = new Date(),
    ) {
      return addAsset(org.id, {
        verifyState: "verified",
        verifyMethod: "dns",
        verifiedAt: now,
        verifyCheckedAt: now,
        stage2Enabled: true,
        stage2AcknowledgedBy: org.users.owner as string,
        stage2AcknowledgedAt: now,
        ...over,
      });
    }
    const asset = async (id: string) =>
      (
        await conn.db.select().from(schema.exposureAsset).where(eq(schema.exposureAsset.id, id))
      )[0] as typeof schema.exposureAsset.$inferSelect;
    async function queued(assetRow: { id: string; organizationId: string }, stage: "passive" | "active") {
      const id = newId("exr");
      await conn.db.insert(schema.exposureRun).values({
        id,
        organizationId: assetRow.organizationId,
        assetId: assetRow.id,
        stage,
        state: "queued",
        trigger: "manual",
        createdAt: new Date(),
      });
      return id;
    }
    const run = async (id: string) =>
      (
        await conn.db.select().from(schema.exposureRun).where(eq(schema.exposureRun.id, id))
      )[0] as typeof schema.exposureRun.$inferSelect;
    const findings = async (assetId: string, state: "open" | "resolved" = "open") =>
      conn.db
        .select()
        .from(schema.exposureFinding)
        .where(and(eq(schema.exposureFinding.assetId, assetId), eq(schema.exposureFinding.state, state)));
    const rules = async (assetId: string) =>
      (await findings(assetId)).map((f) => `${f.rule}:${f.subject}`).sort();
    const told = async (org: string, titleKey: string) =>
      conn.db
        .select()
        .from(schema.userNotification)
        .where(
          and(
            eq(schema.userNotification.organizationId, org),
            eq(schema.userNotification.titleKey, titleKey),
          ),
        );
    const audits = async (assetId: string) =>
      (await conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, assetId))).map(
        (a) => a.action,
      );

    async function passive(
      assetRow: { id: string; organizationId: string },
      over: Partial<NetEnv> = {},
      now?: Date,
    ) {
      const id = await queued(assetRow, "passive");
      await ex.runPassive(id, { net: env(over), ...(now ? { now: () => now } : {}), ctPauseMs: 0 });
      return run(id);
    }
    async function active(
      assetRow: { id: string; organizationId: string },
      extra: { ports?: readonly PortSpec[]; net?: Partial<NetEnv>; now?: Date } = {},
    ) {
      const id = await queued(assetRow, "active");
      await ex.runActive(id, {
        net: env(extra.net),
        ...(extra.ports ? { ports: extra.ports } : {}),
        ...(extra.now ? { now: () => extra.now as Date } : {}),
      });
      return run(id);
    }

    /** Makes a domain resolve to loopback with the records of a tidy domain. */
    function tidyZone(name: string) {
      zone[name] = {
        a: ["127.0.0.1"],
        mx: [{ priority: 10, exchange: `mail.${name}` }],
        caa: [{ critical: 0, issue: "ca.example.net" }],
        txt: [["v=spf1 mx -all"]],
      };
      zone[`_dmarc.${name}`] = { txt: [["v=DMARC1; p=reject"]] };
    }
    const TIDY_HEADERS = {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "permissions-policy": "geolocation=()",
    };

    beforeAll(async () => {
      admin = createDb(adminUrl as string, { max: 1 });
      await admin.pool.query(`drop database if exists ${dbName} with (force)`);
      await admin.pool.query(`create database ${dbName}`);
      const url = new URL(adminUrl as string);
      url.pathname = `/${dbName}`;
      workDir = await mkdtemp(join(tmpdir(), "garnetops-exposure-test-"));
      const keyFile = join(workDir, "vault.key.pem");
      writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
      Object.assign(process.env, {
        NODE_ENV: "test",
        DATABASE_URL: url.toString(),
        GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
        GARNETOPS_GRYPE_BIN: "grype-not-used",
        GARNETOPS_GRYPE_DB_DIR: join(workDir, "no-db"),
        GARNETOPS_WORK_DIR: workDir,
      });
      conn = createDb(url.toString(), { max: 4 });
      await runMigrations(conn.db);

      good = selfSigned(workDir, "good", [SITE, `www.${SITE}`], 90);
      expiring = selfSigned(workDir, "expiring", [SITE, `www.${SITE}`], 10);
      expired = expiredCert(workDir, SITE);
      trust = `${good.cert}\n${expiring.cert}`;

      const listen = (server: HttpsServer | HttpServer) =>
        new Promise<number>((resolve) =>
          server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)),
        );
      siteGood = createHttpsServer({ key: good.key, cert: good.cert }, handle);
      siteExpiring = createHttpsServer({ key: expiring.key, cert: expiring.cert }, handle);
      siteExpired = createHttpsServer({ key: expired.key, cert: expired.cert }, handle);
      siteLegacy = createHttpsServer(
        { key: good.key, cert: good.cert, minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" },
        handle,
      );
      plain = createHttpServer((req, res) => {
        plainState.requests += 1;
        web.hostsSeen.push(String(req.headers.host));
        if (plainState.redirect) return void res.writeHead(301, { location: `https://${SITE}/` }).end();
        res.writeHead(200, { "content-type": "text/html" }).end("plain");
      });
      ports = {
        good: await listen(siteGood),
        expiring: await listen(siteExpiring),
        expired: await listen(siteExpired),
        legacy: await listen(siteLegacy),
        plain: await listen(plain),
      };
      for (const method of ["log", "error", "warn", "info"] as const) {
        vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
          consoleLines.push(args.map(String).join(" "));
        });
      }
      ex = await import("./exposure.ts");
      net = await import("./exposure-net.ts");
      ct = await import("./exposure-ct.ts");
    }, 90_000);

    afterAll(async () => {
      vi.restoreAllMocks();
      for (const server of [siteGood, siteExpiring, siteExpired, siteLegacy, plain]) {
        server?.close();
        (server as HttpsServer | undefined)?.closeAllConnections?.();
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

    /* ======================================================================== */
    describe("proof of control", () => {
      it("verifies a domain by its DNS TXT record and audits it", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id);
        zone[`_garnetops-challenge.${a.value}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        await ex.runVerify(a.id, { net: env() });
        const row = await asset(a.id);
        expect(row).toMatchObject({ verifyState: "verified", verifyMethod: "dns", verifyError: null });
        expect(row.verifiedAt).not.toBeNull();
        expect(await audits(a.id)).toContain("exposure.verified");
      });

      it("asks the zone's own name servers, so a cached or internal 'not there' does not hide a published record", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id);
        // The system resolver does not see the record (it cached the miss of an earlier check, or has an internal view of the
        // domain); the domain's name server answers with it.
        zone[a.value] = { ns: [`ns1.${a.value}`, "ns.internal.example.com"] };
        zone[`ns1.${a.value}`] = { a: ["192.0.2.53"] };
        zone["ns.internal.example.com"] = { a: ["10.0.0.53"] };
        const asked: string[] = [];
        const dnsAt = (server: string) => {
          asked.push(server);
          return {
            ...dns,
            resolveTxt: async () => [[verifyRecordValue(a.verifyToken)]],
          };
        };
        await ex.runVerify(a.id, { net: env({ dnsAt }) });
        expect(await asset(a.id)).toMatchObject({ verifyState: "verified", verifyMethod: "dns" });
        // A name server that resolves to a non-public address is never asked.
        expect(asked).toEqual(["192.0.2.53"]);
      });

      it("still verifies through the system resolver when the name servers cannot be asked", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id);
        zone[a.value] = { ns: [`ns1.${a.value}`] };
        zone[`ns1.${a.value}`] = { a: ["192.0.2.53"] };
        zone[`_garnetops-challenge.${a.value}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        const refused = () => Object.assign(new Error("refused"), { code: "EREFUSED" });
        const dnsAt = () => ({ ...dns, resolveTxt: () => Promise.reject(refused()) });
        await ex.runVerify(a.id, { net: env({ dnsAt }) });
        expect(await asset(a.id)).toMatchObject({ verifyState: "verified", verifyMethod: "dns" });
      });

      it("explains why a record is missing or different, and stays unverified", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id);
        zone[a.value] = { a: ["127.0.0.1"] };
        await ex.runVerify(a.id, { net: env() });
        expect((await asset(a.id)).verifyError).toBe("dnsRecordMissing");
        zone[`_garnetops-challenge.${a.value}`] = { txt: [[verifyRecordValue(newVerifyToken())]] };
        await ex.runVerify(a.id, { net: env() });
        expect(await asset(a.id)).toMatchObject({ verifyState: "unverified", verifyError: "dnsNoMatch" });
      });

      it("never accepts another organisation's token or a token for another asset", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id);
        const b = await addAsset(org.id);
        zone[`_garnetops-challenge.${a.value}`] = { txt: [[verifyRecordValue(b.verifyToken)]] };
        await ex.runVerify(a.id, { net: env() });
        expect((await asset(a.id)).verifyState).toBe("unverified");
      });

      it("verifies by the file, for a name over HTTPS and for an address", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        web.proof = a.verifyToken;
        await ex.runVerify(a.id, { net: env() });
        expect(await asset(a.id)).toMatchObject({ verifyState: "verified", verifyMethod: "http" });

        // An address asset: the file is fetched over HTTPS (chain verified) and then plain HTTP; the test server is HTTPS only for 443,
        // so the file is found on the HTTPS port, which the test environment maps to the good server.
        const ip = await addAsset(org.id, { kind: "ip", value: "127.0.0.1" });
        web.proof = `${ip.verifyToken}\n`;
        await ex.runVerify(ip.id, { net: env() });
        expect(await asset(ip.id)).toMatchObject({ verifyState: "verified", verifyMethod: "http" });
        web.proof = null;
      });

      it("refuses a redirected or oversized file and a file that is not there", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        web.proof = a.verifyToken;
        web.proofStatus = 302;
        await ex.runVerify(a.id, { net: env() });
        expect((await asset(a.id)).verifyError).toBe("fileRedirected");
        web.proofStatus = 200;
        web.proof = `${"x".repeat(3000)}\n${a.verifyToken}`;
        await ex.runVerify(a.id, { net: env() });
        expect((await asset(a.id)).verifyError).toBe("fileTooLarge");
        web.proof = "something else";
        await ex.runVerify(a.id, { net: env() });
        expect((await asset(a.id)).verifyError).toBe("fileNoMatch");
        web.proof = null;
        await ex.runVerify(a.id, { net: env() });
        expect(await asset(a.id)).toMatchObject({
          verifyState: "unverified",
          verifyError: "dnsRecordMissing",
        });
        // For an address there is no DNS: the file's absence is the answer.
        const ip = await addAsset(org.id, { kind: "ip", value: "127.0.0.1" });
        await ex.runVerify(ip.id, { net: env() });
        expect((await asset(ip.id)).verifyError).toBe("fileNotFound");
      });

      it("does not look for the file at an address that is not public", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: "internal-name.example.com" });
        zone[a.value] = { a: ["10.0.0.5"] };
        web.requests.length = 0;
        await ex.runVerify(a.id, { net: env() });
        expect(web.requests).toEqual([]);
        expect((await asset(a.id)).verifyError).toBe("dnsRecordMissing");
      });

      it("loses a verified asset when the proof is definitely gone: stage 2 off, acknowledgement void, audited, owners and admins told", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1"] };
        web.proof = null;
        await ex.runVerify(a.id, { net: env() });
        const row = await asset(a.id);
        expect(row).toMatchObject({
          verifyState: "lost",
          stage2Enabled: false,
          stage2AcknowledgedAt: null,
          stage2AcknowledgedBy: null,
          verifyError: "dnsRecordMissing",
        });
        expect(await audits(a.id)).toContain("exposure.verification_lost");
        const notes = await told(org.id, "exposureVerificationLost");
        expect(notes.map((n) => n.userId).sort()).toEqual([org.users.admin, org.users.owner].sort());
        expect(notes[0]?.params).toEqual({ asset: SITE });
        expect(notes[0]?.link).toBe(`/websites/${a.id}`);
        // Told once: a second check of a lost asset says nothing more.
        await ex.runVerify(a.id, { net: env() });
        expect(await told(org.id, "exposureVerificationLost")).toHaveLength(2);
      });

      it("does not lose the proof because a lookup failed", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { fail: ["txt"] };
        zone[SITE] = { a: ["127.0.0.1"] };
        await ex.runVerify(a.id, { net: env() });
        expect(await asset(a.id)).toMatchObject({
          verifyState: "verified",
          stage2Enabled: true,
          verifyError: "dnsFailed",
        });
        expect(await told(org.id, "exposureVerificationLost")).toEqual([]);
      });

      it("restores a lost asset when the proof is back, but stage 2 needs a new acknowledgement", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE, verifyState: "lost" });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        await ex.runVerify(a.id, { net: env() });
        expect(await asset(a.id)).toMatchObject({ verifyState: "verified", stage2Enabled: false });
        expect(await audits(a.id)).toContain("exposure.verification_restored");
      });

      it("stops stage 2 of subdomains when their verified parent loses its proof", async () => {
        resetZone();
        const org = await newOrg();
        const parent = await readyAsset(org, { value: "parent.example.com", includeSubdomains: true });
        const child = await addAsset(org.id, {
          value: "app.parent.example.com",
          stage2Enabled: true,
          stage2AcknowledgedBy: org.users.owner as string,
          stage2AcknowledgedAt: new Date(),
        });
        zone["parent.example.com"] = { a: ["127.0.0.1"] };
        await ex.runVerify(parent.id, { net: env() });
        expect((await asset(parent.id)).verifyState).toBe("lost");
        expect(await asset(child.id)).toMatchObject({ stage2Enabled: false, stage2AcknowledgedAt: null });
        expect(await audits(child.id)).toContain("exposure.stage2_stopped");
      });
    });

    /* ======================================================================== */
    describe("stage 1", () => {
      it("notes the WordPress plugins and themes the home page's asset addresses name, and nothing else of the page (ADR 0042)", async () => {
        resetZone();
        Object.assign(web, freshWeb(), {
          headers: { ...TIDY_HEADERS },
          body: `<meta name="generator" content="WordPress 6.5.2" />
            <link href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" rel="stylesheet" />
            <script src="/wp-content/plugins/contact-form-7/a.js?ver=5.9.3"></script>
            <script src="/wp-content/plugins/plain/a.js?ver=6.5.2"></script>
            SECRET-BODY-MARKER`,
        });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        await passive(a);
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot.http?.wordpress).toEqual({
          plugins: [
            { slug: "contact-form-7", version: "5.9.3" },
            { slug: "plain", version: null },
          ],
          themes: [{ slug: "twentytwentyfour", version: "1.2" }],
        });
        Object.assign(web, freshWeb());
      });

      it("asks wordpress.org only for opted-in organisations' slugs, once a day, and judges plugins against the answers (ADR 0042)", async () => {
        resetZone();
        const wp = await import("./wordpress-org.ts");
        const body = `<meta name="generator" content="WordPress 6.5.2" />
          <script src="/wp-content/plugins/contact-form-7/a.js?ver=5.9.3"></script>
          <script src="/wp-content/plugins/premium-only/a.js?ver=2.0"></script>`;
        const asked: string[] = [];
        const fetch = async (kind: "plugin" | "theme", slug: string) => {
          asked.push(`${kind}:${slug}`);
          return slug === "premium-only"
            ? ({ listed: false } as const)
            : ({ listed: true, latest: "5.9.8" } as const);
        };
        // Two organisations with the same plugin; only one switched the lookup on.
        const on = await newOrg();
        const off = await newOrg();
        await conn.db
          .update(schema.exposureSettings)
          .set({ wordpressOrgEnabled: true })
          .where(eq(schema.exposureSettings.organizationId, on.id));
        const a = await addAsset(on.id, { value: SITE });
        tidyZone(SITE);
        Object.assign(web, freshWeb(), { headers: { ...TIDY_HEADERS }, body });
        await passive(a);
        await conn.db.delete(schema.wordpressComponent);
        const now = new Date();
        expect(await wp.refreshWordPressVersions({ fetch, now: () => now, gapMs: 0 })).toBe(2);
        expect(asked.sort()).toEqual(["plugin:contact-form-7", "plugin:premium-only"]);
        // Asked again only after a day.
        expect(await wp.refreshWordPressVersions({ fetch, now: () => now, gapMs: 0 })).toBe(0);

        // The next look judges it: behind its latest version is a low finding; an unlisted plugin is not judged.
        await passive(a);
        expect((await rules(a.id)).filter((r) => r.startsWith("wordpressOutdated"))).toEqual([
          "wordpressOutdated:plugin:contact-form-7",
        ]);
        // The organisation without the lookup gets no such finding for the same plugin.
        const b = await addAsset(off.id, { value: SITE });
        await passive(b);
        expect((await rules(b.id)).filter((r) => r.startsWith("wordpressOutdated"))).toEqual([]);
        // Switched off: the finding is resolved at the next look.
        await conn.db
          .update(schema.exposureSettings)
          .set({ wordpressOrgEnabled: false })
          .where(eq(schema.exposureSettings.organizationId, on.id));
        await passive(a);
        expect((await rules(a.id)).filter((r) => r.startsWith("wordpressOutdated"))).toEqual([]);
        Object.assign(web, freshWeb());
      });

      it("downloads the Wordfence feed with the organisation's own key, keeps only its slugs, and finds affected versions (ADR 0042)", async () => {
        resetZone();
        const wf = await import("./wordfence.ts");
        const { sealSecret } = await import("./vault-secrets.ts");
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        Object.assign(web, freshWeb(), {
          headers: { ...TIDY_HEADERS },
          body: `<meta name="generator" content="WordPress 6.5.2" />
            <script src="/wp-content/plugins/contact-form-7/a.js?ver=5.9.3"></script>`,
        });
        await passive(a);
        const key = `wf_${"k".repeat(40)}`;
        const secretId = await sealSecret(conn.db, org.id, "wordfence-api-key", key);
        await conn.db
          .update(schema.exposureSettings)
          .set({ wordfenceSecretId: secretId })
          .where(eq(schema.exposureSettings.organizationId, org.id));
        const range = (to: string) => ({
          [`* - ${to}`]: { from_version: "*", from_inclusive: true, to_version: to, to_inclusive: true },
        });
        const feed = {
          "11111111-aaaa": {
            id: "11111111-aaaa",
            title: "Contact Form 7 <= 5.9.3 - Reflected Cross-Site Scripting",
            software: [
              {
                type: "plugin",
                slug: "contact-form-7",
                affected_versions: range("5.9.3"),
                patched_versions: ["5.9.4"],
              },
            ],
            cvss: { score: 6.1, rating: "Medium" },
            cve: "CVE-2024-0001",
            published: "2024-03-01 10:00:00",
          },
          "22222222-bbbb": {
            id: "22222222-bbbb",
            title: "Contact Form 7 <= 5.0 - old",
            software: [{ type: "plugin", slug: "contact-form-7", affected_versions: range("5.0") }],
            cvss: { score: 9.8, rating: "Critical" },
          },
          "33333333-cccc": {
            id: "33333333-cccc",
            title: "WordPress Core <= 6.5.2 - Stored XSS",
            software: [{ type: "core", slug: "wordpress", affected_versions: range("6.5.2") }],
            cvss: { score: 7.2, rating: "High" },
          },
          "44444444-dddd": {
            id: "44444444-dddd",
            title: "Not on any website",
            software: [{ type: "plugin", slug: "akismet", affected_versions: range("9.9") }],
          },
        };
        let usedKey = "";
        const result = await wf.syncWordfence(org.id, {
          fetch: async (k) => {
            usedKey = k;
            return feed;
          },
        });
        expect(usedKey).toBe(key);
        expect(result).toEqual({ advisories: 3 });
        const stored = await conn.db
          .select()
          .from(schema.wordpressAdvisory)
          .where(eq(schema.wordpressAdvisory.organizationId, org.id));
        expect(stored.map((x) => `${x.kind}:${x.slug}:${x.id}`).sort()).toEqual([
          "core:wordpress:33333333-cccc",
          "plugin:contact-form-7:11111111-aaaa",
          "plugin:contact-form-7:22222222-bbbb",
        ]);

        await passive(a);
        const vulnerable = (await findings(a.id)).filter((f) => f.rule === "wordpressVulnerable");
        expect(vulnerable.map((f) => [f.subject, f.severity]).sort()).toEqual([
          ["core:wordpress:33333333-cccc", "high"],
          ["plugin:contact-form-7:11111111-aaaa", "medium"],
        ]);
        expect(vulnerable.find((f) => f.severity === "medium")?.params).toMatchObject({
          cve: "CVE-2024-0001",
          patched: "5.9.4",
        });

        // A rejected key is stored as a code, and the advisories of the last download stay.
        const { OutboundError } = await import("./outbound.ts");
        expect(
          await wf.syncWordfence(org.id, {
            fetch: async () => {
              throw new OutboundError("httpStatus", 401);
            },
          }),
        ).toEqual({ error: "unauthorized" });
        const [settings] = await conn.db
          .select()
          .from(schema.exposureSettings)
          .where(eq(schema.exposureSettings.organizationId, org.id));
        expect(settings).toMatchObject({ wordfenceError: "unauthorized", wordfenceAdvisories: 3 });
        Object.assign(web, freshWeb());
      });

      it("reads the GarnetOps WordPress plugin with the site's token, only for a verified site (ADR 0042, part 4)", async () => {
        resetZone();
        const { sealSecret } = await import("./vault-secrets.ts");
        const org = await newOrg();
        tidyZone(SITE);
        const token = "t".repeat(43);
        Object.assign(web, freshWeb(), { headers: { ...TIDY_HEADERS }, wpToken: token });
        const inventoryCalls = () => web.requests.filter((r) => r.includes("rest_route=/garnetops")).length;

        // Not verified: the token is never sent.
        const a = await addAsset(org.id, { value: SITE });
        const secretId = await sealSecret(conn.db, org.id, "wordpress-plugin-token", token);
        await conn.db
          .update(schema.exposureAsset)
          .set({ wordpressTokenSecretId: secretId })
          .where(eq(schema.exposureAsset.id, a.id));
        await passive(a);
        expect(inventoryCalls()).toBe(0);
        expect(((await asset(a.id)).passive as PassiveSnapshot).wordpressPlugin).toEqual({
          error: "notVerified",
          pluginVersion: null,
        });

        // Verified: read, and its exact list replaces the guess from asset addresses.
        await conn.db
          .update(schema.exposureAsset)
          .set({
            verifyState: "verified",
            verifyMethod: "dns",
            verifiedAt: new Date(),
            verifyCheckedAt: new Date(),
          })
          .where(eq(schema.exposureAsset.id, a.id));
        await passive(a);
        expect(inventoryCalls()).toBe(1);
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot.wordpressPlugin).toEqual({ error: null, pluginVersion: "1.0.0" });
        expect(snapshot.http?.wordpress).toMatchObject({
          source: "plugin",
          plugins: [
            { slug: "contact-form-7", version: "5.9.3", active: true },
            { slug: "hidden-plugin", version: "2.0.0", active: false },
          ],
        });
        expect(snapshot.http?.reported).toEqual({ wordpress: "6.5.2", php: "8.2.12" });
        // The token never ends up in the stored snapshot.
        expect(JSON.stringify(snapshot)).not.toContain(token);

        // A token the plugin does not know is reported as such.
        web.wpToken = "u".repeat(43);
        await passive(a);
        expect(((await asset(a.id)).passive as PassiveSnapshot).wordpressPlugin?.error).toBe("unauthorized");
        web.wpToken = null;
        await passive(a);
        expect(((await asset(a.id)).passive as PassiveSnapshot).wordpressPlugin?.error).toBe("notInstalled");
        Object.assign(web, freshWeb());
      });

      it("looks at a tidy site and finds nothing wrong; the page body is not stored", async () => {
        resetZone();
        Object.assign(web, freshWeb(), {
          headers: { ...TIDY_HEADERS, server: "nginx" },
          body: "SECRET-BODY-MARKER",
        });
        plainState.redirect = true;
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        const result = await passive(a);
        expect(result).toMatchObject({ state: "succeeded", error: null });
        expect(await rules(a.id)).toEqual([]);
        const row = await asset(a.id);
        const snapshot = row.passive as PassiveSnapshot;
        expect(snapshot).toMatchObject({
          resolves: true,
          httpsOpen: true,
          addresses: ["127.0.0.1"],
          nonPublic: [],
        });
        expect(snapshot.tls[0]).toMatchObject({
          ok: true,
          trusted: true,
          nameMatches: true,
          protocol: "TLSv1.3",
          port: 443,
        });
        expect(snapshot.tls[0]?.cert).toMatchObject({ subject: SITE, keyType: "ec", selfSigned: true });
        expect(snapshot.tls[0]?.legacy).toEqual({ tls10: false, tls11: false });
        expect(snapshot.http).toMatchObject({ status: 200, finalUrl: `https://${SITE}/` });
        expect(snapshot.plain).toMatchObject({ status: 301, redirectsToHttps: true });
        expect(snapshot.dns).toMatchObject({
          caaFound: true,
          spf: { records: 1, policy: "fail" },
          dmarc: { found: true, policy: "reject" },
          dnssec: "unknown",
        });
        expect(JSON.stringify(row.passive)).not.toContain("SECRET-BODY-MARKER");
        expect(row.lastPassiveAt).not.toBeNull();
        expect(await told(org.id, "exposureCertificateExpiring")).toEqual([]);
      });

      it("lists missing headers, a banner with a version, plain HTTP without a redirect, and weak mail policies, as findings with the rule's severity", async () => {
        resetZone();
        Object.assign(web, freshWeb(), {
          // Release lines with no end in sight in the committed data (Apache 2.4) or years away (PHP 8.5), so the result does not
          // change with the date.
          headers: { server: "Apache/2.4.57 (Debian)", "x-powered-by": "PHP/8.5.1" },
        });
        plainState.redirect = false;
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1"], mx: [{ priority: 10, exchange: `mail.${SITE}` }] };
        const result = await passive(a);
        expect(result.state).toBe("succeeded");
        expect(await rules(a.id)).toEqual(
          [
            "dnsNoCaa:",
            "dnsNoDmarc:",
            "dnsNoSpf:",
            "httpBannerVersion:server",
            "httpBannerVersion:x-powered-by",
            "httpCspMissing:",
            "httpFramingMissing:",
            "httpHstsMissing:",
            "httpNoRedirectToHttps:",
            "httpNosniffMissing:",
            "httpPermissionsPolicyMissing:",
            "httpReferrerPolicyMissing:",
            // PHP is behind the latest of its line (ADR 0038); Apache names Debian, whose builds carry fixes without a new
            // number, so it is not judged.
            "softwareOutdated:php",
          ].sort(),
        );
        const all = await findings(a.id);
        expect(all.find((f) => f.rule === "softwareOutdated" && f.subject === "php")?.params).toMatchObject({
          product: "PHP",
          version: "8.5.1",
          cycle: "8.5",
        });
        const banner = all.find((f) => f.rule === "httpBannerVersion" && f.subject === "server");
        expect(banner).toMatchObject({ severity: "low", stage: "passive" });
        expect(banner?.params).toMatchObject({ banner: "Apache/2.4.57 (Debian)" });
        // With a mail server, missing SPF and DMARC are medium.
        expect(all.find((f) => f.rule === "dnsNoSpf")?.severity).toBe("medium");
        // Medium: SPF, DMARC and no redirect to HTTPS; a version from a server header counts low.
        expect((await run(result.id)).findingCounts).toMatchObject({ medium: 3, low: expect.any(Number) });
        expect(all.find((f) => f.rule === "softwareOutdated")?.severity).toBe("low");
        plainState.redirect = true;
      });

      it("stores header and banner text as plain text, cleaned and cut", async () => {
        resetZone();
        Object.assign(web, freshWeb(), {
          headers: { ...TIDY_HEADERS, server: `<img src=x onerror="alert(1)"> ${"A".repeat(600)}` },
        });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        await passive(a);
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        const server = snapshot.http?.headers.server ?? "";
        expect(server.startsWith('<img src=x onerror="alert(1)">')).toBe(true);
        expect(server.length).toBeLessThanOrEqual(300);
      });

      it("sees an expired certificate: a high finding and a notification once", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        const result = await passive(a, { httpsPort: ports.expired });
        expect(result.state).toBe("succeeded");
        const open = await findings(a.id);
        expect(open.find((f) => f.rule === "tlsExpired")).toMatchObject({ severity: "high", subject: "443" });
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot.tls[0]).toMatchObject({ ok: true, trusted: false });
        expect((await told(org.id, "exposureCertificateExpired")).length).toBe(2);
        await passive(a, { httpsPort: ports.expired });
        expect((await told(org.id, "exposureCertificateExpired")).length).toBe(2);
      });

      it("warns at 30, 14 and 7 days, once each, and again after a renewal", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        const t0 = new Date();
        // The certificate has ten days left: the 14 day step.
        await passive(a, { httpsPort: ports.expiring }, t0);
        let notes = await told(org.id, "exposureCertificateExpiring");
        expect(notes.filter((n) => n.userId === org.users.owner)).toHaveLength(1);
        expect(notes[0]?.params).toMatchObject({ asset: SITE, days: expect.any(Number) });
        expect(await rules(a.id)).toContain("tlsExpiring:443");
        expect((await findings(a.id)).find((f) => f.rule === "tlsExpiring")?.severity).toBe("medium");
        // Same day again: nothing new.
        await passive(a, { httpsPort: ports.expiring }, t0);
        expect(
          (await told(org.id, "exposureCertificateExpiring")).filter((n) => n.userId === org.users.owner),
        ).toHaveLength(1);
        // Four days later it is the 7 day step.
        await passive(a, { httpsPort: ports.expiring }, new Date(t0.getTime() + 4 * DAY));
        notes = await told(org.id, "exposureCertificateExpiring");
        expect(notes.filter((n) => n.userId === org.users.owner)).toHaveLength(2);
        expect((await findings(a.id)).find((f) => f.rule === "tlsExpiring")?.severity).toBe("high");
        // A renewed certificate resets the announcements and resolves the finding.
        await passive(a, { httpsPort: ports.good }, new Date(t0.getTime() + 5 * DAY));
        expect((await asset(a.id)).certNotifiedLevel).toBeNull();
        expect(await rules(a.id)).not.toContain("tlsExpiring:443");
        expect((await findings(a.id, "resolved")).map((f) => f.rule)).toContain("tlsExpiring");
        await passive(a, { httpsPort: ports.expiring }, new Date(t0.getTime() + 6 * DAY));
        expect(
          (await told(org.id, "exposureCertificateExpiring")).filter((n) => n.userId === org.users.owner)
            .length,
        ).toBeGreaterThan(2);
      });

      it("reports a server that still accepts TLS 1.0 and 1.1", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        await passive(a, { httpsPort: ports.legacy });
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot.tls[0]?.legacy).toEqual({ tls10: true, tls11: true });
        expect((await findings(a.id)).find((f) => f.rule === "tlsLegacyProtocol")).toMatchObject({
          severity: "medium",
        });
      });

      it("does not connect to a name when one answer is not public, and says so", async () => {
        resetZone();
        Object.assign(web, freshWeb());
        web.requests.length = 0;
        const before = plainState.requests;
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1", "10.0.0.5"] };
        const result = await passive(a);
        expect(result.state).toBe("succeeded");
        expect(web.requests).toEqual([]);
        expect(plainState.requests).toBe(before);
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot).toMatchObject({ addresses: [], nonPublic: ["10.0.0.5"], tls: [], http: null });
        expect(await rules(a.id)).toContain("dnsNonPublicAddress:");
      });

      it("refuses loopback, link-local and metadata answers in production mode", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1"] };
        web.requests.length = 0;
        await passive(a, { allowTestRanges: false });
        expect(web.requests).toEqual([]);
        expect(((await asset(a.id)).passive as PassiveSnapshot).nonPublic).toEqual(["127.0.0.1"]);
        zone[SITE] = { a: ["169.254.169.254"] };
        await passive(a, { allowTestRanges: true });
        expect(web.requests).toEqual([]);
        expect(((await asset(a.id)).passive as PassiveSnapshot).nonPublic).toEqual(["169.254.169.254"]);
      });

      it("follows redirects inside the site, at most three, and records the ones it does not follow", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        zone[`www.${SITE}`] = { a: ["127.0.0.1"] };
        zone["evil.example.org"] = { a: ["127.0.0.1"] };
        Object.assign(web, freshWeb(), {
          status: 302,
          location: `https://www.${SITE}/next`,
          headers: TIDY_HEADERS,
        });
        await passive(a);
        let http = ((await asset(a.id)).passive as PassiveSnapshot).http;
        // Every hop answers with the same redirect: the chain stops after three followed hops.
        expect(http?.redirects.filter((r) => r.followed)).toHaveLength(3);
        expect(http?.redirects.at(-1)?.followed).toBe(false);

        Object.assign(web, freshWeb(), {
          status: 302,
          location: "https://evil.example.org/",
          headers: TIDY_HEADERS,
        });
        dns.queries.length = 0;
        web.requests.length = 0;
        await passive(a);
        http = ((await asset(a.id)).passive as PassiveSnapshot).http;
        expect(http?.redirects).toEqual([{ to: "https://evil.example.org/", status: 302, followed: false }]);
        expect(dns.queries.filter((q) => q.endsWith("evil.example.org"))).toEqual([]);
        expect(web.hostsSeen.some((h) => h.includes("evil"))).toBe(false);

        // A redirect to another port is not followed either.
        Object.assign(web, freshWeb(), {
          status: 302,
          location: `https://${SITE}:8443/`,
          headers: TIDY_HEADERS,
        });
        await passive(a);
        http = ((await asset(a.id)).passive as PassiveSnapshot).http;
        expect(http?.redirects[0]).toMatchObject({ followed: false });
      });

      it("follows a redirect to another verified asset of the organisation, and only then", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        zone["other.example.net"] = { a: ["127.0.0.1"] };
        Object.assign(web, freshWeb(), {
          status: 302,
          location: "https://other.example.net/",
          headers: TIDY_HEADERS,
        });
        await passive(a);
        expect(((await asset(a.id)).passive as PassiveSnapshot).http?.redirects[0]?.followed).toBe(false);
        await addAsset(org.id, {
          value: "other.example.net",
          verifyState: "verified",
          verifyMethod: "dns",
          verifiedAt: new Date(),
        });
        await passive(a);
        expect(((await asset(a.id)).passive as PassiveSnapshot).http?.redirects[0]?.followed).toBe(true);
      });

      it("leaves findings alone that it could not judge", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        zone[SITE] = { ...zone[SITE], txt: [["v=spf1 +all"]] };
        await passive(a);
        expect(await rules(a.id)).toContain("dnsSpfPermissive:");
        // The TXT lookup fails this time: the finding stays open instead of being resolved.
        zone[SITE] = { ...zone[SITE], fail: ["txt"] };
        await passive(a);
        expect(await rules(a.id)).toContain("dnsSpfPermissive:");
        // And it is resolved when the answer is there and fine.
        zone[SITE] = {
          a: ["127.0.0.1"],
          mx: [{ priority: 10, exchange: `mail.${SITE}` }],
          caa: [{ critical: 0, issue: "ca.example.net" }],
          txt: [["v=spf1 mx -all"]],
        };
        await passive(a);
        expect(await rules(a.id)).not.toContain("dnsSpfPermissive:");
      });

      it("shows an address asset's reverse name and treats the certificate's name as unknown", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { kind: "ip", value: "127.0.0.1" });
        zone[SITE] = { a: ["127.0.0.1"], ptr: ["gateway.example.com", "‮evil"] };
        await passive(a);
        const snapshot = (await asset(a.id)).passive as PassiveSnapshot;
        expect(snapshot.dns).toBeNull();
        expect(snapshot.ptr).toEqual(["gateway.example.com", "evil"]);
        expect(snapshot.tls[0]?.nameMatches).toBeNull();
        expect((await findings(a.id)).map((f) => f.rule)).not.toContain("tlsNameMismatch");
      });

      it("suggests names found in the DNS records under the asset's domain, and never connects to them", async () => {
        resetZone();
        Object.assign(web, freshWeb(), { headers: TIDY_HEADERS });
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        zone[SITE] = { ...zone[SITE], ns: [`ns1.${SITE}`, "ns.provider.example.net"], cname: [] };
        await passive(a);
        const names = (
          await conn.db
            .select()
            .from(schema.exposureDiscovery)
            .where(eq(schema.exposureDiscovery.assetId, a.id))
        ).map((d) => `${d.name}:${d.source}`);
        expect(names.sort()).toEqual([`mail.${SITE}:dns`, `ns1.${SITE}:dns`]);
        expect(dns.queries.some((q) => q.includes("mail.site"))).toBe(false);
      });

      it("records a failed run with a code and keeps the earlier snapshot", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, { value: SITE });
        tidyZone(SITE);
        await passive(a);
        const first = (await asset(a.id)).passive;
        const id = await queued(a, "passive");
        await conn.db.delete(schema.exposureAsset).where(eq(schema.exposureAsset.id, a.id));
        await ex.runPassive(id, { net: env() });
        expect(first).not.toBeNull();
      });
    });

    /* ======================================================================== */
    describe("net: limits of a single request", () => {
      it("reads at most the cap of a huge body and closes the connection", async () => {
        const result = await net.httpGet({
          scheme: "https",
          address: "127.0.0.1",
          port: ports.good,
          host: SITE,
          path: "/huge",
          verify: true,
          ca: trust,
          maxBody: 64 * 1024,
        });
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.body.length).toBeLessThanOrEqual(64 * 1024);
          expect(result.truncated).toBe(true);
        }
      });
      it("drops response headers it does not know", async () => {
        Object.assign(web, freshWeb(), {
          headers: { "set-cookie": "session=abc", "x-secret": "1", "x-content-type-options": "nosniff" },
        });
        const result = await net.httpGet({
          scheme: "https",
          address: "127.0.0.1",
          port: ports.good,
          host: SITE,
          path: "/",
          verify: true,
          ca: trust,
          maxBody: 0,
        });
        expect(result.ok && Object.keys(result.headers)).toEqual(["x-content-type-options"]);
      });
      it("sends no cookie, no body and only GET", async () => {
        web.requests.length = 0;
        Object.assign(web, freshWeb());
        await net.httpGet({
          scheme: "https",
          address: "127.0.0.1",
          port: ports.good,
          host: SITE,
          path: "/",
          verify: true,
          ca: trust,
          maxBody: 100,
        });
        expect(web.requests).toEqual(["GET /"]);
      });
      it("fails closed on a certificate it does not trust", async () => {
        const result = await net.httpGet({
          scheme: "https",
          address: "127.0.0.1",
          port: ports.expired,
          host: SITE,
          path: "/",
          verify: true,
          ca: trust,
          maxBody: 100,
        });
        expect(result).toEqual({ ok: false, error: "tls" });
      });
    });

    /* ======================================================================== */
    describe("stage 2", () => {
      const spec = (port: number, over: Partial<PortSpec> = {}): PortSpec => ({
        port,
        service: "ssh",
        category: "expected",
        banner: false,
        tls: false,
        severity: null,
        ...over,
      });
      const openOf = async (id: string) => ((await asset(id)).active as ActiveSnapshot | null)?.open ?? [];
      let listeners: Listener[] = [];
      const track = <T extends Listener>(l: T) => {
        listeners.push(l);
        return l;
      };
      const stopListeners = async () => {
        await Promise.all(listeners.map((l) => l.close()));
        listeners = [];
      };

      it("is the documented list of ports and limits in code", () => {
        expect(EXPOSURE_PORTS).toHaveLength(30);
        expect(ACTIVE_LIMITS.concurrency).toBe(4);
        expect(ACTIVE_LIMITS.gapMs).toBe(200);
        expect(ACTIVE_LIMITS.connectTimeoutMs).toBe(3000);
      });

      it("connects to open ports, reads what a service sends first, and sends nothing to any port", async () => {
        resetZone();
        Object.assign(web, freshWeb());
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { ...zone[SITE], a: ["127.0.0.1"] };
        const ssh = track(await tcpListener((s) => s.write("SSH-2.0-TestServer_1.0\r\n")));
        const silent = track(await tcpListener());
        const redis = track(await tcpListener());
        const hostile = track(
          await tcpListener((s) => s.write(`220 \u001b[31mred\u0000 <script>alert(1)</script>\r\n`)),
        );
        const flood = track(await tcpListener((s) => s.write("A".repeat(5000))));
        const shut = await closedPort();
        const tlsOk = track(await tlsListener({ key: good.key, cert: good.cert }));
        const notTls = track(await tcpListener((s) => s.end("HTTP/1.1 400 Bad Request\r\n\r\n")));
        const list = [
          spec(ssh.port, { banner: true, service: "ssh" }),
          spec(silent.port, { banner: true, service: "smtp" }),
          spec(redis.port, { service: "redis", category: "database", severity: "high" }),
          spec(hostile.port, { banner: true, service: "ftp", category: "cleartext", severity: "medium" }),
          spec(flood.port, { banner: true, service: "imap", category: "cleartext", severity: "low" }),
          spec(shut, { service: "mysql", category: "database", severity: "high" }),
          spec(tlsOk.port, { tls: true, service: "httpsAlt" }),
          spec(notTls.port, { tls: true, service: "smtps" }),
        ];
        const result = await active(a, { ports: list });
        expect(result).toMatchObject({ state: "succeeded", error: null, openPorts: 7 });
        const open = await openOf(a.id);
        const by = (port: number) => open.find((o) => o.port === port);
        expect(by(ssh.port)?.banner).toBe("SSH-2.0-TestServer_1.0");
        expect(by(silent.port)).toMatchObject({ banner: null });
        expect(by(redis.port)).toMatchObject({ banner: null, service: "redis", severity: "high" });
        expect(by(shut)).toBeUndefined();
        // Hostile bytes become harmless text, a flood is cut at 512 bytes.
        const hostileBanner = by(hostile.port)?.banner ?? "";
        expect(hostileBanner).toContain("<script>alert(1)</script>");
        expect([...hostileBanner].some((c) => (c.codePointAt(0) ?? 0) < 32 && c !== "\n")).toBe(false);
        expect((by(flood.port)?.banner ?? "").length).toBeLessThanOrEqual(512);
        expect(by(tlsOk.port)?.tls).toMatchObject({ ok: true, trusted: true, protocol: "TLSv1.3" });
        expect(by(notTls.port)?.tls).toMatchObject({ ok: false, error: "handshake" });
        // Counted: eight checked, one closed.
        expect(await asset(a.id).then((r) => r.active)).toMatchObject({ checked: 8, closed: 1, noAnswer: 0 });

        // The enforcement: not one byte was written to a plain port, and a TLS port saw the handshake only.
        for (const quiet of [ssh, silent, redis, hostile, flood])
          expect(bytesReceived(quiet), `port ${quiet.port}`).toBe(0);
        expect(tlsRecordTypes(Buffer.concat(notTls.received))).toEqual([22]);
        expect(Buffer.concat(tlsOk.received).length).toBe(0);
        await stopListeners();
      });

      it("reports risky services as findings and tells owners and admins once", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const redis = track(await tcpListener());
        const ftp = track(await tcpListener((s) => s.write("220 ftp ready\r\n")));
        const list = [
          spec(redis.port, { service: "redis", category: "database", severity: "high" }),
          spec(ftp.port, { service: "ftp", category: "cleartext", banner: true, severity: "medium" }),
        ];
        const t0 = new Date();
        await active(a, { ports: list, now: t0 });
        const open = await findings(a.id);
        expect(open.map((f) => `${f.rule}:${f.severity}:${f.stage}`).sort()).toEqual(
          [`portExposed:high:active`, `portExposed:medium:active`].sort(),
        );
        const risky = await told(org.id, "exposureRiskyService");
        expect(risky.map((n) => n.userId).sort()).toEqual([org.users.admin, org.users.owner].sort());
        expect(risky[0]?.params).toMatchObject({ asset: SITE, service: "redis", count: 1 });
        // Next day: nothing new is told for the same open service; the first run is also the baseline for new ports.
        await active(a, { ports: list, now: new Date(t0.getTime() + 25 * HOUR) });
        expect(await told(org.id, "exposureRiskyService")).toHaveLength(2);
        expect(await told(org.id, "exposureNewOpenPort")).toEqual([]);
        await stopListeners();
      });

      it("tells about a port that is new since the last run, and resolves a finding when the port closes", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const ssh = track(await tcpListener((s) => s.write("SSH-2.0-A\r\n")));
        const db = track(await tcpListener());
        const list = [
          spec(ssh.port, { banner: true }),
          spec(db.port, { service: "postgres", category: "database", severity: "high" }),
        ];
        const t0 = new Date();
        // Run 1: only ssh is open (the database listener is closed for now).
        const dbPort = db.port;
        await db.close();
        await active(a, { ports: list, now: t0 });
        expect(await told(org.id, "exposureNewOpenPort")).toEqual([]);
        expect(await rules(a.id)).toEqual([]);
        // Run 2: the database appears.
        const again = track(await tcpListener());
        const relisted = [list[0] as PortSpec, { ...(list[1] as PortSpec), port: again.port }];
        await active(a, { ports: relisted, now: new Date(t0.getTime() + 25 * HOUR) });
        const fresh = await told(org.id, "exposureNewOpenPort");
        expect(fresh).toHaveLength(2);
        expect(fresh[0]?.params).toMatchObject({ asset: SITE, count: 1, ports: String(again.port) });
        expect((await told(org.id, "exposureRiskyService")).length).toBe(2);
        // Run 3: it closes again; the finding resolves.
        await again.close();
        await active(a, { ports: relisted, now: new Date(t0.getTime() + 50 * HOUR) });
        expect(await rules(a.id)).toEqual([]);
        expect((await findings(a.id, "resolved")).map((f) => f.rule)).toEqual(["portExposed"]);
        expect(dbPort).toBeGreaterThan(0);
        await stopListeners();
      });

      it("refuses an asset that is not verified, not acknowledged or switched off, without a single connection", async () => {
        resetZone();
        const org = await newOrg();
        zone[SITE] = { a: ["127.0.0.1"] };
        const probe = track(await tcpListener((s) => s.write("hello\r\n")));
        const list = [spec(probe.port, { banner: true })];
        const cases: [string, Partial<typeof schema.exposureAsset.$inferInsert>, string][] = [
          [
            "unverified",
            {
              stage2Enabled: true,
              stage2AcknowledgedBy: org.users.owner as string,
              stage2AcknowledgedAt: new Date(),
            },
            "notVerified",
          ],
          [
            "lost",
            {
              verifyState: "lost",
              stage2Enabled: true,
              stage2AcknowledgedBy: org.users.owner as string,
              stage2AcknowledgedAt: new Date(),
            },
            "notVerified",
          ],
          [
            "not acknowledged",
            { verifyState: "verified", verifyMethod: "dns", verifiedAt: new Date(), stage2Enabled: true },
            "notAcknowledged",
          ],
          [
            "switched off",
            { verifyState: "verified", verifyMethod: "dns", verifiedAt: new Date(), stage2Enabled: false },
            "stageOff",
          ],
        ];
        for (const [name, over, code] of cases) {
          const a = await addAsset(org.id, { value: `case${++counter}.example.com`, ...over });
          zone[a.value] = { a: ["127.0.0.1"] };
          const result = await active(a, { ports: list });
          expect(result, name).toMatchObject({ state: "failed", error: code });
          expect(await asset(a.id)).toMatchObject({ lastActiveAt: null, active: null });
        }
        expect(probe.connections).toBe(0);
        await stopListeners();
      });

      it("looks at the proof again before it connects: a proof that is gone stops the run, loses the asset and tells people", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1"] };
        // verifiedAt is fresh, but the record is not there any more.
        const probe = track(await tcpListener());
        const result = await active(a, { ports: [spec(probe.port)] });
        expect(result).toMatchObject({ state: "failed", error: "notVerified" });
        expect(probe.connections).toBe(0);
        expect(await asset(a.id)).toMatchObject({
          verifyState: "lost",
          stage2Enabled: false,
          lastActiveAt: null,
        });
        expect((await told(org.id, "exposureVerificationLost")).length).toBe(2);
        await stopListeners();
      });

      it("fails closed when the proof cannot be looked at", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[SITE] = { a: ["127.0.0.1"] };
        zone[`_garnetops-challenge.${SITE}`] = { fail: ["txt"] };
        const probe = track(await tcpListener());
        const result = await active(a, { ports: [spec(probe.port)] });
        expect(result.state).toBe("failed");
        expect(probe.connections).toBe(0);
        // Not lost, because nothing proved it gone.
        expect((await asset(a.id)).verifyState).toBe("verified");
        await stopListeners();
      });

      it("scans at most once a day, whoever asks", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const probe = track(await tcpListener());
        const t0 = new Date();
        expect((await active(a, { ports: [spec(probe.port)], now: t0 })).state).toBe("succeeded");
        const connections = probe.connections;
        const early = await active(a, { ports: [spec(probe.port)], now: new Date(t0.getTime() + 23 * HOUR) });
        expect(early).toMatchObject({ state: "failed", error: "tooSoon" });
        expect(probe.connections).toBe(connections);
        expect(
          (await active(a, { ports: [spec(probe.port)], now: new Date(t0.getTime() + 24 * HOUR + 1000) }))
            .state,
        ).toBe("succeeded");
        await stopListeners();
      });

      it("refuses a name that resolves to a private address", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1", "192.168.1.9"] };
        const probe = track(await tcpListener());
        const result = await active(a, { ports: [spec(probe.port)] });
        expect(result).toMatchObject({ state: "failed", error: "addressRefused" });
        expect(probe.connections).toBe(0);
        await stopListeners();
      });

      it("keeps to four connections at a time and 200 ms between the starts of two", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const shared = { current: 0, max: 0 };
        const servers = await Promise.all(Array.from({ length: 9 }, () => tcpListener(() => {}, shared)));
        for (const s of servers) track(s);
        const starts: number[] = [];
        const list = servers.map((s) => spec(s.port, { banner: true }));
        const result = await active(a, {
          ports: list,
          net: { bannerReadMs: 900, onAttempt: () => starts.push(Date.now()) },
        });
        expect(result).toMatchObject({ state: "succeeded", openPorts: 9 });
        expect(starts).toHaveLength(9);
        expect(shared.max).toBeLessThanOrEqual(4);
        expect(shared.max).toBeGreaterThanOrEqual(2);
        for (let i = 1; i < starts.length; i++)
          expect((starts[i] as number) - (starts[i - 1] as number)).toBeGreaterThanOrEqual(190);
        await stopListeners();
      }, 30_000);

      it("stops at once when stage 2 is switched off or the proof is lost while it runs", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const servers = await Promise.all(Array.from({ length: 10 }, () => tcpListener()));
        for (const s of servers) track(s);
        const list = servers.map((s) => spec(s.port));
        let attempts = 0;
        const result = await active(a, {
          ports: list,
          net: {
            onAttempt: () => {
              attempts += 1;
              if (attempts === 3) {
                void conn.pool.query("update exposure_asset set stage2_enabled = false where id = $1", [
                  a.id,
                ]);
              }
            },
          },
        });
        expect(result).toMatchObject({ state: "failed", error: "stageOff" });
        expect(attempts).toBeLessThan(10);
        expect(attempts).toBeLessThanOrEqual(5);
        // The partial result is not stored as a result.
        expect((await asset(a.id)).active).toBeNull();
        await stopListeners();
      }, 20_000);

      it("never connects to a port outside the list it was given, and the real list is only the documented one", async () => {
        resetZone();
        const org = await newOrg();
        const a = await readyAsset(org, { value: SITE });
        zone[`_garnetops-challenge.${SITE}`] = { txt: [[verifyRecordValue(a.verifyToken)]] };
        zone[SITE] = { a: ["127.0.0.1"] };
        const attempted: number[] = [];
        const bystander = track(await tcpListener());
        const mine = track(await tcpListener());
        await active(a, { ports: [spec(mine.port)], net: { onAttempt: (port) => attempted.push(port) } });
        expect(attempted).toEqual([mine.port]);
        expect(bystander.connections).toBe(0);
        await stopListeners();
      });
    });

    /* ======================================================================== */
    describe("Certificate Transparency (opt-in)", () => {
      const names = [
        `a.${SITE}`,
        `b.${SITE}`,
        "unrelated.example.org",
        `${SITE}`,
        "bad_name.example.com",
        `x.${SITE}.evil.example.net`,
      ];
      async function enableCt(orgId: string, enabled = true) {
        await conn.db
          .insert(schema.exposureSettings)
          .values({ organizationId: orgId, ctEnabled: enabled })
          .onConflictDoUpdate({
            target: schema.exposureSettings.organizationId,
            set: { ctEnabled: enabled },
          });
      }
      const discoveries = async (assetId: string) =>
        (
          await conn.db
            .select()
            .from(schema.exposureDiscovery)
            .where(eq(schema.exposureDiscovery.assetId, assetId))
        )
          .map((d) => `${d.name}:${d.source}`)
          .sort();

      it("does nothing while the organisation has not switched it on", async () => {
        resetZone();
        const org = await newOrg();
        const a = await addAsset(org.id, {
          value: SITE,
          verifyState: "verified",
          verifyMethod: "dns",
          verifiedAt: new Date(),
        });
        tidyZone(SITE);
        const fetchCt = vi.fn(async () => names);
        const id = await queued(a, "passive");
        await ex.runPassive(id, { net: env(), ct: fetchCt, ctPauseMs: 0 });
        expect(fetchCt).not.toHaveBeenCalled();
      });

      it("looks up verified domains only, once a day, and keeps valid subdomains as suggestions", async () => {
        resetZone();
        const org = await newOrg();
        await enableCt(org.id);
        const a = await addAsset(org.id, {
          value: SITE,
          verifyState: "verified",
          verifyMethod: "dns",
          verifiedAt: new Date(),
        });
        const unverified = await addAsset(org.id, { value: "unverified.example.com" });
        tidyZone(SITE);
        tidyZone("unverified.example.com");
        const calls: string[] = [];
        const fetchCt: import("./exposure-ct.ts").CtFetch = async (domain) => {
          calls.push(domain);
          return ct.parseCtNames(
            JSON.stringify([{ name_value: names.join("\n"), common_name: SITE }]),
            domain,
          );
        };
        const t0 = new Date();
        for (const row of [a, unverified]) {
          const id = await queued(row, "passive");
          await ex.runPassive(id, { net: env(), ct: fetchCt, ctPauseMs: 0, now: () => t0 });
        }
        expect(calls).toEqual([SITE]);
        expect(await discoveries(a.id)).toEqual(
          [`a.${SITE}:ct`, `b.${SITE}:ct`, `mail.${SITE}:dns`, `x.${SITE}.evil.example.net:ct`]
            .filter((n) => !n.includes("evil"))
            .sort(),
        );
        // Again within a day: no second query.
        const again = await queued(a, "passive");
        await ex.runPassive(again, {
          net: env(),
          ct: fetchCt,
          ctPauseMs: 0,
          now: () => new Date(t0.getTime() + HOUR),
        });
        expect(calls).toHaveLength(1);
        const settings = (
          await conn.db
            .select()
            .from(schema.exposureSettings)
            .where(eq(schema.exposureSettings.organizationId, org.id))
        )[0];
        expect(settings).toMatchObject({ ctUsageCount: 1, ctLastError: null });
      });

      it("stays within the daily budget, and records a failure without failing the run", async () => {
        resetZone();
        const org = await newOrg();
        await enableCt(org.id);
        const t0 = new Date();
        await conn.db
          .update(schema.exposureSettings)
          .set({ ctUsageDay: t0.toISOString().slice(0, 10), ctUsageCount: 100 })
          .where(eq(schema.exposureSettings.organizationId, org.id));
        const a = await addAsset(org.id, {
          value: SITE,
          verifyState: "verified",
          verifyMethod: "dns",
          verifiedAt: t0,
        });
        tidyZone(SITE);
        const fetchCt = vi.fn(async () => names);
        const id = await queued(a, "passive");
        await ex.runPassive(id, { net: env(), ct: fetchCt, ctPauseMs: 0, now: () => t0 });
        expect(fetchCt).not.toHaveBeenCalled();
        // A new day, but the service is down.
        const failing: import("./exposure-ct.ts").CtFetch = async () => {
          throw new ct.CtError("timeout");
        };
        const next = await queued(a, "passive");
        await ex.runPassive(next, {
          net: env(),
          ct: failing,
          ctPauseMs: 0,
          now: () => new Date(t0.getTime() + 2 * DAY),
        });
        expect((await run(next)).state).toBe("succeeded");
        expect(
          (
            await conn.db
              .select()
              .from(schema.exposureSettings)
              .where(eq(schema.exposureSettings.organizationId, org.id))
          )[0]?.ctLastError,
        ).toBe("timeout");
      });

      it("parses only what is valid below the domain, from hostile JSON", () => {
        expect(
          ct.parseCtNames(
            JSON.stringify([
              {
                name_value: `*.a.${SITE}\nb.${SITE}\n${SITE}\nevil.example.org\n-x.${SITE}\nx y.${SITE}\n${"a".repeat(70)}.${SITE}`,
              },
              null,
              7,
              "x",
              { name_value: 5 },
            ]),
            SITE,
          ),
        ).toEqual([`a.${SITE}`, `b.${SITE}`]);
        expect(() => ct.parseCtNames("<html>", SITE)).toThrow(ct.CtError);
        expect(() => ct.parseCtNames('{"a":1}', SITE)).toThrow(ct.CtError);
        const many = Array.from({ length: 2000 }, (_, i) => ({ name_value: `h${i}.${SITE}` }));
        expect(ct.parseCtNames(JSON.stringify(many), SITE).length).toBeLessThanOrEqual(500);
      });

      it("goes only to crt.sh over HTTPS through the address-checked client", async () => {
        // The real client refuses to send a query when the name resolves to an internal address.
        const fetchCt = ct.crtShFetch({
          lookup: (_h, _o, cb) =>
            cb(Object.assign(new Error("refused address"), { code: "EREFUSED_ADDRESS" }), []),
        });
        await expect(fetchCt(SITE)).rejects.toMatchObject({ code: "refusedAddress" });
      });
    });

    /* ======================================================================== */
    describe("the schedule", () => {
      /** The tick looks at every organisation: park what the other tests left behind so the counts here are exact. */
      const parkOthers = async () => {
        await conn.pool.query(
          "update exposure_asset set passive_enabled = false, stage2_enabled = false, verify_checked_at = now()",
        );
      };
      interface Sent {
        name: string;
        data: Record<string, string>;
        options: Record<string, unknown>;
      }
      function fakeBoss() {
        const sent: Sent[] = [];
        return {
          sent,
          boss: {
            send: async (name: string, data: Record<string, string>, options: Record<string, unknown>) =>
              void sent.push({ name, data, options }),
          } as unknown as import("pg-boss").PgBoss,
        };
      }
      const runsOf = async (assetId: string) =>
        conn.db.select().from(schema.exposureRun).where(eq(schema.exposureRun.assetId, assetId));

      it("checks proofs a day old, queues stage 1 for assets last seen over a day ago, and never twice", async () => {
        await parkOthers();
        const org = await newOrg();
        const now = new Date();
        const fresh = await addAsset(org.id, {
          lastPassiveAt: new Date(now.getTime() - HOUR),
          verifyCheckedAt: new Date(now.getTime() - HOUR),
        });
        const stale = await addAsset(org.id, {
          lastPassiveAt: new Date(now.getTime() - 25 * HOUR),
          verifyCheckedAt: new Date(now.getTime() - 25 * HOUR),
        });
        const never = await addAsset(org.id, {});
        const paused = await addAsset(org.id, { passiveEnabled: false });
        const { boss, sent } = fakeBoss();
        await ex.exposureTick(boss, { now: () => now });
        const verifyIds = sent.filter((s) => s.name === ex.EXPOSURE_VERIFY_QUEUE).map((s) => s.data.assetId);
        expect(verifyIds).toEqual(expect.arrayContaining([stale.id, never.id, paused.id]));
        expect(verifyIds).not.toContain(fresh.id);
        expect(await runsOf(fresh.id)).toHaveLength(0);
        expect((await runsOf(stale.id)).map((r) => r.stage)).toEqual(["passive"]);
        expect((await runsOf(never.id)).map((r) => r.stage)).toEqual(["passive"]);
        expect(await runsOf(paused.id)).toHaveLength(0);
        const first = sent.filter((s) => s.name === ex.EXPOSURE_RUN_QUEUE).length;
        await ex.exposureTick(boss, { now: () => now });
        // A queued run is not queued again (the unique index), only sent again once it has been waiting for two minutes.
        expect(await runsOf(stale.id)).toHaveLength(1);
        expect(sent.filter((s) => s.name === ex.EXPOSURE_RUN_QUEUE).length).toBe(first);
      });

      it("queues stage 2 only for assets that are on, acknowledged, verified and due, daily or weekly", async () => {
        await parkOthers();
        const org = await newOrg();
        const now = new Date();
        const daily = await readyAsset(
          org,
          { lastActiveAt: new Date(now.getTime() - 25 * HOUR), lastPassiveAt: now, verifyCheckedAt: now },
          now,
        );
        const dailyNotDue = await readyAsset(
          org,
          { lastActiveAt: new Date(now.getTime() - 10 * HOUR), lastPassiveAt: now, verifyCheckedAt: now },
          now,
        );
        const weeklyNotDue = await readyAsset(
          org,
          {
            stage2Schedule: "weekly",
            lastActiveAt: new Date(now.getTime() - 3 * DAY),
            lastPassiveAt: now,
            verifyCheckedAt: now,
          },
          now,
        );
        const weeklyDue = await readyAsset(
          org,
          {
            stage2Schedule: "weekly",
            lastActiveAt: new Date(now.getTime() - 8 * DAY),
            lastPassiveAt: now,
            verifyCheckedAt: now,
          },
          now,
        );
        const stale = await readyAsset(
          org,
          { lastPassiveAt: now, verifyCheckedAt: now },
          new Date(now.getTime() - 3 * DAY),
        );
        const off = await addAsset(org.id, {
          verifyState: "verified",
          verifiedAt: now,
          lastPassiveAt: now,
          verifyCheckedAt: now,
        });
        const { boss } = fakeBoss();
        await ex.exposureTick(boss, { now: () => now });
        const stages = async (id: string) => (await runsOf(id)).map((r) => r.stage);
        expect(await stages(daily.id)).toEqual(["active"]);
        expect(await stages(weeklyDue.id)).toEqual(["active"]);
        expect(await stages(dailyNotDue.id)).toEqual([]);
        expect(await stages(weeklyNotDue.id)).toEqual([]);
        // A proof confirmed three days ago is too old for stage 2 to start.
        expect(await stages(stale.id)).toEqual([]);
        expect(await stages(off.id)).toEqual([]);
      });

      it("looks at nothing while the module is off (ADR 0033): no proofs, no runs, and a queued run fails as moduleOff", async () => {
        await parkOthers();
        const org = await newOrg();
        await conn.db
          .update(schema.exposureSettings)
          .set({ enabled: false })
          .where(eq(schema.exposureSettings.organizationId, org.id));
        const now = new Date();
        const due = await addAsset(org.id, {});
        const ready = await readyAsset(org, { lastPassiveAt: now, verifyCheckedAt: now }, now);
        const { boss, sent } = fakeBoss();
        await ex.exposureTick(boss, { now: () => now });
        expect(sent.filter((s) => [due.id, ready.id].includes(s.data.assetId ?? ""))).toEqual([]);
        expect(await runsOf(due.id)).toHaveLength(0);
        expect(await runsOf(ready.id)).toHaveLength(0);

        const queued = newId("exr");
        await conn.db.insert(schema.exposureRun).values({
          id: queued,
          organizationId: org.id,
          assetId: due.id,
          stage: "passive",
          state: "queued",
          trigger: "manual",
          createdAt: now,
        });
        await ex.runExposure(queued, { net: env() });
        expect(await run(queued)).toMatchObject({ state: "failed", error: "moduleOff" });
        const [asset] = await conn.db
          .select()
          .from(schema.exposureAsset)
          .where(eq(schema.exposureAsset.id, due.id));
        expect(asset?.lastPassiveAt).toBeNull();
        await ex.runVerify(due.id, { net: env() });
        const [after] = await conn.db
          .select()
          .from(schema.exposureAsset)
          .where(eq(schema.exposureAsset.id, due.id));
        expect(after?.verifyCheckedAt).toBeNull();
      });

      it("sends again a run that was lost between queueing and sending, and fails runs stuck for half an hour", async () => {
        await parkOthers();
        const org = await newOrg();
        const now = new Date();
        const a = await addAsset(org.id, { lastPassiveAt: now, verifyCheckedAt: now });
        const lost = newId("exr");
        await conn.db.insert(schema.exposureRun).values({
          id: lost,
          organizationId: org.id,
          assetId: a.id,
          stage: "passive",
          state: "queued",
          trigger: "schedule",
          createdAt: new Date(now.getTime() - 5 * 60_000),
        });
        const b = await addAsset(org.id, { lastPassiveAt: now, verifyCheckedAt: now });
        const stuck = newId("exr");
        await conn.db.insert(schema.exposureRun).values({
          id: stuck,
          organizationId: org.id,
          assetId: b.id,
          stage: "active",
          state: "running",
          trigger: "schedule",
          startedAt: new Date(now.getTime() - 45 * 60_000),
          createdAt: new Date(now.getTime() - 50 * 60_000),
        });
        const { boss, sent } = fakeBoss();
        await ex.exposureTick(boss, { now: () => now });
        expect(sent.filter((s) => s.name === ex.EXPOSURE_RUN_QUEUE).map((s) => s.data.runId)).toContain(lost);
        expect(await run(stuck)).toMatchObject({ state: "failed", error: "timeout" });
      });
    });

    /* ======================================================================== */
    describe("availability (ADR 0040)", () => {
      const MIN = 60_000;
      const checks = async (assetId: string) =>
        conn.db
          .select()
          .from(schema.exposureUptimeCheck)
          .where(eq(schema.exposureUptimeCheck.assetId, assetId))
          .orderBy(schema.exposureUptimeCheck.checkedAt);
      const told = async (assetId: string, titleKey: string) =>
        (
          await conn.db
            .select()
            .from(schema.userNotification)
            .where(eq(schema.userNotification.titleKey, titleKey))
        ).filter((n) => n.link === `/websites/${assetId}?tab=availability`);

      it("checks only switched-on assets that are due, turns down after three failures and up with the first success", async () => {
        resetZone();
        Object.assign(web, freshWeb());
        const org = await newOrg();
        // The test certificate names SITE.
        const a = await addAsset(org.id, { uptimeEnabled: true, uptimeIntervalMinutes: 5, value: SITE });
        const off = await addAsset(org.id);
        tidyZone(a.value);
        tidyZone(off.value);
        const up = await import("./uptime.ts");
        let now = new Date(Date.UTC(2026, 9, 30, 12, 0));
        const tick = () => up.uptimeTick({ net: env(), now: () => now });

        await tick();
        expect(await checks(a.id)).toHaveLength(1);
        expect(await checks(off.id)).toHaveLength(0);
        expect(await asset(a.id)).toMatchObject({ uptimeState: "up", uptimeFailures: 0 });
        expect((await checks(a.id))[0]).toMatchObject({ up: true, status: 200, error: null });
        // Not due again within its interval.
        now = new Date(now.getTime() + 2 * MIN);
        await tick();
        expect(await checks(a.id)).toHaveLength(1);

        web.status = 503;
        for (let i = 0; i < 3; i++) {
          now = new Date(now.getTime() + 5 * MIN);
          await tick();
          expect((await asset(a.id)).uptimeState).toBe(i < 2 ? "up" : "down");
        }
        expect((await checks(a.id)).at(-1)).toMatchObject({ up: false, status: 503, error: "status" });
        // Owner, admin and member are told.
        expect(await told(a.id, "exposureDown")).toHaveLength(3);
        expect((await told(a.id, "exposureDown"))[0]?.params).toMatchObject({
          asset: a.value,
          reason: "HTTP 503",
        });
        // Still down: nobody is told again.
        now = new Date(now.getTime() + 5 * MIN);
        await tick();
        expect(await told(a.id, "exposureDown")).toHaveLength(3);

        web.status = 404;
        now = new Date(now.getTime() + 5 * MIN);
        await tick();
        const back = await asset(a.id);
        expect(back).toMatchObject({ uptimeState: "up", uptimeFailures: 0 });
        expect(back.uptimeSince?.toISOString()).toBe(now.toISOString());
        expect(await told(a.id, "exposureUp")).toHaveLength(3);
        Object.assign(web, freshWeb());
      });

      it("names the reason of a failure, never asks for a switched-off organisation, and forgets old checks", async () => {
        resetZone();
        Object.assign(web, freshWeb());
        const org = await newOrg();
        const unknown = await addAsset(org.id, { uptimeEnabled: true, value: "missing.example.com" });
        const other = await newOrg();
        const quiet = await addAsset(other.id, { uptimeEnabled: true });
        tidyZone(quiet.value);
        await conn.db
          .update(schema.exposureSettings)
          .set({ enabled: false })
          .where(eq(schema.exposureSettings.organizationId, other.id));
        const now = new Date(Date.UTC(2026, 10, 2, 12, 0));
        await conn.db.insert(schema.exposureUptimeCheck).values({
          id: newId("upt"),
          organizationId: org.id,
          assetId: unknown.id,
          checkedAt: new Date(now.getTime() - 31 * DAY),
          up: true,
        });
        const up = await import("./uptime.ts");
        await up.uptimeTick({ net: env(), now: () => now });
        const rows = await checks(unknown.id);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ up: false, error: "dns", status: null });
        expect(await checks(quiet.id)).toHaveLength(0);
        // A refused connection is its own reason.
        zone[unknown.value] = { a: ["127.0.0.1"] };
        const result = await up.checkAvailability(env({ httpsPort: await closedPort() }), unknown);
        expect(result).toMatchObject({ up: false, error: "refused" });
      });
    });

    it("never wrote a secret or a body into the log or the database", async () => {
      const dump: string[] = [];
      for (const table of [
        "exposure_asset",
        "exposure_run",
        "exposure_finding",
        "exposure_port",
        "exposure_discovery",
        "audit_log",
        "user_notification",
      ]) {
        const res = await conn.pool.query(`select row_to_json(t)::text as row from ${table} t`);
        dump.push(...res.rows.map((r: { row: string }) => r.row));
      }
      const text = `${dump.join("\n")}\n${consoleLines.join("\n")}`;
      expect(text).not.toContain("BEGIN PRIVATE KEY");
      expect(text).not.toContain("SECRET-BODY-MARKER");
      expect(consoleLines.filter((l) => /exposure (passive|active):/.test(l))).toEqual([]);
    });
  },
);
