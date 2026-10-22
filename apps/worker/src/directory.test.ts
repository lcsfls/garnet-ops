/**
 * Directory sign-in in the worker (ADR 0020), against a small LDAP server of our own that speaks
 * Active Directory's and OpenLDAP's dialects (apps/worker/test/fake-ldap.ts). The server has a
 * throw-away certificate made with openssl. A throw-away PostgreSQL database on the development
 * server and a real vault key stand in for the installation. Skipped without openssl or the
 * development PostgreSQL. Nothing leaves the machine.
 *
 * What these tests are for: that a password is only ever sent over a verified, encrypted
 * connection and never when empty; that nothing a person types becomes filter syntax; that the
 * answer is exactly what the directory said (unique id, groups, highest role); that a refusal of
 * any kind is a refusal; and that no secret ends up in a result, a row or a log line.
 */
import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair, loadVaultPrivateKey, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { createDb, runMigrations, schema } from "@garnetops/db";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AD,
  ADMIN_GROUPS,
  activeDirectory,
  guidText,
  NEW_USER_PASSWORD,
  OPENLDAP,
  openLdap,
  SERVICE_PASSWORD,
  USER_PASSWORD,
} from "../test/directory-fixtures.ts";
import { FakeLdapServer } from "../test/fake-ldap.ts";

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

const ORG = "org_directory";
const HOST = "dc1.example.lan";

function selfSigned(dir: string, name: string, host = HOST): { key: string; cert: string } {
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

describe.skipIf(!openssl || !adminUrl)("directory sign-in in the worker", () => {
  const dbName = `garnetops_directory_test_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let dir: typeof import("./directory.ts");
  let vaultPublic: ReturnType<typeof vaultPublicKeyOf>;
  let certA = { key: "", cert: "" };
  let certB = { key: "", cert: "" };
  let certOther = { key: "", cert: "" };
  let fingerprintA = "";
  let fingerprintB = "";
  const consoleLines: string[] = [];
  const net = { resolve: async () => "127.0.0.1" };
  const deps = () => ({ net });

  // The servers all tests share. Each test resets what they saw.
  let ldaps: FakeLdapServer;
  let starttls: FakeLdapServer;
  let plainOnly: FakeLdapServer;
  let openldapServer: FakeLdapServer;

  async function setConfig(
    patch: Omit<Partial<typeof schema.ldapConfig.$inferInsert>, "servers"> & {
      servers?: string[];
      bindPassword?: string;
    } = {},
  ) {
    const { servers = [`ldaps://${HOST}:${ldaps.port}`], bindPassword = SERVICE_PASSWORD, ...rest } = patch;
    await conn.db.delete(schema.ldapConfig).where(eq(schema.ldapConfig.organizationId, ORG));
    await conn.db.delete(schema.secret);
    const secretId = `sec_${Math.random().toString(36).slice(2, 10)}`;
    await conn.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "ldap-bind-password",
      sealed: seal(
        bindPassword,
        { organizationId: ORG, recordId: secretId, purpose: "ldap-bind-password" },
        vaultPublic,
      ),
      vaultKeyId: vaultPublic.id,
    });
    await conn.db.insert(schema.ldapConfig).values({
      organizationId: ORG,
      enabled: true,
      preset: "active-directory",
      servers: servers.map((url) => ({ url, pin: null, candidate: null, certStatus: "pending" as const })),
      tlsTrust: "ca",
      caCertificate: certA.cert,
      bindDn: AD.service,
      bindSecretId: secretId,
      userBaseDn: AD.usersOu,
      userFilter: "(&(objectClass=user)(sAMAccountName={username}))",
      emailAttribute: "mail",
      nameAttribute: "displayName",
      uniqueIdAttribute: "objectGUID",
      groupMode: "nested",
      groupFilter: "",
      groupRoles: ADMIN_GROUPS,
      ...rest,
    });
    return (await config()) as typeof schema.ldapConfig.$inferSelect;
  }
  const config = async () =>
    (await conn.db.select().from(schema.ldapConfig).where(eq(schema.ldapConfig.organizationId, ORG)))[0];
  const withPin = async (url: string, fingerprint: string) => {
    const row = await config();
    await conn.db
      .update(schema.ldapConfig)
      .set({
        servers: (row?.servers ?? []).map((s) =>
          s.url === url
            ? {
                ...s,
                certStatus: "confirmed" as const,
                pin: {
                  fingerprint,
                  subject: "CN=x",
                  issuer: "CN=x",
                  validFrom: "2026-01-01T00:00:00.000Z",
                  validTo: "2027-01-01T00:00:00.000Z",
                  confirmedAt: "2026-01-01T00:00:00.000Z",
                  confirmedBy: null,
                },
              }
            : s,
        ),
      })
      .where(eq(schema.ldapConfig.organizationId, ORG));
    return (await config()) as typeof schema.ldapConfig.$inferSelect;
  };
  const audit = async () =>
    conn.db.select().from(schema.auditLog).where(eq(schema.auditLog.organizationId, ORG));
  /** Everything the server saw except the polite goodbyes, which arrive late. */
  const traffic = (server: FakeLdapServer) => server.seen.filter((s) => s.op !== "unbind");
  const binds = (server: FakeLdapServer) => server.seen.filter((s) => s.op === "bind");
  const searches = (server: FakeLdapServer) => server.seen.filter((s) => s.op === "search");

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    workDir = await mkdtemp(join(tmpdir(), "garnetops-directory-test-"));
    const keys = generateVaultKeyPair();
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 });
    vaultPublic = vaultPublicKeyOf(loadVaultPrivateKey(keys.privateKeyPem));
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
    await conn.db.insert(schema.organization).values({ id: ORG, name: "Directory Test" });

    certA = selfSigned(workDir, "A");
    certB = selfSigned(workDir, "B");
    certOther = selfSigned(workDir, "Other", "other.example.lan");
    fingerprintA = new X509Certificate(certA.cert).fingerprint256;
    fingerprintB = new X509Certificate(certB.cert).fingerprint256;

    const ad = activeDirectory();
    ldaps = new FakeLdapServer({ ...ad, mode: "ldaps", tls: certA, requireTls: true });
    starttls = new FakeLdapServer({
      ...ad,
      mode: "ldap",
      tls: certA,
      requireTls: true,
      allowUnauthenticatedBind: true,
    });
    plainOnly = new FakeLdapServer({ ...ad, mode: "ldap", requireTls: true });
    const ol = openLdap();
    openldapServer = new FakeLdapServer({ ...ol, mode: "ldaps", tls: certA });
    await Promise.all([ldaps.start(), starttls.start(), plainOnly.start(), openldapServer.start()]);

    for (const method of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleLines.push(args.map(String).join(" "));
      });
    }
    dir = await import("./directory.ts");
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    await Promise.all([ldaps?.stop(), starttls?.stop(), plainOnly?.stop(), openldapServer?.stop()]);
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
    for (const s of [ldaps, starttls, plainOnly, openldapServer]) s?.reset();
    consoleLines.length = 0;
  });

  describe("signing in over ldaps", () => {
    it("finds the person, checks the password and reads the unique id, mail, name and groups", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
      expect(result.user).toEqual({
        uniqueId: guidText(2),
        dn: AD.user("Anna Smith"),
        email: "asmith@example.lan",
        name: "Anna Smith",
        // In the users and the viewers group: the higher role wins.
        groups: [AD.users, AD.viewers],
        role: "member",
      });
    });

    it("binds first as the service account, then as the person, on separate connections, always encrypted", async () => {
      const cfg = await setConfig();
      await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      const list = binds(ldaps);
      expect(list.map((b) => b.dn)).toEqual([AD.service, AD.user("Anna Smith")]);
      expect(list.every((b) => b.tls)).toBe(true);
      expect(new Set(list.map((b) => b.connection)).size).toBe(2);
      // The service connection did the searches; the person's connection only bound.
      expect(searches(ldaps).every((s) => s.connection === list[0]?.connection)).toBe(true);
    });

    it("gives admin for a member of a group inside a group (Active Directory's chain rule)", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "jdoe", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
      expect(result.user?.role).toBe("admin");
      expect(result.user?.groups).toEqual([AD.admins]);
      const chain = searches(ldaps).find((s) => s.filter?.includes("1.2.840.113556.1.4.1941"));
      expect(chain?.scope).toBe("base");
    });

    it("direct memberOf alone does not see through nested groups", async () => {
      const cfg = await setConfig({ groupMode: "member-of" });
      const result = await dir.signIn(cfg, "jdoe", USER_PASSWORD, deps());
      expect(result.outcome).toBe("not-allowed");
      expect(result.problem).toBe("not-in-group");
      expect(result.user?.role).toBeNull();
    });

    it("gives viewer for a viewer", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "bwilson", USER_PASSWORD, deps());
      expect(result.user?.role).toBe("viewer");
    });

    it("refuses a person who is in no allowed group, and says why to the admin only", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "cnoone", USER_PASSWORD, deps());
      expect(result).toMatchObject({ outcome: "not-allowed", problem: "not-in-group" });
      expect(result.user?.groups).toEqual([]);
    });

    it("a person with a comma and parentheses in the name works", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "zsmith", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
      expect(result.user?.dn).toBe(AD.zed);
      expect(result.user?.role).toBe("member");
      // The DN went into the filter escaped, not as filter syntax.
      expect(searches(ldaps).some((s) => s.filter?.includes("\\5c,") || s.filter?.includes("\\28"))).toBe(
        true,
      );
    });

    it("a missing mail address is reported as missing, not invented", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "nomail", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
      expect(result.user?.email).toBeNull();
    });

    it("is case-insensitive about the name the way the directory is", async () => {
      const cfg = await setConfig();
      expect((await dir.signIn(cfg, "ASmith", USER_PASSWORD, deps())).outcome).toBe("ok");
    });
  });

  describe("refusals", () => {
    it("a wrong password is a refusal", async () => {
      const cfg = await setConfig();
      expect(await dir.signIn(cfg, "asmith", NEW_USER_PASSWORD, deps())).toEqual({
        outcome: "invalid-credentials",
        problem: "wrong-password",
        // The audit log names the entry the password was tried for, not what was typed.
        subject: { dn: AD.user("Anna Smith"), uniqueId: guidText(2) },
      });
    });

    it("an unknown name is a refusal, with the same number of round trips as a real attempt", async () => {
      const cfg = await setConfig();
      await dir.signIn(cfg, "asmith", NEW_USER_PASSWORD, deps());
      const wrongPassword = ldaps.seen.filter((s) => s.op === "bind" || s.op === "search").length;
      ldaps.reset();
      const result = await dir.signIn(cfg, "nobody-here", USER_PASSWORD, deps());
      expect(result).toEqual({ outcome: "invalid-credentials", problem: "user-not-found" });
      // Service bind, search, and a bind on the second connection; a real attempt adds the group searches only when the password is right.
      expect(ldaps.seen.filter((s) => s.op === "bind" || s.op === "search").length).toBe(wrongPassword);
      // The password typed for a name that does not exist is not sent anywhere.
      expect(binds(ldaps).every((b) => b.dn !== AD.user("nobody-here"))).toBe(true);
    });

    it("an empty password never reaches the directory, even one that would accept an unauthenticated bind", async () => {
      const cfg = await setConfig({ servers: [`ldap://${HOST}:${starttls.port}`] });
      const result = await dir.signIn(cfg, "asmith", "", deps());
      expect(result).toEqual({ outcome: "invalid-credentials", problem: "wrong-password" });
      expect(traffic(starttls)).toEqual([]);
      // Whitespace is a password like any other, and the directory judges it.
      const spaces = await dir.signIn(cfg, "asmith", "   ", deps());
      expect(spaces.outcome).toBe("invalid-credentials");
      expect(binds(starttls).every((b) => (b.passwordLength ?? 0) > 0)).toBe(true);
    });

    it("never makes an anonymous bind", async () => {
      const cfg = await setConfig();
      await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      await dir.signIn(cfg, "nobody", USER_PASSWORD, deps());
      expect(binds(ldaps).every((b) => b.dn !== "" && (b.passwordLength ?? 0) > 0)).toBe(true);
    });

    it("refuses names with filter syntax before any search is sent", async () => {
      const cfg = await setConfig();
      for (const name of [
        "*",
        "asmith)(|(cn=*",
        "*)(uid=*))(|(uid=*",
        "asmith\u0000",
        "",
        " ",
        "a".repeat(200),
      ]) {
        expect(await dir.signIn(cfg, name, USER_PASSWORD, deps())).toEqual({
          outcome: "invalid-credentials",
          problem: "wrong-password",
        });
      }
      expect(traffic(ldaps)).toEqual([]);
    });

    it("a backslash in an allowed name is escaped into the filter", async () => {
      const cfg = await setConfig();
      await dir.signIn(cfg, "EXAMPLE\\asmith", USER_PASSWORD, deps());
      expect(searches(ldaps).some((s) => s.filter?.includes("samaccountname=EXAMPLE\\5casmith"))).toBe(true);
    });

    it("two entries for one name are a misconfiguration, not a coin toss", async () => {
      const cfg = await setConfig();
      const result = await dir.signIn(cfg, "twin", USER_PASSWORD, deps());
      expect(result).toEqual({ outcome: "misconfigured", problem: "user-ambiguous" });
      // No password was tried for either of them.
      expect(binds(ldaps).map((b) => b.dn)).toEqual([AD.service]);
    });

    it("a server that answers with an entry outside the search base is not believed", async () => {
      const liar = new FakeLdapServer({ ...activeDirectory(), mode: "ldaps", tls: certA, ignoreScope: true });
      await liar.start();
      try {
        const cfg = await setConfig({
          servers: [`ldaps://${HOST}:${liar.port}`],
          userBaseDn: `OU=Elsewhere,${AD.root}`,
        });
        // The base must exist for the search to run at all.
        liar.entries.push({
          dn: `OU=Elsewhere,${AD.root}`,
          attributes: { objectClass: ["organizationalUnit"] },
        });
        const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
        expect(result).toEqual({ outcome: "misconfigured", problem: "user-outside-base" });
        expect(binds(liar).map((b) => b.dn)).toEqual([AD.service]);
      } finally {
        await liar.stop();
      }
    });

    it("does nothing when the directory sign-in is switched off", async () => {
      const cfg = await setConfig({ enabled: false });
      expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toMatchObject({
        outcome: "unavailable",
        problem: "disabled",
      });
      expect(traffic(ldaps)).toEqual([]);
    });
  });

  describe("the service account", () => {
    it("a refused password stops everything for a while, so the account cannot be locked out", async () => {
      const cfg = await setConfig({ bindPassword: "test-only-wrong-service-password" });
      expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toEqual({
        outcome: "misconfigured",
        problem: "service-bind-failed",
      });
      expect(binds(ldaps)).toHaveLength(1);
      const blocked = await config();
      expect(blocked?.bindBlockedUntil && blocked.bindBlockedUntil > new Date()).toBe(true);
      // The next attempts do not even connect.
      ldaps.reset();
      expect(await dir.signIn(blocked as typeof cfg, "asmith", USER_PASSWORD, deps())).toEqual({
        outcome: "misconfigured",
        problem: "service-bind-blocked",
      });
      expect(traffic(ldaps)).toEqual([]);
      expect(ldaps.connections).toBeGreaterThan(0);
    });

    it("a refused password does not make it try the next server too", async () => {
      const second = new FakeLdapServer({ ...activeDirectory(), mode: "ldaps", tls: certA });
      await second.start();
      try {
        const cfg = await setConfig({
          servers: [`ldaps://${HOST}:${ldaps.port}`, `ldaps://${HOST}:${second.port}`],
          bindPassword: "test-only-wrong-service-password",
        });
        await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
        expect(binds(second)).toEqual([]);
      } finally {
        await second.stop();
      }
    });

    it("the password is only ever opened from the vault, and never appears in a result or a log line", async () => {
      const cfg = await setConfig();
      const results = [
        await dir.signIn(cfg, "asmith", USER_PASSWORD, deps()),
        await dir.signIn(cfg, "asmith", NEW_USER_PASSWORD, deps()),
        await dir.test(cfg, "asmith", deps()),
      ];
      const text = JSON.stringify(results) + consoleLines.join("\n");
      expect(text).not.toContain(SERVICE_PASSWORD);
      expect(text).not.toContain(USER_PASSWORD);
      expect(text).not.toContain(NEW_USER_PASSWORD);
      const stored = JSON.stringify(await conn.db.select().from(schema.ldapConfig));
      expect(stored).not.toContain(SERVICE_PASSWORD);
    });
  });

  describe("StartTLS and plain LDAP", () => {
    it("upgrades ldap:// with StartTLS before anything is bound", async () => {
      const cfg = await setConfig({ servers: [`ldap://${HOST}:${starttls.port}`] });
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
      expect(starttls.seen[0]).toMatchObject({ op: "starttls", tls: false });
      // Everything except the StartTLS request itself travelled encrypted.
      expect(
        traffic(starttls)
          .filter((s) => s.op !== "starttls")
          .every((s) => s.tls),
      ).toBe(true);
      expect(traffic(starttls).filter((s) => s.op === "starttls")).toHaveLength(2);
      expect(binds(starttls).length).toBe(2);
    });

    it("refuses to bind when the server will not do StartTLS: no password goes out in the clear", async () => {
      const cfg = await setConfig({ servers: [`ldap://${HOST}:${plainOnly.port}`] });
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result).toEqual({ outcome: "unavailable", problem: "starttls-refused" });
      expect(binds(plainOnly)).toEqual([]);
      expect(traffic(plainOnly).every((s) => s.op === "starttls")).toBe(true);
    });

    it("a server that says yes to StartTLS and then fails the handshake is not used", async () => {
      const bad = new FakeLdapServer({ ...activeDirectory(), mode: "ldap", tls: certOther });
      await bad.start();
      try {
        const cfg = await setConfig({ servers: [`ldap://${HOST}:${bad.port}`] });
        const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
        // The certificate is for another name.
        expect(result).toMatchObject({ outcome: "unavailable", problem: "tls-failed" });
        expect(binds(bad)).toEqual([]);
      } finally {
        await bad.stop();
      }
    });
  });

  describe("trust in the server's certificate", () => {
    it("system trust refuses a self-signed certificate", async () => {
      const cfg = await setConfig({ tlsTrust: "system", caCertificate: "" });
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result).toMatchObject({ outcome: "unavailable", problem: "tls-failed" });
      expect(traffic(ldaps)).toEqual([]);
    });

    it("a CA certificate that did not sign the server's is refused", async () => {
      const cfg = await setConfig({ caCertificate: certB.cert });
      expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toMatchObject({ problem: "tls-failed" });
      expect(traffic(ldaps)).toEqual([]);
    });

    it("the certificate has to be for the name in the configuration", async () => {
      const wrongName = new FakeLdapServer({ ...activeDirectory(), mode: "ldaps", tls: certOther });
      await wrongName.start();
      try {
        const cfg = await setConfig({
          servers: [`ldaps://${HOST}:${wrongName.port}`],
          caCertificate: certOther.cert,
        });
        expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toMatchObject({
          problem: "tls-failed",
        });
        expect(traffic(wrongName)).toEqual([]);
      } finally {
        await wrongName.stop();
      }
    });

    it("pinning: a server without a confirmed pin is not used, and its certificate is proposed", async () => {
      const url = `ldaps://${HOST}:${ldaps.port}`;
      const cfg = await setConfig({ tlsTrust: "pin", caCertificate: "" });
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result).toMatchObject({ outcome: "unavailable", problem: "certificate-not-confirmed" });
      expect(traffic(ldaps)).toEqual([]);
      const server = (await config())?.servers.find((s) => s.url === url);
      expect(server?.certStatus).toBe("pending");
      expect(server?.pin).toBeNull();
      expect(server?.candidate?.fingerprint).toBe(fingerprintA);
    });

    it("pinning: the pinned certificate works, whatever CA signed it", async () => {
      const url = `ldaps://${HOST}:${ldaps.port}`;
      await setConfig({ tlsTrust: "pin", caCertificate: "" });
      const cfg = await withPin(url, fingerprintA);
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
    });

    it("pinning: another certificate is refused before anything is sent, recorded, audited and told to the admins", async () => {
      const server = new FakeLdapServer({ ...activeDirectory(), mode: "ldaps", tls: certA });
      await server.start();
      try {
        const url = `ldaps://${HOST}:${server.port}`;
        await setConfig({ servers: [url], tlsTrust: "pin", caCertificate: "" });
        const cfg = await withPin(url, fingerprintA);
        server.setCertificate(certB);
        const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
        expect(result).toMatchObject({ outcome: "unavailable", problem: "certificate-changed" });
        expect(traffic(server)).toEqual([]);
        const row = (await config())?.servers[0];
        expect(row?.certStatus).toBe("changed");
        expect(row?.pin?.fingerprint).toBe(fingerprintA);
        expect(row?.candidate?.fingerprint).toBe(fingerprintB);
        const entries = (await audit()).filter((e) => e.action === "directory.certificate_changed");
        expect(entries).toHaveLength(1);
        expect(entries[0]?.data).toMatchObject({ pinned: fingerprintA, seen: fingerprintB, server: url });
        // Once per change.
        await dir.signIn((await config()) as typeof cfg, "asmith", USER_PASSWORD, deps());
        expect((await audit()).filter((e) => e.action === "directory.certificate_changed")).toHaveLength(1);
        // The old certificate is back: the alarm clears itself.
        server.setCertificate(certA);
        const again = await dir.signIn((await config()) as typeof cfg, "asmith", USER_PASSWORD, deps());
        expect(again.outcome).toBe("ok");
        expect((await config())?.servers[0]?.certStatus).toBe("confirmed");
      } finally {
        await server.stop();
      }
    });

    it("reading a certificate sends nothing and only proposes it", async () => {
      const cfg = await setConfig({ tlsTrust: "pin", caCertificate: "" });
      const result = await dir.readCertificates(cfg, null, deps());
      expect(result.servers[0]?.certificate?.fingerprint).toBe(fingerprintA);
      expect(traffic(ldaps)).toEqual([]);
      const server = (await config())?.servers[0];
      expect(server?.candidate?.fingerprint).toBe(fingerprintA);
      expect(server?.candidate?.trusted).toBe(false);
      expect(server?.pin).toBeNull();
    });
  });

  describe("servers that do not answer", () => {
    it("falls back to the next server", async () => {
      const cfg = await setConfig({
        servers: ["ldaps://down.example.lan:1", `ldaps://${HOST}:${ldaps.port}`],
      });
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result.outcome).toBe("ok");
    });

    it("says unreachable when none does", async () => {
      const cfg = await setConfig({ servers: ["ldaps://down.example.lan:1"] });
      expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toEqual({
        outcome: "unavailable",
        problem: "unreachable",
      });
    });

    it("refuses an address that is not allowed, whatever the stored URL says", async () => {
      const cfg = await setConfig({ servers: ["ldaps://127.0.0.1:1"] });
      expect(await dir.signIn(cfg, "asmith", USER_PASSWORD, deps())).toEqual({
        outcome: "unavailable",
        problem: "address-refused",
      });
    });

    it("times out a search that is never answered", async () => {
      const cfg = await setConfig({ operationTimeoutSeconds: 1 });
      ldaps.hangSearches = true;
      const started = Date.now();
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result).toEqual({ outcome: "unavailable", problem: "timeout" });
      expect(Date.now() - started).toBeLessThan(5000);
    });

    it("a failing group search is an error, never 'not a member'", async () => {
      const cfg = await setConfig();
      // The group searches (base scope) are refused with "unwilling to perform".
      ldaps.failSearchesWith = 53;
      ldaps.failScope = "base";
      const result = await dir.signIn(cfg, "asmith", USER_PASSWORD, deps());
      expect(result).toEqual({ outcome: "misconfigured", problem: "group-search-failed" });
    });
  });

  describe("OpenLDAP", () => {
    const ol = (patch: Omit<Partial<typeof schema.ldapConfig.$inferInsert>, "servers"> = {}) =>
      setConfig({
        servers: [`ldaps://${HOST}:${openldapServer.port}`],
        preset: "openldap",
        bindDn: OPENLDAP.service,
        userBaseDn: OPENLDAP.peopleOu,
        userFilter: "(&(objectClass=inetOrgPerson)(uid={username}))",
        nameAttribute: "cn",
        uniqueIdAttribute: "entryUUID",
        groupMode: "search",
        groupFilter: "(|(member={dn})(uniqueMember={dn}))",
        groupRoles: [
          { dn: OPENLDAP.admins, role: "admin" },
          { dn: OPENLDAP.users, role: "member" },
          { dn: OPENLDAP.viewers, role: "viewer" },
        ],
        ...patch,
      });

    it("signs in with groupOfNames groups and entryUUID", async () => {
      const cfg = await ol();
      const admin = await dir.signIn(cfg, "olga", USER_PASSWORD, deps());
      expect(admin.user).toMatchObject({
        uniqueId: "aaaaaaaa-0000-4000-8000-000000000001",
        email: "olga@example.lan",
        role: "admin",
      });
      const both = await dir.signIn(cfg, "oskar", USER_PASSWORD, deps());
      expect(both.user?.role).toBe("member");
      expect(both.user?.groups).toEqual([OPENLDAP.users, OPENLDAP.viewers]);
      const none = await dir.signIn(cfg, "omar", USER_PASSWORD, deps());
      expect(none.outcome).toBe("not-allowed");
    });

    it("a configured group that does not exist grants nothing", async () => {
      const cfg = await ol({
        groupRoles: [
          { dn: `cn=garnetops-ghosts,ou=groups,${OPENLDAP.root}`, role: "admin" },
          { dn: OPENLDAP.viewers, role: "viewer" },
        ],
      });
      const result = await dir.signIn(cfg, "oskar", USER_PASSWORD, deps());
      expect(result.user?.role).toBe("viewer");
    });
  });

  describe("connection test", () => {
    it("shows every server, the user, the groups and the role, and never a password", async () => {
      const second = new FakeLdapServer({ ...activeDirectory(), mode: "ldaps", tls: certB });
      await second.start();
      try {
        const cfg = await setConfig({
          servers: [`ldaps://${HOST}:${ldaps.port}`, `ldaps://${HOST}:${second.port}`],
        });
        const result = await dir.test(cfg, "jdoe", deps());
        expect(result.ok).toBe(true);
        expect(result.servers).toMatchObject([
          { ok: true, transport: "ldaps" },
          { ok: false, problem: "tls-failed", transport: "ldaps" },
        ]);
        expect(result.user).toMatchObject({
          dn: AD.user("John Doe"),
          email: "jdoe@example.lan",
          role: "admin",
        });
        expect(result.groups).toEqual([
          { dn: AD.admins, exists: true, member: true },
          { dn: AD.users, exists: true, member: false },
          { dn: AD.viewers, exists: true, member: false },
        ]);
        expect(JSON.stringify(result)).not.toContain(SERVICE_PASSWORD);
      } finally {
        await second.stop();
      }
    });

    it("reports a search base that does not exist", async () => {
      const cfg = await setConfig({ userBaseDn: `OU=Nowhere,${AD.root}` });
      expect(await dir.test(cfg, null, deps())).toMatchObject({ ok: false, problem: "base-not-found" });
    });

    it("reports a group that does not exist", async () => {
      const cfg = await setConfig({
        groupRoles: [
          { dn: `CN=GarnetOps-Typo,OU=Groups,${AD.root}`, role: "admin" },
          { dn: AD.users, role: "member" },
        ],
      });
      const result = await dir.test(cfg, "asmith", deps());
      expect(result.ok).toBe(true);
      expect(result.groups?.[0]).toMatchObject({ exists: false, member: false });
      expect(result.user?.role).toBe("member");
    });

    it("says so when the person is not found", async () => {
      const cfg = await setConfig();
      expect(await dir.test(cfg, "nobody", deps())).toMatchObject({ ok: false, problem: "user-not-found" });
    });

    it("works without a user name: connection, bind and base only", async () => {
      const cfg = await setConfig();
      const result = await dir.test(cfg, null, deps());
      expect(result.ok).toBe(true);
      expect(result.user).toBeUndefined();
    });

    it("a pinned server that shows another certificate is reported with the certificate it showed", async () => {
      const url = `ldaps://${HOST}:${ldaps.port}`;
      await setConfig({ tlsTrust: "pin", caCertificate: "" });
      const cfg = await withPin(url, fingerprintB);
      const result = await dir.test(cfg, null, deps());
      expect(result.ok).toBe(false);
      expect(result.servers[0]).toMatchObject({ ok: false, problem: "certificate-changed" });
      expect(result.servers[0]?.certificate?.fingerprint).toBe(fingerprintA);
    });
  });

  describe("look-up", () => {
    it("finds a person without binding as them", async () => {
      const cfg = await setConfig();
      const result = await dir.lookup(cfg, "asmith", deps());
      expect(result.outcome).toBe("ok");
      expect(result.user?.uniqueId).toBe(guidText(2));
      expect(binds(ldaps).map((b) => b.dn)).toEqual([AD.service]);
    });
  });

  describe("the periodic check", () => {
    const person = async (
      id: string,
      name: string,
      role: "owner" | "admin" | "member" | "viewer",
      n: number,
      dn: string,
      sam: string,
    ) => {
      await conn.db
        .insert(schema.user)
        .values({ id, name, email: `${sam}@example.lan` })
        .onConflictDoNothing();
      await conn.db.delete(schema.membership).where(eq(schema.membership.userId, id));
      await conn.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role });
      await conn.db.delete(schema.directoryIdentity).where(eq(schema.directoryIdentity.userId, id));
      await conn.db.insert(schema.directoryIdentity).values({
        id: `di_${id}`,
        organizationId: ORG,
        userId: id,
        uniqueId: guidText(n),
        dn,
        loginName: sam,
      });
      await conn.db.delete(schema.session).where(eq(schema.session.userId, id));
      await conn.db.insert(schema.session).values({
        id: `s_${id}`,
        token: `t_${id}`,
        userId: id,
        expiresAt: new Date(Date.now() + 3600_000),
      });
    };
    const roleOf = async (id: string) =>
      (await conn.db.select().from(schema.membership).where(eq(schema.membership.userId, id)))[0]?.role ??
      null;
    const sessionCount = async (id: string) =>
      (await conn.db.select().from(schema.session).where(eq(schema.session.userId, id))).length;
    let original: typeof ldaps.entries;

    beforeEach(async () => {
      original = ldaps.entries.map((e) => ({
        dn: e.dn,
        attributes: Object.fromEntries(Object.entries(e.attributes).map(([k, v]) => [k, [...v]])),
      }));
      await conn.db.delete(schema.auditLog);
      await conn.db.delete(schema.directoryIdentity);
      await person("u_jdoe", "John Doe", "admin", 1, AD.user("John Doe"), "jdoe");
      await person("u_asmith", "Anna Smith", "member", 2, AD.user("Anna Smith"), "asmith");
      await person("u_bwilson", "Ben Wilson", "viewer", 3, AD.user("Ben Wilson"), "bwilson");
    });
    it("leaves everyone alone when the directory agrees", async () => {
      const cfg = await setConfig();
      await person("u_jdoe", "John Doe", "admin", 1, AD.user("John Doe"), "jdoe");
      const summary = await dir.reconcileDirectory(cfg, deps());
      expect(summary).toEqual({ checked: 3, changed: 0, removed: 0, skipped: false });
      expect(await roleOf("u_jdoe")).toBe("admin");
      expect(await sessionCount("u_jdoe")).toBe(1);
      expect((await audit()).filter((e) => e.action.startsWith("directory."))).toEqual([]);
    });

    it("ends the access of someone taken out of the allowed groups, sessions included, and audits it", async () => {
      const cfg = await setConfig();
      // Anna Smith leaves both of her groups.
      for (const entry of ldaps.entries) {
        if (entry.dn === AD.users || entry.dn === AD.viewers) {
          entry.attributes.member = (entry.attributes.member as string[]).filter(
            (m) => m !== AD.user("Anna Smith"),
          );
        }
      }
      try {
        const summary = await dir.reconcileDirectory(cfg, deps());
        expect(summary).toMatchObject({ checked: 3, removed: 1, changed: 0, skipped: false });
        expect(await roleOf("u_asmith")).toBeNull();
        expect(await sessionCount("u_asmith")).toBe(0);
        expect(await roleOf("u_jdoe")).toBe("admin");
        const entry = (await audit()).find((e) => e.action === "directory.access_removed");
        expect(entry).toMatchObject({
          targetId: "u_asmith",
          data: { email: "asmith@example.lan", before: "member", via: "check" },
        });
      } finally {
        ldaps.entries = original;
      }
    });

    it("changes the role when the groups changed", async () => {
      const cfg = await setConfig();
      await person("u_bwilson", "Ben Wilson", "admin", 3, AD.user("Ben Wilson"), "bwilson");
      const summary = await dir.reconcileDirectory(cfg, deps());
      expect(summary).toMatchObject({ changed: 1, removed: 0 });
      expect(await roleOf("u_bwilson")).toBe("viewer");
      // Sessions stay: the role is read on every request.
      expect(await sessionCount("u_bwilson")).toBe(1);
      const entry = (await audit()).find((e) => e.action === "directory.role_changed");
      expect(entry?.data).toMatchObject({ before: "admin", after: "viewer", via: "check" });
    });

    it("treats a deleted entry, or another person at the same name, as gone", async () => {
      const cfg = await setConfig();
      ldaps.entries = ldaps.entries.filter((e) => e.dn !== AD.user("Ben Wilson"));
      await conn.db
        .update(schema.directoryIdentity)
        .set({ uniqueId: "00000000-0000-0000-0000-000000000000" })
        .where(eq(schema.directoryIdentity.userId, "u_asmith"));
      try {
        const summary = await dir.reconcileDirectory(cfg, deps());
        expect(summary).toMatchObject({ removed: 2 });
        expect(await roleOf("u_bwilson")).toBeNull();
        expect(await roleOf("u_asmith")).toBeNull();
        expect(await roleOf("u_jdoe")).toBe("admin");
      } finally {
        ldaps.entries = original;
      }
    });

    it("removes an account the user filter no longer matches, for example a disabled one", async () => {
      const cfg = await setConfig({
        userFilter: "(&(objectClass=user)(sAMAccountName={username})(!(description=disabled)))",
      });
      const entry = ldaps.entries.find(
        (e) => e.dn === AD.user("Ben Wilson"),
      ) as (typeof ldaps.entries)[number];
      entry.attributes.description = ["disabled"];
      try {
        const summary = await dir.reconcileDirectory(cfg, deps());
        expect(summary).toMatchObject({ removed: 1 });
        expect(await roleOf("u_bwilson")).toBeNull();
      } finally {
        delete entry.attributes.description;
      }
    });

    it("changes nobody when the directory cannot be asked", async () => {
      const cfg = await setConfig({ servers: ["ldaps://down.example.lan:1"] });
      expect(await dir.reconcileDirectory(cfg, deps())).toMatchObject({ skipped: true });
      expect(await roleOf("u_jdoe")).toBe("admin");
      expect(await sessionCount("u_jdoe")).toBe(1);
    });

    it("changes nobody when the group search fails half way", async () => {
      const cfg = await setConfig();
      ldaps.failSearchesWith = 53;
      ldaps.failScope = "base";
      expect(await dir.reconcileDirectory(cfg, deps())).toMatchObject({ skipped: true });
      expect(await roleOf("u_jdoe")).toBe("admin");
      expect(await roleOf("u_bwilson")).toBe("viewer");
    });

    it("never touches an owner", async () => {
      const cfg = await setConfig();
      await person("u_owner", "An Owner", "owner", 99, AD.user("Gone Owner"), "gone-owner");
      const summary = await dir.reconcileDirectory(cfg, deps());
      expect(summary).toMatchObject({ checked: 4, removed: 0, changed: 0 });
      expect(await roleOf("u_owner")).toBe("owner");
      expect(await sessionCount("u_owner")).toBe(1);
    });

    it("does nothing while the service account is blocked or the sign-in is off", async () => {
      expect(await dir.reconcileDirectory(await setConfig({ enabled: false }), deps())).toMatchObject({
        skipped: true,
      });
      const blocked = await setConfig({ bindBlockedUntil: new Date(Date.now() + 60_000) });
      expect(await dir.reconcileDirectory(blocked, deps())).toMatchObject({ skipped: true });
      expect(traffic(ldaps)).toEqual([]);
    });
  });

  describe("the queue", () => {
    async function request(
      kind: "sign-in" | "test" | "lookup" | "certificate",
      params: Record<string, string>,
      password?: string,
    ) {
      const id = `dir_${Math.random().toString(36).slice(2, 10)}`;
      let passwordSecretId: string | null = null;
      if (password !== undefined) {
        passwordSecretId = `sec_${Math.random().toString(36).slice(2, 10)}`;
        await conn.db.insert(schema.secret).values({
          id: passwordSecretId,
          organizationId: ORG,
          purpose: "ldap-user-password",
          sealed: seal(
            password,
            { organizationId: ORG, recordId: passwordSecretId, purpose: "ldap-user-password" },
            vaultPublic,
          ),
          vaultKeyId: vaultPublic.id,
        });
      }
      await conn.db
        .insert(schema.directoryRequest)
        .values({ id, organizationId: ORG, kind, params, passwordSecretId });
      return { id, passwordSecretId };
    }
    const row = async (id: string) =>
      (await conn.db.select().from(schema.directoryRequest).where(eq(schema.directoryRequest.id, id)))[0];

    it("opens the sealed password, deletes it at once, and stores an answer without it", async () => {
      await setConfig();
      const { id, passwordSecretId } = await request("sign-in", { username: "asmith" }, USER_PASSWORD);
      await dir.runDirectoryRequest(id, deps());
      const done = await row(id);
      expect(done?.status).toBe("done");
      expect(done?.result).toMatchObject({ outcome: "ok", user: { role: "member", uniqueId: guidText(2) } });
      expect(JSON.stringify(done)).not.toContain(USER_PASSWORD);
      const secrets = await conn.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, passwordSecretId as string));
      expect(secrets).toEqual([]);
      expect(consoleLines.join("\n")).not.toContain(USER_PASSWORD);
    });

    it("deletes the password even when the sign-in is refused or the directory is gone", async () => {
      await setConfig({ servers: ["ldaps://down.example.lan:1"] });
      const { id, passwordSecretId } = await request("sign-in", { username: "asmith" }, USER_PASSWORD);
      await dir.runDirectoryRequest(id, deps());
      expect((await row(id))?.result).toEqual({ outcome: "unavailable", problem: "unreachable" });
      expect(
        await conn.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, passwordSecretId as string)),
      ).toEqual([]);
    });

    it("takes a request once", async () => {
      await setConfig();
      const { id } = await request("lookup", { username: "asmith" });
      await Promise.all([dir.runDirectoryRequest(id, deps()), dir.runDirectoryRequest(id, deps())]);
      expect(searches(ldaps).filter((s) => s.scope === "sub")).toHaveLength(1);
    });

    it("a sign-in without a password is a refusal, not an unauthenticated bind", async () => {
      await setConfig();
      const { id } = await request("sign-in", { username: "asmith" });
      await dir.runDirectoryRequest(id, deps());
      expect((await row(id))?.result).toEqual({ outcome: "invalid-credentials", problem: "wrong-password" });
      expect(traffic(ldaps)).toEqual([]);
    });

    it("a request without a configuration is answered, not left hanging", async () => {
      await conn.db.delete(schema.ldapConfig).where(eq(schema.ldapConfig.organizationId, ORG));
      const { id } = await request("test", {});
      await dir.runDirectoryRequest(id, deps());
      expect((await row(id))?.result).toMatchObject({ ok: false, problem: "not-configured" });
    });

    it("a test that found a person marks these settings as tested", async () => {
      const cfg = await setConfig();
      expect(cfg.testedAt).toBeNull();
      const first = await request("test", { username: "asmith" });
      await dir.runDirectoryRequest(first.id, deps());
      expect((await config())?.testedAt).not.toBeNull();
      // A test without a person proves less and does not mark anything.
      await conn.db
        .update(schema.ldapConfig)
        .set({ testedAt: null })
        .where(eq(schema.ldapConfig.organizationId, ORG));
      const second = await request("test", {});
      await dir.runDirectoryRequest(second.id, deps());
      expect((await config())?.testedAt).toBeNull();
    });

    it("sweeps what nobody collected, and the passwords of requests that never ran", async () => {
      await setConfig();
      const { id, passwordSecretId } = await request("sign-in", { username: "asmith" }, USER_PASSWORD);
      await conn.db.execute(
        sql`update directory_request set created_at = now() - interval '20 minutes' where id = ${id}`,
      );
      await dir.sweepDirectory();
      expect(await row(id)).toBeUndefined();
      expect(
        await conn.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, passwordSecretId as string)),
      ).toEqual([]);
    });
  });
});
