/**
 * Deprecated and yanked packages in the worker (ADR 0051), against a throw-away database: what is asked, what never is, the cache,
 * the own registry's answers kept to the organisation, and errors as "not checked". The registries are replaced by a function.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { dropTestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

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

describe("addresses a registry may have", () => {
  it("refuses loopback, link-local and metadata addresses even for an own server, and private ones for a public one", async () => {
    const { httpsGet, lookupVia } = await import("./outbound.ts");
    for (const host of ["127.0.0.1", "169.254.169.254", "[::1]"]) {
      await expect(httpsGet({ host, path: "/", timeoutMs: 1000, allowPrivate: true })).rejects.toMatchObject({
        code: "refusedAddress",
      });
    }
    await expect(httpsGet({ host: "10.0.0.5", path: "/", timeoutMs: 1000 })).rejects.toMatchObject({
      code: "refusedAddress",
    });
    const answer = (address: string, allowPrivate: boolean) =>
      new Promise<string>((resolve) =>
        lookupVia(async () => [{ address, family: 4 }], allowPrivate)("npm.example.lan", {}, (error) =>
          resolve(error ? "refused" : "ok"),
        ),
      );
    expect(await answer("10.0.0.5", true)).toBe("ok");
    expect(await answer("10.0.0.5", false)).toBe("refused");
    expect(await answer("169.254.169.254", true)).toBe("refused");
    expect(await answer("127.0.0.1", true)).toBe("refused");
  });
});

describe.skipIf(!adminUrl)("deprecated packages in the worker", () => {
  const dbName = `garnetops_deprecated_test_${process.pid}`;
  const org = "org_dep";
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let workerPool: { end(): Promise<void>; on?(e: "error", f: () => void): void };
  let mod: typeof import("./deprecated.ts");
  const asked: { base: string; path: string; own: boolean }[] = [];
  let failNpm = false;

  const fetch: import("./deprecated.ts").RegistryFetch = async (base, path, ecosystem, own) => {
    asked.push({ base, path, own });
    if (ecosystem === "npm" && failNpm) throw Object.assign(new Error("timeout"), { code: "timeout" });
    if (path === "/rimraf")
      return JSON.stringify({
        versions: { "2.7.1": { deprecated: "Rimraf versions prior to v4 are no longer supported" } },
      });
    if (path === "/lodash") return JSON.stringify({ versions: { "4.17.21": {} } });
    if (path === "/pypi/requests/2.0.0/json")
      return JSON.stringify({ urls: [{ yanked: true, yanked_reason: "Broken release" }] });
    if (path === "/se/rd/serde") return '{"vers":"1.0.0","yanked":true}\n{"vers":"1.0.1","yanked":false}';
    return "missing";
  };
  const status = () => conn.db.select().from(schema.packageStatus);

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-deprecated-test-"));
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "grype-not-used",
      GARNETOPS_GRYPE_DB_DIR: workDir,
      GARNETOPS_WORK_DIR: workDir,
    });
    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);
    mod = await import("./deprecated.ts");
    ({ pool: workerPool } = await import("./db.ts"));
    await conn.db.insert(schema.organization).values({ id: org, name: "Deprecated test" });
    await conn.db.insert(schema.repository).values([
      {
        id: "repo_dep",
        organizationId: org,
        name: "app",
        url: "https://git.example.test/a.git",
        authKind: "none",
      },
      {
        id: "repo_old",
        organizationId: org,
        name: "old",
        url: "https://git.example.test/b.git",
        authKind: "none",
        inactiveAt: new Date(),
      },
    ]);
    const pkg = (id: string, repositoryId: string, type: string, name: string, version: string) => ({
      id,
      organizationId: org,
      repositoryId,
      scanId: "scan_x",
      name,
      version,
      type,
    });
    await conn.db
      .insert(schema.repositoryPackage)
      .values([
        pkg("p1", "repo_dep", "npm", "rimraf", "2.7.1"),
        pkg("p2", "repo_dep", "npm", "lodash", "4.17.21"),
        pkg("p3", "repo_dep", "npm", "@acme/ui", "1.0.0"),
        pkg("p4", "repo_dep", "npm", "acme-billing", "2.0.0"),
        pkg("p5", "repo_dep", "python", "requests", "2.0.0"),
        pkg("p6", "repo_dep", "rust-crate", "serde", "1.0.0"),
        pkg("p7", "repo_dep", "go-module", "golang.org/x/net", "0.1.0"),
        pkg("p8", "repo_old", "npm", "left-pad", "1.0.0"),
      ]);
  }, 60_000);

  afterAll(async () => {
    for (const pool of [workerPool, conn?.pool] as { on?(e: "error", f: () => void): void }[])
      pool?.on?.("error", () => {});
    await workerPool?.end();
    await conn?.pool.end();
    if (admin) await dropTestDatabase(admin.pool, dbName);
    await admin?.pool.end();
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it("asks nothing while the module is off", async () => {
    await mod.checkOrganization(org, fetch);
    expect(asked).toEqual([]);
  });

  it("asks the public registries about active repositories' names, never excluded ones, and keeps the answers", async () => {
    await conn.db
      .insert(schema.deprecationSettings)
      .values({ organizationId: org, enabled: true, excluded: ["@acme", "acme-*"] });
    const now = new Date("2026-11-15T10:00:00Z");
    await mod.checkOrganization(org, fetch, now);
    expect(asked.map((a) => `${a.base}${a.path}`).sort()).toEqual([
      "https://index.crates.io/se/rd/serde",
      "https://pypi.org/pypi/requests/2.0.0/json",
      "https://registry.npmjs.org/lodash",
      "https://registry.npmjs.org/rimraf",
    ]);
    expect(asked.every((a) => !a.own)).toBe(true);
    const rows = await status();
    expect(rows.map((r) => [r.scope, r.ecosystem, r.name, r.version, r.state, r.message]).sort()).toEqual([
      ["public", "crates", "serde", "1.0.0", "yanked", null],
      ["public", "npm", "lodash", "4.17.21", "current", null],
      [
        "public",
        "npm",
        "rimraf",
        "2.7.1",
        "deprecated",
        "Rimraf versions prior to v4 are no longer supported",
      ],
      ["public", "pypi", "requests", "2.0.0", "yanked", "Broken release"],
    ]);
    const [settings] = await conn.db.select().from(schema.deprecationSettings);
    expect(settings?.lastRun).toMatchObject({ asked: 4, failed: 0, skipped: 2 });

    // Within a day nothing is asked again; after a day it is.
    asked.length = 0;
    await mod.checkOrganization(org, fetch, new Date("2026-11-15T20:00:00Z"));
    expect(asked).toEqual([]);
    expect(await mod.dueOrganizations(new Date("2026-11-15T20:00:00Z"))).toEqual([]);
    // The run at 20:00 counts, though it asked nothing: due again a day after it.
    expect(await mod.dueOrganizations(new Date("2026-11-16T19:59:59Z"))).toEqual([]);
    expect(await mod.dueOrganizations(new Date("2026-11-16T20:00:01Z"))).toEqual([org]);
  });

  it("keeps an own registry's answers to the organisation, and stores nothing for a registry that fails", async () => {
    await conn.db
      .update(schema.deprecationSettings)
      .set({ registries: { npm: "https://npm.example.lan:8443/repository/npm" } })
      .where(eq(schema.deprecationSettings.organizationId, org));
    asked.length = 0;
    failNpm = true;
    await mod.checkOrganization(org, fetch, new Date("2026-11-15T21:00:00Z"));
    failNpm = false;
    expect(asked.map((a) => [a.base, a.path, a.own])).toEqual(
      [
        ["https://npm.example.lan:8443/repository/npm", "/lodash", true],
        ["https://npm.example.lan:8443/repository/npm", "/rimraf", true],
      ].sort(),
    );
    expect((await status()).filter((r) => r.scope === org)).toEqual([]);
    const [settings] = await conn.db.select().from(schema.deprecationSettings);
    expect(settings?.lastRun).toMatchObject({ failed: 2, problems: { npm: "failed" } });

    await mod.checkOrganization(org, fetch, new Date("2026-11-15T22:00:00Z"));
    expect((await status()).filter((r) => r.scope === org).map((r) => [r.name, r.state])).toEqual(
      expect.arrayContaining([
        ["rimraf", "deprecated"],
        ["lodash", "current"],
      ]),
    );
  });

  it("sweeps answers older than a week and those of organisations that are gone", async () => {
    await conn.db.insert(schema.packageStatus).values({
      scope: "org_gone",
      ecosystem: "npm",
      name: "x",
      version: "1.0.0",
      state: "current",
      checkedAt: new Date("2026-11-15T22:00:00Z"),
    });
    await mod.sweepPackageStatus(new Date("2026-11-20T00:00:00Z"));
    expect((await status()).some((r) => r.scope === "org_gone")).toBe(false);
    expect((await status()).length).toBeGreaterThan(0);
    await mod.sweepPackageStatus(new Date("2026-12-01T00:00:00Z"));
    expect(await status()).toEqual([]);
  });
});
