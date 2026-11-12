/**
 * The code viewer's job against a real database (ADR 0048). The clone is replaced: it writes a small repository into the target
 * directory, and can refuse a single commit the way a forge without "allow reachable SHA-1 in want" does.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
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

const clone = vi.hoisted(() => ({ refuseCommit: false, refs: [] as (string | null)[] }));
vi.mock("./git.ts", () => ({
  sshClient: async () => ({ bin: "ssh", kex: [] }),
  shallowClone: async (options: { dir: string; ref: string | null }) => {
    clone.refs.push(options.ref);
    if (options.ref && clone.refuseCommit) throw new Error("couldn't find remote ref");
    const files: Record<string, string> = {
      "package.json": '{\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n',
      "package-lock.json":
        '{\n  "packages": {\n    "node_modules/lodash": {\n      "version": "4.17.15"\n    }\n  }\n}\n',
      "src/a.ts": 'import _ from "lodash";\nexport const x = _.merge({}, {});\n',
      "node_modules/lodash/index.js": 'require("lodash");\n',
    };
    for (const [path, text] of Object.entries(files)) {
      mkdirSync(join(options.dir, path, ".."), { recursive: true });
      writeFileSync(join(options.dir, path), text);
    }
    return { commitSha: options.ref ?? "b".repeat(40), branch: "main" };
  },
}));

describe.skipIf(!adminUrl)("code viewer job", () => {
  const dbName = `garnetops_code_test_${process.pid}`;
  const org = "org_code";
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let workerPool: { end(): Promise<void>; on?(e: "error", f: () => void): void };
  let mod: typeof import("./code-view.ts");
  let counter = 0;

  async function request(user = "usr_member") {
    const id = `cod_t${++counter}`;
    await conn.db.insert(schema.codeRequest).values({
      id,
      organizationId: org,
      requestedBy: user,
      findingId: "fnd_code",
      repositoryId: "repo_code",
    });
    await mod.runCodeRequest(id);
    const [row] = await conn.db.select().from(schema.codeRequest).where(eq(schema.codeRequest.id, id));
    return row;
  }

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-code-test-"));
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
    mod = await import("./code-view.ts");
    ({ pool: workerPool } = await import("./db.ts"));
    await conn.db.insert(schema.organization).values({ id: org, name: "Code test" });
    await conn.db.insert(schema.user).values([
      { id: "usr_member", name: "Member", email: "member@example.com" },
      { id: "usr_viewer", name: "Viewer", email: "viewer@example.com" },
      { id: "usr_other", name: "Other", email: "other@example.com" },
    ]);
    await conn.db.insert(schema.membership).values([
      { organizationId: org, userId: "usr_member", role: "member" },
      { organizationId: org, userId: "usr_viewer", role: "viewer" },
      { organizationId: org, userId: "usr_other", role: "member" },
    ]);
    await conn.db.insert(schema.repository).values({
      id: "repo_code",
      organizationId: org,
      name: "app",
      url: "https://git.example.test/team/app.git",
      authKind: "none",
      visibility: "private",
      ownerUserId: "usr_member",
    });
    await conn.db.insert(schema.scan).values({
      id: "scan_code",
      organizationId: org,
      repositoryId: "repo_code",
      state: "succeeded",
      trigger: "manual",
      commitSha: "a".repeat(40),
    });
    await conn.db.insert(schema.vulnerability).values({ id: "GHSA-test-code-0001", severity: "high" });
    const now = new Date();
    await conn.db.insert(schema.finding).values({
      id: "fnd_code",
      organizationId: org,
      repositoryId: "repo_code",
      vulnerabilityId: "GHSA-test-code-0001",
      dedupKey: "code-test",
      packageName: "lodash",
      packageVersion: "4.17.15",
      packageType: "npm",
      locations: ["/package-lock.json"],
      severity: "high",
      severityRank: 4,
      state: "open",
      firstSeenScanId: "scan_code",
      lastSeenScanId: "scan_code",
      firstSeenAt: now,
      lastSeenAt: now,
    });
    await conn.db.insert(schema.repositoryManifest).values({
      id: "man_code",
      organizationId: org,
      repositoryId: "repo_code",
      scanId: "scan_code",
      path: "package.json",
      kind: "npm",
      blobSha: "c".repeat(40),
      size: 60,
      dependencies: [
        { name: "lodash", section: "dependencies", spec: "^4.17.15", indirect: false, dev: false },
      ],
    });
  }, 60_000);

  afterAll(async () => {
    for (const pool of [workerPool, conn?.pool] as { on?(e: "error", f: () => void): void }[])
      pool?.on?.("error", () => {});
    await workerPool?.end();
    await conn?.pool.end();
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin?.pool.end();
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it("reads the declarations and usages at the scanned commit, and removes the clone", async () => {
    const row = await request();
    expect(row?.state).toBe("done");
    expect(clone.refs.at(-1)).toBe("a".repeat(40));
    const view = row?.result as Record<string, unknown> & {
      declarations: { path: string; role: string; marks: number[] }[];
      usages: { path: string; marks: number[] }[];
    };
    expect(view).toMatchObject({
      commit: "a".repeat(40),
      scanCommit: "a".repeat(40),
      ecosystem: "npm",
      usageCount: 1,
    });
    expect(view.declarations.map((d) => [d.path, d.role, d.marks])).toEqual([
      ["package.json", "manifest", [3]],
      ["package-lock.json", "lockfile", [3]],
    ]);
    expect(view.usages.map((u) => [u.path, u.marks])).toEqual([["src/a.ts", [1]]]);
    expect((await readdir(workDir)).filter((n) => n.startsWith("code-"))).toEqual([]);
  });

  it("falls back to the branch head when the forge will not hand out the commit, and says so", async () => {
    clone.refuseCommit = true;
    const row = await request();
    clone.refuseCommit = false;
    expect(clone.refs.slice(-2)).toEqual(["a".repeat(40), null]);
    expect(row?.result).toMatchObject({ commit: "b".repeat(40), scanCommit: "a".repeat(40) });
  });

  it("checks the person again: a viewer, or someone who does not see the private repository, gets nothing", async () => {
    for (const user of ["usr_viewer", "usr_other"]) {
      const before = clone.refs.length;
      const row = await request(user);
      expect(row).toMatchObject({ state: "failed", result: null });
      expect(clone.refs.length).toBe(before);
    }
  });

  it("sweeps requests older than ten minutes", async () => {
    await conn.db.insert(schema.codeRequest).values({
      id: "cod_old",
      organizationId: org,
      requestedBy: "usr_member",
      findingId: "fnd_code",
      repositoryId: "repo_code",
      createdAt: new Date(Date.now() - 11 * 60_000),
    });
    await mod.sweepCodeRequests();
    expect(
      await conn.db.select().from(schema.codeRequest).where(eq(schema.codeRequest.id, "cod_old")),
    ).toEqual([]);
  });
});
