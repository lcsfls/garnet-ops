/**
 * Secret scanning with the real gitleaks (`pnpm scanners:fetch`), a throw-away database on the development server and a real
 * vault key (ADR 0049). The token in the test repository is built at run time, so no file of this project holds one.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const gitleaksBin = join(
  root,
  ".tools",
  "gitleaks",
  process.platform === "win32" ? "gitleaks.exe" : "gitleaks",
);

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
let hasGit = true;
try {
  execFileSync("git", ["--version"], { stdio: "ignore" });
} catch {
  hasGit = false;
}
const ready = Boolean(adminUrl) && existsSync(gitleaksBin) && hasGit;

// A GitHub token shape and an AWS key id, assembled here so that no file holds one. gitleaks skips values with little
// entropy, so the token's characters come from a small generator, not a repeated pattern.
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
let seed = 20261109;
const token = `ghp_${Array.from({ length: 36 }, () => {
  seed = (seed * 1103515245 + 12345) % 2 ** 31;
  return ALPHABET[seed % ALPHABET.length];
}).join("")}`;
const awsKey = `AKIA${"QX7RT2LMNB4VWZ5K"}`;

describe.skipIf(!ready)("secret scanning with the real gitleaks", () => {
  const dbName = `garnetops_secret_test_${process.pid}`;
  const org = "org_secrets";
  const repo = { id: "repo_secrets", organizationId: org };
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let workerPool: { end(): Promise<void>; on?(e: "error", f: () => void): void };
  let mod: typeof import("./secret-scan.ts");
  let scanCounter = 0;

  const git = (dir: string, ...args: string[]) =>
    execFileSync("git", ["-C", dir, "-c", "user.name=T", "-c", "user.email=t@example.com", ...args], {
      stdio: "ignore",
    });

  /** A repository on disk: files written, committed, then `after` applied in a second commit. */
  async function repository(files: Record<string, string>, after: Record<string, string | null> = {}) {
    const dir = await mkdtemp(join(workDir, "repo-"));
    const write = (set: Record<string, string | null>) => {
      for (const [path, text] of Object.entries(set)) {
        const full = join(dir, path);
        if (text === null) {
          rm(full, { force: true });
          continue;
        }
        mkdirSync(join(full, ".."), { recursive: true });
        writeFileSync(full, text);
      }
    };
    execFileSync("git", ["init", "-q", dir]);
    write(files);
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "first");
    if (Object.keys(after).length > 0) {
      write(after);
      await new Promise((r) => setTimeout(r, 50));
      git(dir, "add", "-A");
      git(dir, "commit", "-qm", "second");
    }
    return dir;
  }

  async function scanAndStore(dir: string, history = false, repoConfig = false) {
    const out = await mkdtemp(join(workDir, "out-"));
    const result = await mod.runSecretScan(dir, out, org, history, repoConfig);
    const scanId = `scan_${++scanCounter}`;
    const summary = await conn.db.transaction((tx) =>
      mod.persistSecrets(tx as never, scanId, repo, result, new Date()),
    );
    return { result, summary };
  }

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-secret-test-"));
    const keys = generateVaultKeyPair();
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "grype-not-used",
      GARNETOPS_GRYPE_DB_DIR: workDir,
      GARNETOPS_GITLEAKS_BIN: gitleaksBin,
      GARNETOPS_WORK_DIR: workDir,
    });
    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);
    mod = await import("./secret-scan.ts");
    ({ pool: workerPool } = await import("./db.ts"));
    await conn.db.insert(schema.organization).values({ id: org, name: "Secrets test" });
    await conn.db.insert(schema.repository).values({
      id: repo.id,
      organizationId: org,
      name: "fixture",
      url: "https://git.example.test/team/fixture.git",
      authKind: "none",
    });
  }, 60_000);

  afterAll(async () => {
    // Dropping the database below ends connections a pool may still be closing; that is expected here.
    for (const pool of [workerPool, conn?.pool] as { on?(e: "error", f: () => void): void }[])
      pool?.on?.("error", () => {});
    await workerPool?.end();
    await conn?.pool.end();
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin?.pool.end();
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  const rows = () =>
    conn.db.select().from(schema.secretFinding).where(eq(schema.secretFinding.repositoryId, repo.id));

  it("finds secrets and sensitive files with GarnetOps' rules, whatever the repository says, and stores no value", async () => {
    const dir = await repository({
      "src/config.js": `export const token = "${token}"; // gitleaks:allow\n`,
      "deploy/copy.js": `const again = "${token}";\n`,
      ".env": "DATABASE_PASSWORD=correct-horse-battery\n",
      ".env.example": "DATABASE_PASSWORD=\n",
      // A repository that tries to switch the check off.
      ".gitleaks.toml": 'title = "off"\n[allowlist]\npaths = [".*"]\n',
      ".gitleaksignore": "src/config.js:github-pat:1\n",
    });
    const { result, summary } = await scanAndStore(dir);
    expect(result.state).toBe("done");
    expect(result.tree.map((h) => `${h.ruleId} ${h.path}`).sort()).toEqual([
      "garnetops-env-file .env",
      "github-pat deploy/copy.js",
      "github-pat src/config.js",
    ]);
    // The same token in two files is one secret.
    expect(summary).toEqual({ counts: { critical: 1, high: 1 }, newSecrets: 2 });
    const stored = await rows();
    expect(stored).toHaveLength(2);
    const pat = stored.find((r) => r.ruleId === "github-pat");
    expect(pat).toMatchObject({ state: "open", severity: "critical", inTree: true, treeLocationCount: 2 });
    expect(pat?.treeLocations).toEqual(
      expect.arrayContaining([
        { path: "src/config.js", line: 1 },
        { path: "deploy/copy.js", line: 1 },
      ]),
    );
    const everything = JSON.stringify(await conn.db.select().from(schema.secretFinding));
    expect(everything).not.toContain(token);
    expect(everything).not.toContain(token.slice(4, 14));
    expect(everything).not.toContain("correct-horse");
    // One fingerprint key, sealed: never readable in the database.
    const keys = await conn.db
      .select()
      .from(schema.secret)
      .where(eq(schema.secret.purpose, "secret-fingerprint-key"));
    expect(keys).toHaveLength(1);
    expect(JSON.stringify(keys[0]?.sealed)).not.toMatch(/^"[A-Za-z0-9+/=]{44}"$/);
  });

  it("keeps a secret open when the file is gone, keeps a dismissal, and lets the gate skip closed ones", async () => {
    const pat = (await rows()).find((r) => r.ruleId === "github-pat");
    const env = (await rows()).find((r) => r.ruleId === "garnetops-env-file");
    await conn.db
      .update(schema.secretFinding)
      .set({ state: "dismissed", stateReason: "a test value, never used" })
      .where(eq(schema.secretFinding.id, env?.id as string));

    // Same token in one file now, .env still there; another scan of the same repository content.
    const dir = await repository({
      "src/config.js": `export const token = "${token}";\n`,
      ".env": "DATABASE_PASSWORD=correct-horse-battery\n",
    });
    const { result, summary } = await scanAndStore(dir);
    expect(summary).toEqual({ counts: { critical: 1 }, newSecrets: 0 });
    const gate = await conn.db.transaction((tx) => mod.gateSecrets(tx as never, repo, result));
    expect(gate).toEqual([{ severity: "critical" }]);
    expect((await rows()).find((r) => r.id === env?.id)).toMatchObject({ state: "dismissed", inTree: true });

    // The token removed from the files: still open, only in the history now.
    const clean = await repository({ "src/config.js": "export const token = process.env.TOKEN;\n" });
    const after = await scanAndStore(clean);
    expect(after.summary).toEqual({ counts: {}, newSecrets: 0 });
    expect((await rows()).find((r) => r.id === pat?.id)).toMatchObject({
      state: "open",
      inTree: false,
      treeLocations: [],
      treeLocationCount: 0,
    });
  });

  it("finds a secret that only the history still has, with its commit, and records the check", async () => {
    const dir = await repository(
      { "config/aws.ini": `aws_access_key_id = ${awsKey}\n` },
      { "config/aws.ini": "aws_access_key_id = from-the-environment\n" },
    );
    const plain = await scanAndStore(dir);
    expect(plain.result.tree).toEqual([]);
    expect(plain.result.history).toBeNull();

    const { result, summary } = await scanAndStore(dir, true);
    expect(result.history?.map((h) => [h.ruleId, h.path, h.line])).toEqual([
      ["aws-access-token", "config/aws.ini", 1],
    ]);
    expect(result.history?.[0]?.commit).toMatch(/^[0-9a-f]{40}$/);
    // Seen in this scan, in the history: counted, and new.
    expect(summary).toEqual({ counts: { critical: 1 }, newSecrets: 1 });
    const aws = (await rows()).find((r) => r.ruleId === "aws-access-token");
    expect(aws).toMatchObject({
      state: "open",
      inTree: false,
      historyLocationCount: 1,
      severity: "critical",
    });
    expect(aws?.historyLocations[0]).toMatchObject({ path: "config/aws.ini", line: 1 });
    const [r] = await conn.db.select().from(schema.repository).where(eq(schema.repository.id, repo.id));
    expect(r?.secretHistoryCheckedAt).toBeInstanceOf(Date);
    expect(JSON.stringify(await rows())).not.toContain(awsKey);
  });

  it("sets aside what an ignore rule covers everywhere, counts it nowhere, and brings it back when the rule goes", async () => {
    await conn.db.insert(schema.secretIgnoreRule).values({
      id: "sir_fixtures",
      organizationId: org,
      repositoryId: repo.id,
      pathPattern: "test/fixtures/**",
      ruleId: null,
      reason: "Fake keys for the parser tests",
    });
    const fixtures = await repository({
      "test/fixtures/keys/config.js": `export const key = "${token}";\n`,
      ".env": "DATABASE_PASSWORD=correct-horse-battery\n",
    });
    const { result, summary } = await scanAndStore(fixtures);
    // The token only in fixtures: set aside, not counted; the .env (dismissed above) is not counted either.
    expect(summary).toEqual({ counts: {}, newSecrets: 0 });
    const pat = (await rows()).find((r) => r.ruleId === "github-pat");
    expect(pat).toMatchObject({ state: "open", ignoredBy: "sir_fixtures" });
    expect(await conn.db.transaction((tx) => mod.gateSecrets(tx as never, repo, result))).toEqual([]);

    // The same value also outside the fixtures: it counts again.
    const both = await repository({
      "test/fixtures/keys/config.js": `export const key = "${token}";\n`,
      "src/live.js": `export const key = "${token}";\n`,
    });
    const again = await scanAndStore(both);
    expect(again.summary).toEqual({ counts: { critical: 1 }, newSecrets: 0 });
    expect((await rows()).find((r) => r.ruleId === "github-pat")?.ignoredBy).toBeNull();

    // Removing the rule (the API does this at once) leaves nothing set aside.
    await scanAndStore(fixtures);
    expect((await rows()).find((r) => r.ruleId === "github-pat")?.ignoredBy).toBe("sir_fixtures");
    await conn.db.delete(schema.secretIgnoreRule).where(eq(schema.secretIgnoreRule.id, "sir_fixtures"));
    const { applySecretIgnoreRules } = await import("@garnetops/db");
    await applySecretIgnoreRules(conn.db, org);
    expect((await rows()).every((r) => r.ignoredBy === null)).toBe(true);
  });

  it("never lets the repository's .gitleaksignore hide a secret, in the files or in the history", async () => {
    // A second token, so that it is new to this repository's findings.
    const hidden = `ghp_${Array.from({ length: 36 }, () => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return ALPHABET[seed % ALPHABET.length];
    }).join("")}`;
    const dir = await repository({ "tools/deploy.js": `const key = "${hidden}";\n` });
    const commit = execFileSync("git", ["-C", dir, "rev-parse", "HEAD"]).toString().trim();
    // The fingerprints gitleaks itself prints for this place, in history and in file mode.
    writeFileSync(
      join(dir, ".gitleaksignore"),
      `${commit}:tools/deploy.js:github-pat:1\ntools/deploy.js:github-pat:1\n${join(dir, "tools/deploy.js")}:github-pat:1\n`,
    );
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "ignore it");

    const { result } = await scanAndStore(dir, true);
    expect(result.tree.map((h) => [h.ruleId, h.path])).toContainEqual(["github-pat", "tools/deploy.js"]);
    expect(result.history?.map((h) => [h.ruleId, h.path, h.commit])).toContainEqual([
      "github-pat",
      "tools/deploy.js",
      commit,
    ]);
  });

  it("respects the repository's own configuration when switched on: adds its rules' finds, sets aside what it hides", async () => {
    const next = () =>
      `ghp_${Array.from({ length: 36 }, () => {
        seed = (seed * 1103515245 + 12345) % 2 ** 31;
        return ALPHABET[seed % ALPHABET.length];
      }).join("")}`;
    const [open, inline, fixture, listed] = [next(), next(), next(), next()];
    const acme = `acme_${next().slice(4, 28)}`;
    const dir = await repository({
      ".gitleaks.toml": [
        "[extend]",
        'path = "/etc/passwd"',
        "",
        "[[rules]]",
        'id = "acme-key"',
        'description = "ACME key"',
        "regex = '''acme_[A-Za-z0-9]{24}'''",
        "",
        "[allowlist]",
        "paths = ['''^test/fixtures/''']",
        "",
      ].join("\n"),
      "app/open.js": `const a = "${open}";\n`,
      "app/inline.js": `const b = "${inline}"; // gitleaks:allow\n`,
      "test/fixtures/fake.js": `const c = "${fixture}";\n`,
      "app/listed.js": `const d = "${listed}";\n`,
      "app/acme.txt": `${acme}\n`,
      ".gitleaksignore": "app/listed.js:github-pat:1\n",
    });
    const byPath = async (path: string) =>
      (await rows()).find((r) => r.treeLocations.some((l) => l.path === path));

    const on = await scanAndStore(dir, false, true);
    expect(on.result.repo?.problem).toBeNull();
    expect(on.result.repo?.file).toBe(".gitleaks.toml");
    expect(on.result.repo?.ignoreFile).toBe(true);
    for (const path of ["app/inline.js", "test/fixtures/fake.js", "app/listed.js"]) {
      expect(await byPath(path), path).toMatchObject({ state: "open", setAsideByRepository: true });
    }
    expect(await byPath("app/open.js")).toMatchObject({ setAsideByRepository: false });
    // The repository's own rule adds a finding.
    expect(await byPath("app/acme.txt")).toMatchObject({ ruleId: "acme-key", setAsideByRepository: false });
    const [r1] = await conn.db.select().from(schema.repository).where(eq(schema.repository.id, repo.id));
    expect(r1?.secretRepoConfigResult).toMatchObject({
      problem: null,
      setAside: 3,
      added: 1,
      file: ".gitleaks.toml",
    });
    // The scan's summary counts neither what the repository hides; it counts its own rule's find.
    expect(on.summary?.newSecrets).toBe(2);

    // A file GarnetOps cannot use safely sets nothing aside.
    writeFileSync(join(dir, ".gitleaks.toml"), 'extend = { path = "/etc/passwd" }\n');
    writeFileSync(join(dir, ".gitleaksignore"), "app/listed.js:github-pat:1\n");
    const refused = await scanAndStore(dir, false, true);
    expect(refused.result.repo?.problem).toBe("extendForm");
    expect(await byPath("app/listed.js")).toMatchObject({ setAsideByRepository: false });

    // Switched off: the strict run alone, nothing set aside.
    writeFileSync(join(dir, ".gitleaksignore"), "app/listed.js:github-pat:1\n");
    const off = await scanAndStore(dir, false, false);
    expect(off.result.repo).toBeUndefined();
    expect((await rows()).filter((r) => r.setAsideByRepository)).toEqual([]);
  });

  it("leaves findings alone when the secret check did not run", async () => {
    const before = await rows();
    const summary = await conn.db.transaction((tx) =>
      mod.persistSecrets(
        tx as never,
        "scan_x",
        repo,
        { state: "failed", tree: [], history: null },
        new Date(),
      ),
    );
    expect(summary).toBeNull();
    expect(await rows()).toEqual(before);
    expect(
      await conn.db.transaction((tx) =>
        mod.gateSecrets(tx as never, repo, { state: "skipped", tree: [], history: null }),
      ),
    ).toBeUndefined();
  });
});
