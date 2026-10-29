/**
 * Reading open pull requests (ADR 0032) against a fake forge (HTTPS, throw-away certificate) and a throw-away PostgreSQL
 * database with a real vault key: through a connection, stored and replaced, hostile titles cleaned and cut, links built
 * from the repository address, pull requests that closed removed, and problems stored as codes. Skipped without the
 * development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { FakeForge, FORGE_HOST } from "../test/fake-forge.ts";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-pulls-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_pulls";
const ALEX = "user_alex";
const TOKEN = "read-token-0123456789abcdef";

describe.skipIf(!adminUrl || !openssl)("open pull requests", () => {
  let t: TestDatabase;
  let mod: typeof import("./pull-requests.ts");
  let forgeMod: typeof import("./forge.ts");
  let forge: FakeForge;
  let repo: typeof schema.repository.$inferSelect;

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    const publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_pulls");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
    });
    mod = await import("./pull-requests.ts");
    forgeMod = await import("./forge.ts");
    vi.spyOn(console, "error").mockImplementation(() => {});
    forge = await new FakeForge("gitea", TOKEN, "team", "app", { files: { "README.md": "hi" } }).start();
    forgeMod.setForgeTestHooks({
      resolve: async () => ["192.168.1.20"],
      connectTo: () => "127.0.0.1",
      ca: forge.ca,
    });

    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db.insert(schema.user).values({ id: ALEX, name: "Alex Example", email: "alex@example.test" });
    const secretId = "sec_pulls";
    await t.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "forge-connection-token",
      sealed: seal(
        TOKEN,
        { organizationId: ORG, recordId: secretId, purpose: "forge-connection-token" },
        publicKey,
      ),
      vaultKeyId: publicKey.id,
    });
    const web = forge.apiBase.replace(/\/api\/v1$/, "");
    await t.db.insert(schema.forgeConnection).values({
      id: "fcn_pulls",
      organizationId: ORG,
      userId: ALEX,
      forgeKind: "gitea",
      webBaseUrl: web,
      apiBaseUrl: forge.apiBase,
      secretId,
    });
    [repo] = (await t.db
      .insert(schema.repository)
      .values({
        id: "repo_pulls",
        organizationId: ORG,
        name: "app",
        url: `${web}/team/app.git`,
        authKind: "connection",
        forgeConnectionId: "fcn_pulls",
        visibility: "private",
        ownerUserId: ALEX,
      })
      .returning()) as [typeof schema.repository.$inferSelect];
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    forgeMod?.setForgeTestHooks(null);
    await forge?.stop();
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  const stored = async () =>
    t.db.select().from(schema.pullRequest).where(eq(schema.pullRequest.repositoryId, "repo_pulls"));

  it("stores the open pull requests, cleaned, with links built from the repository address", async () => {
    forge.extraPulls = [
      {
        number: 7,
        title: `<script>alert(1)</script>\u0000\u0007${"x".repeat(1000)}`,
        user: { login: "mallory\u001b[31m" },
        head: { ref: "feature/one", sha: "A".repeat(40) },
        base: { ref: "main" },
        html_url: "https://evil.example.com/phish",
        draft: true,
        created_at: "2026-10-27T08:00:00Z",
        updated_at: "2026-10-29T09:00:00Z",
      },
      { number: 8, title: "No real commit", head: { ref: "x", sha: "not-a-sha" } },
    ];
    await mod.refreshRepositoryPullRequests(repo);
    const rows = await stored();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      number: 7,
      author: "mallory [31m",
      headRef: "feature/one",
      headSha: "a".repeat(40),
      baseRef: "main",
      draft: true,
      url: `https://${FORGE_HOST}:${new URL(forge.apiBase).port}/team/app/pulls/7`,
    });
    expect(rows[0]?.title.startsWith("<script>alert(1)</script> x")).toBe(true);
    expect(rows[0]?.title.length).toBe(300);
    expect(JSON.stringify(rows)).not.toContain("evil.example.com");
    const [after] = await t.db.select().from(schema.repository).where(eq(schema.repository.id, "repo_pulls"));
    expect(after?.pullRequestsProblem).toBeNull();
    expect(after?.pullRequestsCheckedAt).not.toBeNull();
    // Read with the connection's token, nothing written.
    expect(forge.requests.every((r) => r.method === "GET")).toBe(true);
  });

  it("removes pull requests that are no longer open", async () => {
    forge.extraPulls = [];
    await mod.refreshRepositoryPullRequests(repo);
    expect(await stored()).toEqual([]);
  });

  it("stores problems as short codes and keeps the stored list", async () => {
    forge.extraPulls = [{ number: 9, title: "Open", head: { ref: "b", sha: "b".repeat(40) } }];
    await mod.refreshRepositoryPullRequests(repo);
    forge.faults.push({ match: /pulls/, status: 500 });
    await mod.refreshRepositoryPullRequests(repo);
    forge.faults.length = 0;
    expect(await stored()).toHaveLength(1);
    const [after] = await t.db.select().from(schema.repository).where(eq(schema.repository.id, "repo_pulls"));
    expect(after?.pullRequestsProblem).toBe("http-error");

    const [unknown] = await t.db
      .insert(schema.repository)
      .values({
        id: "repo_unknown",
        organizationId: ORG,
        name: "other",
        url: "https://code.example.lan/team/other.git",
        authKind: "none",
      })
      .returning();
    await mod.refreshRepositoryPullRequests(unknown as typeof schema.repository.$inferSelect);
    const [u] = await t.db.select().from(schema.repository).where(eq(schema.repository.id, "repo_unknown"));
    expect(u?.pullRequestsProblem).toBe("forge-unknown");
  });
});
