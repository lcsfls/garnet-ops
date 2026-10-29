/**
 * Personal forge connections in the worker (ADR 0030) against a fake forge (GitHub and Gitea/Forgejo flavours,
 * HTTPS with a throw-away certificate) and a throw-away PostgreSQL database with a real vault key: the token check,
 * the stored list (paged, cut at the limit, foreign clone addresses left out), failures as short codes, a job that
 * names the wrong person, and that channels never hear of a private repository. Skipped without the development
 * PostgreSQL or openssl.
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
const work = mkdtempSync(join(tmpdir(), "garnetops-connection-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_conn";
const ALEX = "user_alex";
const TOKEN = "read-token-0123456789abcdef";

describe.skipIf(!adminUrl || !openssl)("personal forge connections", () => {
  let t: TestDatabase;
  let mod: typeof import("./forge-connection.ts");
  let forgeMod: typeof import("./forge.ts");
  let notify: typeof import("./notify.ts");
  let publicKey: ReturnType<typeof loadVaultPublicKey>;
  const logs: string[] = [];
  let ids = 0;

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_connection");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
    });
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db.insert(schema.user).values({ id: ALEX, name: "Alex Example", email: "alex@example.test" });
    mod = await import("./forge-connection.ts");
    forgeMod = await import("./forge.ts");
    notify = await import("./notify.ts");
    for (const level of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(args.map(String).join(" "));
      });
    }
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    forgeMod?.setForgeTestHooks(null);
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  /** A connection of Alex's to the fake forge, with a sealed token. */
  async function connect(forge: FakeForge, token = TOKEN) {
    const n = ++ids;
    const secretId = `sec_conn${n}`;
    await t.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "forge-connection-token",
      sealed: seal(
        token,
        { organizationId: ORG, recordId: secretId, purpose: "forge-connection-token" },
        publicKey,
      ),
      vaultKeyId: publicKey.id,
    });
    const id = `fcn_${n}`;
    await t.db.insert(schema.forgeConnection).values({
      id,
      organizationId: ORG,
      userId: ALEX,
      forgeKind: forge.flavour,
      // One connection per forge address and person: each test connection gets its own sub-path.
      webBaseUrl: `https://${FORGE_HOST}/c${n}`,
      apiBaseUrl: forge.apiBase,
      secretId,
    });
    return id;
  }
  const row = async (id: string) =>
    (await t.db.select().from(schema.forgeConnection).where(eq(schema.forgeConnection.id, id)))[0];
  const listedOf = async (id: string) =>
    t.db
      .select()
      .from(schema.forgeConnectionRepository)
      .where(eq(schema.forgeConnectionRepository.connectionId, id));

  describe.each([
    ["github", "github" as const],
    ["gitea", "gitea" as const],
  ])("%s", (_name, flavour) => {
    let forge: FakeForge;

    beforeAll(async () => {
      forge = await new FakeForge(flavour, TOKEN, "team", "app", {
        scopes: flavour === "github" ? "repo, read:org" : undefined,
      }).start();
      forgeMod.setForgeTestHooks({
        resolve: async () => ["192.168.1.20"],
        connectTo: () => "127.0.0.1",
        ca: forge.ca,
      });
    });
    afterAll(async () => {
      await forge.stop();
    });

    it("checks the token and stores what the account can see, page by page", async () => {
      // More than one page in either flavour, plus entries that are not repositories on this forge.
      forge.listed = [
        ...Array.from({ length: 120 }, (_, i) => ({
          id: 1000 + i,
          full_name: `team/app-${String(i).padStart(3, "0")}`,
          clone_url: `https://${FORGE_HOST}/team/app-${String(i).padStart(3, "0")}.git`,
          default_branch: "main",
          private: i % 2 === 0,
          archived: i === 5,
          description: i === 1 ? "line\u0007one\u0000<b>two</b>" : null,
        })),
        {
          id: 1,
          full_name: "team/elsewhere",
          clone_url: "https://evil.example.com/team/elsewhere.git",
          private: false,
        },
        { id: 2, full_name: "team/plain", clone_url: `http://${FORGE_HOST}/team/plain.git`, private: false },
        { id: 3, full_name: "a/b/c", clone_url: `https://${FORGE_HOST}/a/b/c.git`, private: false },
      ];
      const id = await connect(forge);
      await mod.refreshConnection({ connectionId: id, organizationId: ORG, userId: ALEX });
      const stored = await row(id);
      expect(stored).toMatchObject({
        state: "ok",
        problem: null,
        accountLogin: "alex",
        broadToken: flavour === "github",
        truncated: false,
      });
      const items = await listedOf(id);
      expect(items).toHaveLength(120);
      expect(items.find((i) => i.forgeId === "1001")).toMatchObject({
        fullName: "team/app-001",
        cloneUrl: `https://${FORGE_HOST}/team/app-001.git`,
        private: false,
        description: "line one <b>two</b>",
      });
      expect(items.find((i) => i.forgeId === "1005")?.archived).toBe(true);
      expect(items.some((i) => ["1", "2", "3"].includes(i.forgeId))).toBe(false);
      // Only the account endpoints were asked, always with the token, never anything that writes.
      expect(forge.requests.every((r) => r.method === "GET" && r.authorization === forge.authorization)).toBe(
        true,
      );
      expect(new Set(forge.requests.map((r) => r.path.replace(forge.prefix, "")))).toEqual(
        new Set(["/user", "/user/repos"]),
      );
      forge.requests.length = 0;

      // A refresh replaces the list.
      forge.listed = forge.listed.slice(0, 3);
      await mod.refreshConnection({ connectionId: id, organizationId: ORG, userId: ALEX });
      expect(await listedOf(id)).toHaveLength(3);
    });

    it("stores a rejected token as a short code and keeps the previous list", async () => {
      forge.listed = forge.listed.slice(0, 2);
      const id = await connect(forge);
      await mod.refreshConnection({ connectionId: id, organizationId: ORG, userId: ALEX });
      expect(await listedOf(id)).toHaveLength(2);
      forge.faults.push({ match: /^GET .*\/user$/, status: 401 });
      await mod.refreshConnection({ connectionId: id, organizationId: ORG, userId: ALEX });
      forge.faults.length = 0;
      expect(await row(id)).toMatchObject({ state: "failed", problem: "token-rejected" });
      expect(await listedOf(id)).toHaveLength(2);
      // The forge's error text never lands anywhere.
      expect(JSON.stringify(await row(id))).not.toContain("secret details");
    });

    it("does nothing for a job that names another person, and never logs the token", async () => {
      const id = await connect(forge);
      forge.requests.length = 0;
      await mod.refreshConnection({ connectionId: id, organizationId: ORG, userId: "user_someone_else" });
      expect(forge.requests).toEqual([]);
      expect(await row(id)).toMatchObject({ state: "unchecked" });
      expect(logs.join("\n")).not.toContain(TOKEN);
    });
  });

  it("never queues a channel message about a private repository", async () => {
    await t.db.insert(schema.repository).values([
      {
        id: "repo_open",
        organizationId: ORG,
        name: "open",
        url: "https://git.example.lan/t/open.git",
        authKind: "none",
      },
      {
        id: "repo_mine",
        organizationId: ORG,
        name: "mine",
        url: "https://git.example.lan/t/mine.git",
        authKind: "none",
        visibility: "private",
        ownerUserId: ALEX,
      },
    ]);
    await t.db.insert(schema.notificationChannel).values({
      id: "nch_all",
      organizationId: ORG,
      name: "chat",
      kind: "webhook",
      format: "generic",
      events: ["scan.failed"],
      config: {},
    });
    const sent: { channelId: string; payload: { repository?: { id: string } } }[] = [];
    const boss = { send: async (_q: string, data: (typeof sent)[number]) => void sent.push(data) };
    const payload = (id: string, name: string) => ({
      event: "scan.failed" as const,
      organization: { id: ORG, name: "Example Org" },
      repository: { id, name },
      link: `https://garnetops.example.test/repositories/${id}`,
      occurredAt: new Date().toISOString(),
    });
    await notify.queueNotifications(boss as never, ORG, [
      payload("repo_open", "open"),
      payload("repo_mine", "mine"),
    ] as never);
    expect(sent.map((s) => s.payload.repository?.id)).toEqual(["repo_open"]);
  });
});
