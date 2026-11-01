/**
 * Scan on push, registered through a connected account (ADR 0045), in the worker: against a fake forge (GitHub and
 * Gitea/Forgejo flavours, HTTPS with a throw-away certificate) and a throw-away PostgreSQL database on the development
 * server, with a real vault key. Checks that the webhook is created with the creator's own connection only, that every
 * re-check fails with its code before anything is opened, that the handed-over secret is deleted in every outcome, that
 * removing works and counts a missing webhook as removed, the sweep, and that neither token nor secret lands in a row, an
 * audit entry or a log line. Skipped without the development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { and, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeForge, FORGE_HOST } from "../test/fake-forge.ts";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-hookreg-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_hookreg";
const USER = "user_hookreg";
const OTHER_USER = "user_hookreg_other";
const PUBLIC_URL = "https://garnetops.example.test";
/** Built at run time, so no scanner mistakes them for real credentials. */
const TOKEN = ["hookreg", "t".repeat(24)].join("-");
const HOOK_SECRET = "h".repeat(43);

describe.skipIf(!adminUrl || !openssl)("registering webhooks through a connected account", () => {
  let t: TestDatabase;
  let mod: typeof import("./webhook-register.ts");
  let forgeMod: typeof import("./forge.ts");
  let publicKey: ReturnType<typeof loadVaultPublicKey>;
  const logs: string[] = [];
  let ids = 0;

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_hookreg");
    // The worker's modules read their settings when they are first imported.
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
      PUBLIC_URL,
    });
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db.insert(schema.user).values([
      { id: USER, name: "Erika Example", email: "erika@example.test" },
      { id: OTHER_USER, name: "Max Example", email: "max@example.test" },
    ]);
    mod = await import("./webhook-register.ts");
    forgeMod = await import("./forge.ts");
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

  describe.each([
    ["github", "github" as const],
    ["gitea", "gitea" as const],
  ])("%s", (_name, flavour) => {
    let forge: FakeForge;

    async function sealed(purpose: "forge-connection-token" | "webhook-secret", plain: string) {
      const id = `sec_hookreg${++ids}`;
      await t.db.insert(schema.secret).values({
        id,
        organizationId: ORG,
        purpose,
        sealed: seal(plain, { organizationId: ORG, recordId: id, purpose }, publicKey),
        vaultKeyId: publicKey.id,
      });
      return id;
    }

    /** A repository on the fake forge, a connection of `owner`, and a webhook `createdBy` that waits to be registered. */
    async function seed(
      options: {
        owner?: string;
        createdBy?: string;
        connection?: Partial<typeof schema.forgeConnection.$inferInsert>;
        hook?: Partial<typeof schema.repositoryWebhook.$inferInsert>;
      } = {},
    ) {
      const n = ++ids;
      const repositoryId = `repo_hookreg${n}`;
      await t.db.insert(schema.repository).values({
        id: repositoryId,
        organizationId: ORG,
        name: `app${n}`,
        url: forge.repositoryUrl.replace(/app\.git$/, `app${n}.git`),
        authKind: "none",
      });
      // One connection per person and forge: a second repository of the same test uses the same one.
      const webBaseUrl = options.connection?.webBaseUrl ?? `https://${FORGE_HOST}:${forge.port}`;
      const [existing] = await t.db
        .select({ id: schema.forgeConnection.id })
        .from(schema.forgeConnection)
        .where(
          and(
            eq(schema.forgeConnection.userId, options.owner ?? USER),
            eq(schema.forgeConnection.webBaseUrl, webBaseUrl),
          ),
        );
      const connectionId = existing?.id ?? `fcn_hookreg${n}`;
      if (!existing) {
        await t.db.insert(schema.forgeConnection).values({
          id: connectionId,
          organizationId: ORG,
          userId: options.owner ?? USER,
          forgeKind: flavour,
          webBaseUrl,
          apiBaseUrl: forge.apiBase,
          secretId: await sealed("forge-connection-token", TOKEN),
          accountLogin: "erika",
          state: "ok",
          ...options.connection,
        });
      }
      const secretId = await sealed("webhook-secret", HOOK_SECRET);
      const webhookId = `hook_hookreg${n}`;
      const pathId = String(n).padStart(43, "p");
      await t.db.insert(schema.repositoryWebhook).values({
        id: webhookId,
        organizationId: ORG,
        repositoryId,
        pathId,
        secretSealed: "v1.sealed-for-the-api",
        createdBy: options.createdBy ?? USER,
        connectionId,
        registerState: "pending",
        handoverSecretId: secretId,
        ...options.hook,
      });
      return { repositoryId, connectionId, secretId, webhookId, pathId };
    }

    const hook = async (id: string) =>
      (await t.db.select().from(schema.repositoryWebhook).where(eq(schema.repositoryWebhook.id, id)))[0];
    const secretExists = async (id: string) =>
      (await t.db.select().from(schema.secret).where(eq(schema.secret.id, id))).length > 0;
    const audits = async (repositoryId: string) =>
      t.db
        .select()
        .from(schema.auditLog)
        .where(and(eq(schema.auditLog.targetType, "repository"), eq(schema.auditLog.targetId, repositoryId)));
    const run = (s: { webhookId: string; secretId: string }) =>
      mod.runWebhookRegister({ webhookId: s.webhookId, organizationId: ORG, secretId: s.secretId });

    beforeAll(async () => {
      forge = await new FakeForge(flavour, TOKEN, "team", "app").start();
      forgeMod.setForgeTestHooks({
        resolve: async () => ["192.168.1.20"],
        connectTo: () => "127.0.0.1",
        ca: forge.ca,
      });
    }, 60_000);
    afterAll(async () => {
      forgeMod.setForgeTestHooks(null);
      await forge?.stop();
    });
    beforeEach(() => {
      forge.requests.length = 0;
      forge.faults.length = 0;
      forge.hooks.clear();
    });
    afterEach(async () => {
      await t.db.delete(schema.repository);
      await t.db.delete(schema.forgeConnection);
      await t.db.delete(schema.auditLog);
    });

    it("creates the webhook with the creator's own connection, stores its id and deletes the handed-over secret", async () => {
      const s = await seed();
      await run(s);
      const [created] = forge.requests;
      expect(forge.requests).toHaveLength(1);
      expect(created).toMatchObject({
        method: "POST",
        path: `${forge.prefix}/repos/team/app${s.repositoryId.replace("repo_hookreg", "")}/hooks`,
        authorization: forge.authorization,
      });
      expect(created?.body).toMatchObject({
        active: true,
        events: ["push"],
        config: { url: `${PUBLIC_URL}/api/v1/hooks/${s.pathId}`, content_type: "json", secret: HOOK_SECRET },
      });
      const [forgeId] = [...forge.hooks.keys()];
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "ok",
        registerReason: null,
        forgeHookId: String(forgeId),
        handoverSecretId: null,
        connectionId: s.connectionId,
      });
      expect(await secretExists(s.secretId)).toBe(false);
      const entries = await audits(s.repositoryId);
      expect(entries.map((a) => a.action)).toEqual(["repository.webhook_registered"]);
      expect(entries[0]).toMatchObject({ actorUserId: USER });
      expect(entries[0]?.data).toMatchObject({ forge: flavour, connection: s.connectionId });
    });

    it("never uses a connection that belongs to somebody else, and still deletes the secret", async () => {
      const s = await seed({ owner: OTHER_USER });
      await run(s);
      expect(forge.requests).toHaveLength(0);
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "failed",
        registerReason: "connection-missing",
        forgeHookId: null,
        handoverSecretId: null,
      });
      expect(await secretExists(s.secretId)).toBe(false);
      const entries = await audits(s.repositoryId);
      expect(entries.map((a) => a.action)).toEqual(["repository.webhook_register_failed"]);
      expect(entries[0]?.data).toMatchObject({ reason: "connection-missing" });
    });

    it("a connection on another forge is not used", async () => {
      const s = await seed({ connection: { webBaseUrl: "https://git.example.com" } });
      await run(s);
      expect(forge.requests).toHaveLength(0);
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "failed",
        registerReason: "connection-missing",
      });
      expect(await secretExists(s.secretId)).toBe(false);
    });

    it("a Gitea or Forgejo sign-in needs its write scope; a GitHub App does not", async () => {
      const s = await seed({ connection: { authMethod: "sign-in", writeScope: false } });
      await run(s);
      if (flavour === "github") {
        expect(await hook(s.webhookId)).toMatchObject({ registerState: "ok" });
      } else {
        expect(forge.requests).toHaveLength(0);
        expect(await hook(s.webhookId)).toMatchObject({
          registerState: "failed",
          registerReason: "write-scope-missing",
        });
      }
      expect(await secretExists(s.secretId)).toBe(false);
    });

    it("a refusal of the forge is stored as its code, and the secret is deleted all the same", async () => {
      const s = await seed();
      forge.faults.push({ match: /^POST .*\/hooks$/, status: 403, body: `{"message":"${HOOK_SECRET}"}` });
      await run(s);
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "failed",
        registerReason: "forbidden",
        forgeHookId: null,
        handoverSecretId: null,
      });
      expect(await secretExists(s.secretId)).toBe(false);
      expect((await audits(s.repositoryId))[0]?.data).toMatchObject({ reason: "forbidden" });
    });

    it("a token the forge rejects fails with its code", async () => {
      const s = await seed();
      forge.faults.push({ match: /^POST /, status: 401 });
      await run(s);
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "failed",
        registerReason: "token-rejected",
      });
      expect(await secretExists(s.secretId)).toBe(false);
    });

    it("a webhook switched off while the forge created it is removed in the forge again", async () => {
      const s = await seed();
      forge.beforeAnswer = async (method) => {
        if (method === "POST")
          await t.db.delete(schema.repositoryWebhook).where(eq(schema.repositoryWebhook.id, s.webhookId));
      };
      try {
        await run(s);
      } finally {
        forge.beforeAnswer = null;
      }
      expect(forge.requests.map((r) => r.method)).toEqual(["POST", "DELETE"]);
      expect(forge.hooks.size).toBe(0);
      expect(await secretExists(s.secretId)).toBe(false);
      expect((await audits(s.repositoryId)).map((a) => a.action)).toEqual([]);
    });

    it("does nothing for a webhook that is not pending or was replaced, but deletes the secret the job names", async () => {
      const done = await seed({ hook: { registerState: "ok", forgeHookId: "7" } });
      await run(done);
      const replaced = await seed();
      const stale = await sealed("webhook-secret", HOOK_SECRET);
      await run({ webhookId: replaced.webhookId, secretId: stale });
      await mod.runWebhookRegister({
        webhookId: "hook_gone",
        organizationId: ORG,
        secretId: replaced.secretId,
      });
      expect(forge.requests).toHaveLength(0);
      expect(await hook(done.webhookId)).toMatchObject({ registerState: "ok", forgeHookId: "7" });
      expect(await hook(replaced.webhookId)).toMatchObject({ registerState: "pending" });
      expect(await secretExists(done.secretId)).toBe(false);
      expect(await secretExists(stale)).toBe(false);
      expect(await secretExists(replaced.secretId)).toBe(false);
    });

    it("a secret sealed for another purpose is never opened", async () => {
      const s = await seed();
      const wrong = await sealed("forge-connection-token", HOOK_SECRET);
      await t.db
        .update(schema.repositoryWebhook)
        .set({ handoverSecretId: wrong })
        .where(eq(schema.repositoryWebhook.id, s.webhookId));
      await run({ webhookId: s.webhookId, secretId: wrong });
      expect(forge.requests).toHaveLength(0);
      expect(await hook(s.webhookId)).toMatchObject({
        registerState: "failed",
        registerReason: "secret-missing",
      });
      // Only webhook secrets are ever deleted by this job.
      expect(await secretExists(wrong)).toBe(true);
    });

    describe("removing", () => {
      const unregister = (
        s: { repositoryId: string; connectionId: string },
        forgeHookId: string,
        owner = USER,
      ) =>
        mod.runWebhookUnregister({
          organizationId: ORG,
          repositoryId: s.repositoryId,
          connectionId: s.connectionId,
          forgeHookId,
          ownerUserId: owner,
          requestedBy: OTHER_USER,
        });

      it("removes the webhook with the connection that created it; a missing one counts as removed", async () => {
        const s = await seed();
        await run(s);
        const id = String([...forge.hooks.keys()][0]);
        await unregister(s, id);
        expect(forge.hooks.size).toBe(0);
        expect(forge.requests.at(-1)).toMatchObject({ method: "DELETE", authorization: forge.authorization });
        await unregister(s, id);
        const entries = (await audits(s.repositoryId)).map((a) => a.action);
        expect(entries.filter((a) => a === "repository.webhook_unregistered")).toHaveLength(2);
        const removed = (await audits(s.repositoryId)).find(
          (a) => a.action === "repository.webhook_unregistered",
        );
        expect(removed).toMatchObject({ actorUserId: OTHER_USER });
      });

      it("never with somebody else's connection, and never an id that could reshape the path", async () => {
        const s = await seed();
        await unregister(s, "12", OTHER_USER);
        await unregister(s, "../12");
        expect(forge.requests).toHaveLength(0);
        const reasons = (await audits(s.repositoryId)).map((a) => [
          a.action,
          (a.data as { reason?: string }).reason,
        ]);
        expect(reasons).toEqual(
          expect.arrayContaining([
            ["repository.webhook_unregister_failed", "connection-missing"],
            ["repository.webhook_unregister_failed", "rejected"],
          ]),
        );
      });

      it("a refusal of the forge is audited with its code", async () => {
        const s = await seed();
        forge.faults.push({ match: /^DELETE /, status: 403 });
        await unregister(s, "12");
        const [entry] = await audits(s.repositoryId);
        expect(entry).toMatchObject({ action: "repository.webhook_unregister_failed" });
        expect(entry?.data).toMatchObject({ reason: "forbidden" });
      });
    });

    it("the sweep ends registrations whose job never ran and deletes their secret", async () => {
      const s = await seed();
      const fresh = await seed();
      const old = new Date(Date.now() - 2 * mod.PENDING_TIMEOUT_MS);
      await t.db
        .update(schema.repositoryWebhook)
        .set({ createdAt: old })
        .where(eq(schema.repositoryWebhook.id, s.webhookId));
      await t.db.update(schema.secret).set({ createdAt: old }).where(eq(schema.secret.id, s.secretId));
      expect(await mod.sweepWebhookRegistrations()).toBe(1);
      expect(await hook(s.webhookId)).toMatchObject({ registerState: "failed", registerReason: "expired" });
      expect(await secretExists(s.secretId)).toBe(false);
      expect(await hook(fresh.webhookId)).toMatchObject({ registerState: "pending" });
      expect(await secretExists(fresh.secretId)).toBe(true);
    });

    it("neither the token nor the secret lands in a row, an audit entry or a log line", async () => {
      await run(await seed());
      await run(await seed({ owner: OTHER_USER }));
      const failing = await seed();
      forge.faults.push({ match: /^POST /, status: 500, body: `{"message":"${TOKEN} ${HOOK_SECRET}"}` });
      await run(failing);
      const parts: unknown[] = [];
      for (const table of [
        schema.repositoryWebhook,
        schema.auditLog,
        schema.forgeConnection,
        schema.secret,
        schema.repository,
      ]) {
        parts.push(await t.db.select().from(table));
      }
      const dump = JSON.stringify(parts);
      for (const value of [TOKEN, HOOK_SECRET]) {
        expect(dump).not.toContain(value);
        expect(logs.join("\n")).not.toContain(value);
      }
    });
  });
});
