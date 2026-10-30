/**
 * Signing in to a forge (ADR 0031) in the worker, against a fake forge (HTTPS, throw-away certificate) and a
 * throw-away PostgreSQL database with a real vault key: the device flow (GitHub) with pending answers, the authorization
 * code flow with PKCE and a client secret (Gitea), refusals, the connection that results, the one-time secrets deleted,
 * and renewing an access token before it expires (rotating refresh tokens, a refused renewal). Skipped without the
 * development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newSignInSecret, pkceChallenge, signInRedirectUri } from "@garnetops/core/forge-sign-in";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { FakeForge, FORGE_HOST } from "../test/fake-forge.ts";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-sign-in-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_signin";
const ALEX = "user_alex";
const TOKEN = "issued-access-token-0123456789";
const PUBLIC_URL = "https://garnetops.example.test";

describe.skipIf(!adminUrl || !openssl)("signing in to a forge", () => {
  let t: TestDatabase;
  let mod: typeof import("./forge-sign-in.ts");
  let connections: typeof import("./forge-connection.ts");
  let forgeMod: typeof import("./forge.ts");
  let publicKey: ReturnType<typeof loadVaultPublicKey>;
  const logs: string[] = [];
  let ids = 0;

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_signin");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
      PUBLIC_URL,
    });
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db.insert(schema.user).values({ id: ALEX, name: "Alex Example", email: "alex@example.test" });
    mod = await import("./forge-sign-in.ts");
    connections = await import("./forge-connection.ts");
    forgeMod = await import("./forge.ts");
    mod.setSignInPause(() => Promise.resolve());
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

  const sealed = async (purpose: "forge-sign-in" | "forge-app-secret", plain: string) => {
    const id = `sec_si${++ids}`;
    await t.db.insert(schema.secret).values({
      id,
      organizationId: ORG,
      purpose,
      sealed: seal(plain, { organizationId: ORG, recordId: id, purpose }, publicKey),
      vaultKeyId: publicKey.id,
    });
    return id;
  };
  const signInRow = async (id: string) =>
    (await t.db.select().from(schema.forgeSignIn).where(eq(schema.forgeSignIn.id, id)))[0];
  const connectionOf = async (id: string | null | undefined) =>
    (
      await t.db
        .select()
        .from(schema.forgeConnection)
        .where(eq(schema.forgeConnection.id, id ?? ""))
    )[0];
  const secretIds = async () =>
    new Set((await t.db.select({ id: schema.secret.id }).from(schema.secret)).map((s) => s.id));

  describe("device flow (GitHub App)", () => {
    let forge: FakeForge;
    let appId: string;

    beforeAll(async () => {
      forge = await new FakeForge("github", TOKEN).start();
      forgeMod.setForgeTestHooks({
        resolve: async () => ["192.168.1.20"],
        connectTo: () => "127.0.0.1",
        ca: forge.ca,
      });
      forge.listed = [
        { id: 1, full_name: "team/app", clone_url: `https://${FORGE_HOST}/team/app.git`, private: true },
      ];
      appId = "fapp_github";
      await t.db.insert(schema.forgeApp).values({
        id: appId,
        organizationId: ORG,
        forgeKind: "github",
        webBaseUrl: forge.apiBase.replace(/\/+$/, ""),
        apiBaseUrl: forge.apiBase,
        clientId: forge.oauth.clientId,
        secretId: await sealed("forge-app-secret", "github-client-secret"),
      });
    });
    afterAll(async () => {
      await forge.stop();
    });

    const start = async () => {
      const id = `fsi_${++ids}`;
      await t.db.insert(schema.forgeSignIn).values({
        id,
        organizationId: ORG,
        userId: ALEX,
        appId,
        flow: "device",
        expiresAt: new Date(Date.now() + 600_000),
      });
      return id;
    };

    it("waits while the person confirms, then connects the account and lists its repositories", async () => {
      forge.oauth.pendingPolls = 2;
      forge.oauth.polls = 0;
      const id = await start();
      await mod.runSignIn(id);
      const row = await signInRow(id);
      expect(row).toMatchObject({ state: "done", problem: null, userCode: "WDJB-MJHT", codeSecretId: null });
      expect(row?.verificationUri).toBe(`https://${FORGE_HOST}/login/device`);
      expect(forge.oauth.polls).toBe(3);
      const connection = await connectionOf(row?.connectionId);
      expect(connection).toMatchObject({
        authMethod: "sign-in",
        appId,
        accountLogin: "alex",
        state: "ok",
        userId: ALEX,
      });
      const hours = ((connection?.tokenExpiresAt?.getTime() ?? 0) - Date.now()) / 3_600_000;
      expect(hours).toBeGreaterThan(7.9);
      expect(
        await t.db
          .select()
          .from(schema.forgeConnectionRepository)
          .where(eq(schema.forgeConnectionRepository.connectionId, connection?.id ?? "")),
      ).toHaveLength(1);
      // The device code was sent only to the token endpoint and is gone from the vault.
      const requests = forge.requests.filter((r) => r.path.startsWith("/login/"));
      expect(requests.every((r) => r.authorization === undefined)).toBe(true);
      expect(JSON.stringify(await t.db.select().from(schema.forgeSignIn))).not.toContain(
        "device-code-0123456789",
      );
    });

    it("signing in again replaces the tokens of the same connection", async () => {
      const before = (await t.db.select().from(schema.forgeConnection)).length;
      const [old] = await t.db.select().from(schema.forgeConnection);
      const id = await start();
      forge.oauth.polls = 0;
      await mod.runSignIn(id);
      expect((await t.db.select().from(schema.forgeConnection)).length).toBe(before);
      const now = await connectionOf(old?.id);
      expect(now?.secretId).not.toBe(old?.secretId);
      const left = await secretIds();
      expect(left.has(old?.secretId as string)).toBe(false);
      expect(left.has(old?.refreshSecretId as string)).toBe(false);
    });

    it("a GitHub App has no scopes: signing in again keeps pull requests switched on (ADR 0039)", async () => {
      const [old] = await t.db.select().from(schema.forgeConnection);
      await t.db
        .update(schema.forgeConnection)
        .set({ pullRequests: true, pullRequestsAt: new Date() })
        .where(eq(schema.forgeConnection.id, old?.id as string));
      const id = await start();
      forge.oauth.polls = 0;
      await mod.runSignIn(id);
      expect(await connectionOf(old?.id)).toMatchObject({ pullRequests: true, writeScope: false });
      await t.db
        .update(schema.forgeConnection)
        .set({ pullRequests: false, pullRequestsAt: null })
        .where(eq(schema.forgeConnection.id, old?.id as string));
    });

    it("stores a refusal on the forge as a short code", async () => {
      forge.oauth.denyDevice = true;
      const id = await start();
      await mod.runSignIn(id);
      forge.oauth.denyDevice = false;
      expect(await signInRow(id)).toMatchObject({ state: "failed", problem: "denied", connectionId: null });
    });

    it("renews an access token before it expires, and asks for a new sign-in when the forge refuses", async () => {
      const [connection] = await t.db.select().from(schema.forgeConnection);
      const job = { connectionId: connection?.id as string, organizationId: ORG, userId: ALEX };
      await t.db
        .update(schema.forgeConnection)
        .set({ tokenExpiresAt: new Date(Date.now() + 60_000) })
        .where(eq(schema.forgeConnection.id, job.connectionId));
      const renewals = forge.oauth.renewals;
      await connections.refreshConnection(job);
      expect(forge.oauth.renewals).toBe(renewals + 1);
      const renewed = await connectionOf(job.connectionId);
      expect(renewed?.secretId).not.toBe(connection?.secretId);
      expect(renewed?.refreshSecretId).not.toBe(connection?.refreshSecretId);
      expect(renewed?.state).toBe("ok");
      const left = await secretIds();
      expect(left.has(connection?.secretId as string)).toBe(false);
      expect(left.has(connection?.refreshSecretId as string)).toBe(false);

      // The forge no longer knows the stored refresh token.
      forge.oauth.refreshToken = "something-else";
      await t.db
        .update(schema.forgeConnection)
        .set({ tokenExpiresAt: new Date(Date.now() + 60_000) })
        .where(eq(schema.forgeConnection.id, job.connectionId));
      await connections.refreshConnection(job);
      expect(await connectionOf(job.connectionId)).toMatchObject({
        state: "failed",
        problem: "sign-in-expired",
      });
      expect(logs.join("\n")).not.toMatch(/refresh-\d|issued-access-token|github-client-secret/);
    });
  });

  describe("authorization code with PKCE (Gitea)", () => {
    let forge: FakeForge;
    let appId: string;

    beforeAll(async () => {
      forge = await new FakeForge("gitea", TOKEN).start();
      forgeMod.setForgeTestHooks({
        resolve: async () => ["192.168.1.20"],
        connectTo: () => "127.0.0.1",
        ca: forge.ca,
      });
      forge.oauth.clientSecret = "gitea-client-secret";
      forge.oauth.redirectUri = signInRedirectUri(PUBLIC_URL);
      appId = "fapp_gitea";
      await t.db.insert(schema.forgeApp).values({
        id: appId,
        organizationId: ORG,
        forgeKind: "gitea",
        webBaseUrl: forge.apiBase.replace(/\/api\/v1$/, ""),
        apiBaseUrl: forge.apiBase,
        clientId: forge.oauth.clientId,
        secretId: await sealed("forge-app-secret", "gitea-client-secret"),
      });
    });
    afterAll(async () => {
      await forge.stop();
    });

    const exchange = async (verifier: string, code: string, write = false) => {
      const id = `fsi_${++ids}`;
      await t.db.insert(schema.forgeSignIn).values({
        id,
        organizationId: ORG,
        userId: ALEX,
        appId,
        flow: "code",
        write,
        state: "exchanging",
        verifierSecretId: await sealed("forge-sign-in", verifier),
        codeSecretId: await sealed("forge-sign-in", code),
        expiresAt: new Date(Date.now() + 600_000),
      });
      await mod.runSignIn(id);
      return signInRow(id);
    };

    it("exchanges the code with the verifier and the client secret, and deletes both", async () => {
      const verifier = newSignInSecret();
      const code = forge.authorize(pkceChallenge(verifier));
      const row = await exchange(verifier, code);
      expect(row).toMatchObject({ state: "done", verifierSecretId: null, codeSecretId: null });
      expect(await connectionOf(row?.connectionId)).toMatchObject({
        authMethod: "sign-in",
        forgeKind: "gitea",
      });
      const sent = forge.requests.find((r) => r.path === "/login/oauth/access_token")?.body as Record<
        string,
        string
      >;
      expect(sent).toMatchObject({
        grant_type: "authorization_code",
        client_secret: "gitea-client-secret",
        redirect_uri: "https://garnetops.example.test/settings/accounts/callback",
      });
    });

    it("fails without the right verifier: an intercepted code is useless", async () => {
      const code = forge.authorize(pkceChallenge(newSignInSecret()));
      expect(await exchange(newSignInSecret(), code)).toMatchObject({ state: "failed", problem: "denied" });
    });

    it("a sign-in with write access marks the connection; one without turns its pull requests off (ADR 0039)", async () => {
      let verifier = newSignInSecret();
      const written = await exchange(verifier, forge.authorize(pkceChallenge(verifier)), true);
      const id = written?.connectionId as string;
      expect(await connectionOf(id)).toMatchObject({ writeScope: true, pullRequests: false });
      // The owner switches pull requests on (the API does this, audited).
      await t.db
        .update(schema.forgeConnection)
        .set({ pullRequests: true, pullRequestsAt: new Date() })
        .where(eq(schema.forgeConnection.id, id));
      // Signing in again with write access keeps the switch.
      verifier = newSignInSecret();
      await exchange(verifier, forge.authorize(pkceChallenge(verifier)), true);
      expect(await connectionOf(id)).toMatchObject({ writeScope: true, pullRequests: true });
      // A read-only sign-in cannot write: the switch goes off, audited.
      verifier = newSignInSecret();
      const plain = await exchange(verifier, forge.authorize(pkceChallenge(verifier)));
      expect(plain?.connectionId).toBe(id);
      expect(await connectionOf(id)).toMatchObject({
        writeScope: false,
        pullRequests: false,
        pullRequestsAt: null,
      });
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: "forge_connection.pull_requests_disabled",
        actorUserId: ALEX,
        organizationId: ORG,
      });
      expect(audit[0]?.data).toMatchObject({ reason: "signed-in-without-write" });
    });
  });
});
