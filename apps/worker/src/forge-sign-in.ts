/**
 * Signing in to a forge (ADR 0031), in the worker: the only process that talks to forges and opens their secrets. For
 * the device flow (GitHub Apps) it asks for a device code, shows nothing itself (the API reads the user code from the
 * sign-in row) and polls the token endpoint at the forge's pace; for the authorization code flow (Gitea, Forgejo) it
 * exchanges the code with the PKCE verifier. The resulting tokens are sealed into a personal connection (ADR 0030); the
 * one-time values are deleted when the sign-in ends.
 */

import { newId } from "@garnetops/core";
import { DEVICE_FLOW_MAX_MS, signInRedirectUri } from "@garnetops/core/forge-sign-in";
import { schema } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { accountInfo, ForgeError, requestDeviceCode, requestToken, type TokenAnswer } from "./forge.ts";
import { refreshConnection } from "./forge-connection.ts";
import { openSecretText, sealSecret } from "./vault-secrets.ts";

export const FORGE_SIGN_IN_QUEUE = "forge-sign-in.run";

type SignInRow = typeof schema.forgeSignIn.$inferSelect;
type AppRow = typeof schema.forgeApp.$inferSelect;
type Token = Extract<TokenAnswer, { kind: "token" }>;

const sleeping = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Tests only: no real waiting between polls. */
let pause: (ms: number) => Promise<unknown> = sleeping;
export function setSignInPause(fn: ((ms: number) => Promise<unknown>) | null): void {
  pause = fn ?? sleeping;
}

async function load(signInId: string) {
  const [row] = await db
    .select({ signIn: schema.forgeSignIn, app: schema.forgeApp })
    .from(schema.forgeSignIn)
    .innerJoin(schema.forgeApp, eq(schema.forgeApp.id, schema.forgeSignIn.appId))
    .where(eq(schema.forgeSignIn.id, signInId))
    .limit(1);
  return row ?? null;
}

/** Ends a sign-in: its state, a short problem code if it failed, and the one-time secrets deleted. */
async function finish(
  row: SignInRow,
  state: "done" | "failed",
  extra: { problem?: string; connectionId?: string },
) {
  await db
    .update(schema.forgeSignIn)
    .set({
      state,
      problem: extra.problem ?? null,
      connectionId: extra.connectionId ?? null,
      verifierSecretId: null,
      codeSecretId: null,
      updatedAt: new Date(),
    })
    .where(eq(schema.forgeSignIn.id, row.id));
  const secrets = [row.verifierSecretId, row.codeSecretId].filter((id): id is string => Boolean(id));
  if (secrets.length) await db.delete(schema.secret).where(inArray(schema.secret.id, secrets));
}

/** Runs one sign-in to its end. Never throws: the outcome is written to the sign-in row. */
export async function runSignIn(signInId: string): Promise<void> {
  const loaded = await load(signInId);
  if (!loaded) return;
  const { signIn, app } = loaded;
  try {
    if (signIn.flow === "device" && signIn.state === "starting") await deviceFlow(signIn, app);
    else if (signIn.flow === "code" && signIn.state === "exchanging") await codeFlow(signIn, app);
  } catch (error) {
    const current = (await load(signInId))?.signIn ?? signIn;
    if (!(error instanceof ForgeError)) console.error("forge sign-in failed", (error as Error)?.name);
    await finish(current, "failed", { problem: error instanceof ForgeError ? error.code : "unexpected" });
  }
}

async function deviceFlow(signIn: SignInRow, app: AppRow): Promise<void> {
  const code = await requestDeviceCode(app.webBaseUrl, app.clientId);
  const deviceSecretId = await sealSecret(db, signIn.organizationId, "forge-sign-in", code.deviceCode);
  const expiresAt = new Date(Date.now() + Math.min(code.expiresInSeconds * 1000, DEVICE_FLOW_MAX_MS));
  await db
    .update(schema.forgeSignIn)
    .set({
      state: "waiting",
      codeSecretId: deviceSecretId,
      userCode: code.userCode,
      verificationUri: code.verificationUri,
      expiresAt,
      updatedAt: new Date(),
    })
    .where(eq(schema.forgeSignIn.id, signIn.id));
  let interval = code.intervalSeconds;
  for (;;) {
    await pause(interval * 1000);
    const current = (await load(signIn.id))?.signIn;
    // Cancelled (the row is gone) or ended elsewhere.
    if (current?.state !== "waiting") return;
    if (Date.now() > expiresAt.getTime()) return finish(current, "failed", { problem: "expired" });
    const answer = await requestToken(app.webBaseUrl, {
      client_id: app.clientId,
      device_code: code.deviceCode,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    });
    if (answer.kind === "pending") continue;
    if (answer.kind === "slow-down") {
      interval += 5;
      continue;
    }
    if (answer.kind === "token") return connect(current, app, answer);
    return finish(current, "failed", { problem: answer.kind === "expired" ? "expired" : "denied" });
  }
}

async function codeFlow(signIn: SignInRow, app: AppRow): Promise<void> {
  if (!env.PUBLIC_URL) return finish(signIn, "failed", { problem: "no-public-url" });
  if (Date.now() > signIn.expiresAt.getTime()) return finish(signIn, "failed", { problem: "expired" });
  const [verifier, code, clientSecret] = await Promise.all([
    openSecretText(signIn.verifierSecretId, signIn.organizationId, "forge-sign-in"),
    openSecretText(signIn.codeSecretId, signIn.organizationId, "forge-sign-in"),
    openSecretText(app.secretId, signIn.organizationId, "forge-app-secret"),
  ]);
  if (!verifier || !code) return finish(signIn, "failed", { problem: "denied" });
  const answer = await requestToken(app.webBaseUrl, {
    client_id: app.clientId,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
    grant_type: "authorization_code",
    code,
    redirect_uri: signInRedirectUri(env.PUBLIC_URL),
    code_verifier: verifier,
  });
  if (answer.kind !== "token") return finish(signIn, "failed", { problem: "denied" });
  return connect(signIn, app, answer);
}

/**
 * Stores the tokens as the person's connection to this forge: a new one, or the existing one for the same forge address,
 * whose old secrets go. Then lists the repositories, as a pasted token would.
 */
async function connect(signIn: SignInRow, app: AppRow, token: Token): Promise<void> {
  const me = await accountInfo({ kind: app.forgeKind, apiBaseUrl: app.apiBaseUrl, token: token.accessToken });
  const expiresAt = token.expiresInSeconds ? new Date(Date.now() + token.expiresInSeconds * 1000) : null;
  const connectionId = await db.transaction(async (tx) => {
    const accessId = await sealSecret(tx, signIn.organizationId, "forge-connection-token", token.accessToken);
    const refreshId = token.refreshToken
      ? await sealSecret(tx, signIn.organizationId, "forge-connection-token", token.refreshToken)
      : null;
    const [existing] = await tx
      .select()
      .from(schema.forgeConnection)
      .where(
        and(
          eq(schema.forgeConnection.organizationId, signIn.organizationId),
          eq(schema.forgeConnection.userId, signIn.userId),
          eq(schema.forgeConnection.webBaseUrl, app.webBaseUrl),
        ),
      )
      .for("update")
      .limit(1);
    // A Gitea/Forgejo token can write only when the sign-in asked for it (ADR 0039); GitHub has no scopes.
    const writeScope = signIn.write && app.forgeKind !== "github";
    const values = {
      forgeKind: app.forgeKind,
      apiBaseUrl: app.apiBaseUrl,
      secretId: accessId,
      refreshSecretId: refreshId,
      tokenExpiresAt: expiresAt,
      authMethod: "sign-in" as const,
      appId: app.id,
      accountLogin: me.login,
      broadToken: me.broadToken,
      writeScope,
      state: "unchecked" as const,
      problem: null,
      updatedAt: new Date(),
    };
    if (existing) {
      // The owner's opt-in to pull requests survives a new sign-in only where the new token can still write as before:
      // a GitHub App (its registration decides), or a Gitea/Forgejo sign-in with the write scope. A connection that had
      // a pasted token starts read-only again.
      const keep =
        existing.pullRequests &&
        existing.authMethod === "sign-in" &&
        (app.forgeKind === "github" || writeScope);
      await tx
        .update(schema.forgeConnection)
        .set({
          ...values,
          pullRequests: keep,
          pullRequestsAt: keep ? existing.pullRequestsAt : null,
        })
        .where(eq(schema.forgeConnection.id, existing.id));
      if (existing.pullRequests && !keep) {
        await tx.insert(schema.auditLog).values({
          organizationId: signIn.organizationId,
          actorUserId: signIn.userId,
          action: "forge_connection.pull_requests_disabled",
          targetType: "forge_connection",
          targetId: existing.id,
          data: { web: app.webBaseUrl, reason: "signed-in-without-write" },
        });
      }
      const old = [existing.secretId, existing.refreshSecretId].filter((id): id is string => Boolean(id));
      if (old.length) await tx.delete(schema.secret).where(inArray(schema.secret.id, old));
      return existing.id;
    }
    const id = newId("fcn");
    await tx.insert(schema.forgeConnection).values({
      id,
      organizationId: signIn.organizationId,
      userId: signIn.userId,
      webBaseUrl: app.webBaseUrl,
      ...values,
    });
    return id;
  });
  token.accessToken = "";
  token.refreshToken = null;
  await finish(signIn, "done", { connectionId });
  await refreshConnection({ connectionId, organizationId: signIn.organizationId, userId: signIn.userId });
}
