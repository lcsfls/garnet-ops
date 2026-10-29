/**
 * Personal forge connections in the worker (ADR 0030). The worker is the only process that opens a connection's
 * token: it checks whom the token belongs to and stores the repositories the account can see, for its owner's
 * picker. The token is never written anywhere and never sent to another host than the connection's API address
 * (forge.ts applies the address rules on every request).
 */
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import { accountInfo, type ForgeAccount, ForgeError, listRepositories, requestToken } from "./forge.ts";
import { openSecretText, sealSecret } from "./vault-secrets.ts";

export const FORGE_CONNECTION_QUEUE = "forge-connection.refresh";

export interface RefreshJob {
  connectionId: string;
  organizationId: string;
  userId: string;
}

type ConnectionRow = typeof schema.forgeConnection.$inferSelect;

/**
 * The connection's token, if the connection still belongs to the person and organisation the job names. The token
 * lives only in the returned object.
 */
export async function openConnection(
  job: RefreshJob,
): Promise<{ connection: ConnectionRow; account: ForgeAccount } | null> {
  const [connection] = await db
    .select()
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.id, job.connectionId),
        eq(schema.forgeConnection.organizationId, job.organizationId),
        eq(schema.forgeConnection.userId, job.userId),
      ),
    )
    .limit(1);
  if (!connection) return null;
  return { connection, account: await accountOf(connection) };
}

/** A signed-in connection whose renewal the forge refused (ADR 0031): the person has to sign in again. */
export class SignInExpiredError extends ForgeError {
  constructor() {
    super("token-rejected");
  }
}

/** Access tokens that expire within this time are renewed before they are used. */
const RENEW_BEFORE_MS = 5 * 60_000;

/**
 * Renews the access token of a signed-in connection with its refresh token (ADR 0031), under a row lock, so two jobs
 * never spend the same refresh token (forges rotate them). Returns the connection as it is afterwards.
 */
async function renew(connectionId: string): Promise<ConnectionRow> {
  return db.transaction(async (tx) => {
    const [row] = await tx
      .select()
      .from(schema.forgeConnection)
      .where(eq(schema.forgeConnection.id, connectionId))
      .for("update")
      .limit(1);
    if (!row) throw new ForgeError("token-rejected");
    // Another job renewed it while this one waited for the lock.
    if (!row.tokenExpiresAt || row.tokenExpiresAt.getTime() - Date.now() > RENEW_BEFORE_MS) return row;
    const [app] = row.appId
      ? await tx.select().from(schema.forgeApp).where(eq(schema.forgeApp.id, row.appId)).limit(1)
      : [];
    const refresh = await openSecretText(row.refreshSecretId, row.organizationId, "forge-connection-token");
    if (!app || !refresh) throw new SignInExpiredError();
    const clientSecret = await openSecretText(app.secretId, row.organizationId, "forge-app-secret");
    const answer = await requestToken(app.webBaseUrl, {
      client_id: app.clientId,
      ...(clientSecret ? { client_secret: clientSecret } : {}),
      grant_type: "refresh_token",
      refresh_token: refresh,
    });
    if (answer.kind !== "token") throw new SignInExpiredError();
    const accessId = await sealSecret(tx, row.organizationId, "forge-connection-token", answer.accessToken);
    // A forge that does not rotate refresh tokens keeps the old one.
    const refreshId = answer.refreshToken
      ? await sealSecret(tx, row.organizationId, "forge-connection-token", answer.refreshToken)
      : row.refreshSecretId;
    const [renewed] = await tx
      .update(schema.forgeConnection)
      .set({
        secretId: accessId,
        refreshSecretId: refreshId,
        tokenExpiresAt: answer.expiresInSeconds
          ? new Date(Date.now() + answer.expiresInSeconds * 1000)
          : null,
        updatedAt: new Date(),
      })
      .where(eq(schema.forgeConnection.id, row.id))
      .returning();
    const old = [row.secretId, answer.refreshToken ? row.refreshSecretId : null].filter((id): id is string =>
      Boolean(id),
    );
    if (old.length) await tx.delete(schema.secret).where(inArray(schema.secret.id, old));
    return renewed as ConnectionRow;
  });
}

/**
 * Opens the sealed token of a connection, renewed first if it is a signed-in one about to expire. A missing or foreign
 * secret is a rejected token.
 */
export async function accountOf(current: ConnectionRow): Promise<ForgeAccount> {
  let connection = current;
  if (
    connection.authMethod === "sign-in" &&
    connection.tokenExpiresAt &&
    connection.tokenExpiresAt.getTime() - Date.now() <= RENEW_BEFORE_MS
  ) {
    connection = await renew(connection.id);
  }
  if (!connection.secretId) throw new ForgeError("token-rejected");
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, connection.secretId),
        eq(schema.secret.organizationId, connection.organizationId),
        eq(schema.secret.purpose, "forge-connection-token"),
      ),
    )
    .limit(1);
  if (!secret) throw new ForgeError("token-rejected");
  let token: string;
  try {
    const plain = open(
      secret.sealed,
      { organizationId: secret.organizationId, recordId: secret.id, purpose: "forge-connection-token" },
      vaultPrivateKey,
    );
    token = plain.toString("utf8");
    plain.fill(0);
  } catch {
    throw new ForgeError("token-rejected");
  }
  return { kind: connection.forgeKind, apiBaseUrl: connection.apiBaseUrl, token };
}

/**
 * Checks the token and replaces the stored list of repositories. A failure keeps the previous list and stores a
 * short code on the connection; it is not retried (the person refreshes again).
 */
export async function refreshConnection(job: RefreshJob): Promise<void> {
  let opened: Awaited<ReturnType<typeof openConnection>>;
  try {
    opened = await openConnection(job);
  } catch (error) {
    await markFailed(job.connectionId, error);
    return;
  }
  if (!opened) return; // removed meanwhile, or not this person's
  const { connection, account } = opened;
  try {
    const me = await accountInfo(account);
    const listed = await listRepositories(account, new URL(connection.webBaseUrl).hostname);
    await db.transaction(async (tx) => {
      await tx
        .delete(schema.forgeConnectionRepository)
        .where(eq(schema.forgeConnectionRepository.connectionId, connection.id));
      for (let i = 0; i < listed.items.length; i += 500) {
        await tx.insert(schema.forgeConnectionRepository).values(
          listed.items.slice(i, i + 500).map((r) => ({
            connectionId: connection.id,
            forgeId: r.forgeId,
            fullName: r.fullName,
            cloneUrl: r.cloneUrl,
            defaultBranch: r.defaultBranch,
            private: r.private,
            archived: r.archived,
            description: r.description,
          })),
        );
      }
      await tx
        .update(schema.forgeConnection)
        .set({
          state: "ok",
          problem: null,
          accountLogin: me.login,
          broadToken: me.broadToken,
          truncated: listed.truncated,
          lastCheckedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(schema.forgeConnection.id, connection.id));
    });
  } catch (error) {
    await markFailed(connection.id, error);
  } finally {
    account.token = "";
  }
}

async function markFailed(connectionId: string, error: unknown): Promise<void> {
  const problem =
    error instanceof SignInExpiredError
      ? "sign-in-expired"
      : error instanceof ForgeError
        ? error.code
        : "unexpected";
  if (!(error instanceof ForgeError))
    console.error("forge connection refresh failed", (error as Error)?.name);
  await db
    .update(schema.forgeConnection)
    .set({ state: "failed", problem, lastCheckedAt: new Date(), updatedAt: new Date() })
    .where(eq(schema.forgeConnection.id, connectionId));
}
