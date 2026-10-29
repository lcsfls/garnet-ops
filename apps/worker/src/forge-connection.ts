/**
 * Personal forge connections in the worker (ADR 0030). The worker is the only process that opens a connection's
 * token: it checks whom the token belongs to and stores the repositories the account can see, for its owner's
 * picker. The token is never written anywhere and never sent to another host than the connection's API address
 * (forge.ts applies the address rules on every request).
 */
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq } from "drizzle-orm";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import { accountInfo, type ForgeAccount, ForgeError, listRepositories } from "./forge.ts";

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

/** Opens the sealed token of a connection. A missing or foreign secret is a rejected token. */
export async function accountOf(connection: ConnectionRow): Promise<ForgeAccount> {
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
  const problem = error instanceof ForgeError ? error.code : "unexpected";
  if (!(error instanceof ForgeError))
    console.error("forge connection refresh failed", (error as Error)?.name);
  await db
    .update(schema.forgeConnection)
    .set({ state: "failed", problem, lastCheckedAt: new Date(), updatedAt: new Date() })
    .where(eq(schema.forgeConnection.id, connectionId));
}
