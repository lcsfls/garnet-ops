/**
 * Switching scan on push on (ADR 0045), shared by the repository page and by adding repositories from a connected account,
 * so both do exactly the same: a new random address and secret, the previous webhook replaced, audited, and (when asked)
 * registered in the forge through the caller's own connected account.
 *
 * Registering: the API cannot open a connection's token, so it seals a copy of the webhook secret for the worker (purpose
 * "webhook-secret", bound to the organisation and that secret's record) and queues a job with ids only. The worker checks
 * ownership again, creates the webhook in the forge and deletes the copy, whatever happens. A webhook GarnetOps created is
 * removed in the forge again (best effort) when it is replaced or switched off.
 */
import { newId } from "@garnetops/core";
import { connectionCoversRepository } from "@garnetops/core/fix-prs";
import { seal } from "@garnetops/core/vault";
import {
  registerConnectionProblem,
  type WebhookRegisterJob,
  type WebhookUnregisterJob,
  webhookAddress,
} from "@garnetops/core/webhook";
import { schema, type Viewer } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
import { boss, db, QUEUES } from "../db.ts";
import { env, vaultPublicKey } from "../env.ts";
import { audit } from "./audit.ts";
import type { Actor } from "./context.ts";
import { ProblemError } from "./problem.ts";
import { newWebhookSecret, sealWebhookSecret } from "./webhook-secret.ts";

const w = schema.repositoryWebhook;
type ConnectionRow = typeof schema.forgeConnection.$inferSelect;
type WebhookRow = typeof w.$inferSelect;
type Executor = Pick<typeof db, "select" | "delete">;

/** How long a queued registration or removal may wait for the worker. */
const JOB_EXPIRY_SECONDS = 15 * 60;

/** The address the forge calls for a webhook. */
export const hookUrl = (pathId: string) => webhookAddress(env.PUBLIC_URL, pathId);

/**
 * The caller's own connection on the repository's forge for registering a webhook: one that can (the most specific forge
 * address first), else the best one that cannot, with its problem, else none. Never anybody else's, for admins neither.
 */
export async function registerConnectionFor(
  viewer: Viewer,
  repositoryUrl: string,
): Promise<{ connection: ConnectionRow; problem: ReturnType<typeof registerConnectionProblem> } | null> {
  const own = await db
    .select()
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.organizationId, viewer.organizationId),
        eq(schema.forgeConnection.userId, viewer.userId),
      ),
    );
  const covering = own
    .filter((c) => connectionCoversRepository(c.webBaseUrl, repositoryUrl))
    .map((connection) => ({ connection, problem: registerConnectionProblem(connection) }))
    .sort(
      (a, b) =>
        Number(a.problem !== null) - Number(b.problem !== null) ||
        b.connection.webBaseUrl.length - a.connection.webBaseUrl.length,
    );
  return covering[0] ?? null;
}

/** The connection to register with, or a 409 that says why there is none. */
export function requireRegisterConnection(
  found: Awaited<ReturnType<typeof registerConnectionFor>>,
): ConnectionRow {
  if (!found)
    throw new ProblemError(409, "no-connection", "You have no connected account on this repository's forge");
  if (found.problem === "write-scope-missing")
    throw new ProblemError(
      409,
      "connection-write-scope-missing",
      "Your connected account was signed in without write access. Sign in again with write access",
    );
  if (found.problem === "connection-failed")
    throw new ProblemError(
      409,
      "connection-failed",
      "Your connected account on this forge does not work. Check it",
    );
  return found.connection;
}

/**
 * Queues the removal in the forge of the webhook GarnetOps registered for `row`, if it registered one. Called before the row
 * is deleted, so a failure to queue keeps the row (and with it the forge's id). Only ids travel.
 */
async function queueUnregister(row: WebhookRow, requestedBy: string | null): Promise<void> {
  if (!row.forgeHookId || !row.connectionId || !row.createdBy) return;
  const job: WebhookUnregisterJob = {
    organizationId: row.organizationId,
    repositoryId: row.repositoryId,
    connectionId: row.connectionId,
    forgeHookId: row.forgeHookId,
    ownerUserId: row.createdBy,
    requestedBy,
  };
  await boss.send(QUEUES.webhookUnregister, job, { retryLimit: 0, expireInSeconds: JOB_EXPIRY_SECONDS });
}

/**
 * Deletes the repository's webhook inside a transaction: its row is locked, the removal in the forge queued first, then the
 * row and any handed-over copy of its secret are deleted. Returns whether there was one.
 */
async function removeLocked(
  tx: Executor,
  repositoryId: string,
  requestedBy: string | null,
): Promise<boolean> {
  const rows = await tx.select().from(w).where(eq(w.repositoryId, repositoryId)).for("update");
  for (const row of rows) await queueUnregister(row, requestedBy);
  if (rows.length === 0) return false;
  await tx.delete(w).where(
    inArray(
      w.id,
      rows.map((r) => r.id),
    ),
  );
  const handovers = rows.map((r) => r.handoverSecretId).filter((id): id is string => Boolean(id));
  if (handovers.length) await tx.delete(schema.secret).where(inArray(schema.secret.id, handovers));
  return true;
}

/** Switches scan on push off: the address stops answering at once; a webhook GarnetOps registered goes in the forge too. */
export async function switchOffWebhook(actor: Actor, repositoryId: string): Promise<boolean> {
  const removed = await db.transaction((tx) => removeLocked(tx, repositoryId, actor.userId));
  if (removed) await audit(actor, "repository.webhook_removed", { type: "repository", id: repositoryId });
  return removed;
}

/**
 * Switches scan on push on for a repository the caller may manage (checked by the caller of this function), or replaces
 * address and secret. With `connection` (the caller's own, checked with {@link requireRegisterConnection}) the worker
 * registers the webhook in the forge. Returns address and secret, to be shown once.
 */
export async function switchOnWebhook(
  actor: Actor,
  repositoryId: string,
  connection: ConnectionRow | null,
): Promise<{ url: string; secret: string; replaced: boolean; registering: boolean }> {
  if (
    connection &&
    (connection.userId !== actor.userId || connection.organizationId !== actor.organizationId)
  )
    throw new ProblemError(409, "no-connection", "You have no connected account on this repository's forge");
  const id = newId("hook");
  const pathId = newWebhookSecret();
  const secret = newWebhookSecret();
  const handoverId = connection ? newId("sec") : null;
  const replaced = await db.transaction(async (tx) => {
    const had = await removeLocked(tx, repositoryId, actor.userId);
    if (handoverId) {
      await tx.insert(schema.secret).values({
        id: handoverId,
        organizationId: actor.organizationId,
        purpose: "webhook-secret",
        sealed: seal(
          secret,
          { organizationId: actor.organizationId, recordId: handoverId, purpose: "webhook-secret" },
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
    }
    await tx.insert(w).values({
      id,
      organizationId: actor.organizationId,
      repositoryId,
      pathId,
      secretSealed: sealWebhookSecret(secret, id),
      createdBy: actor.userId,
      connectionId: connection?.id ?? null,
      registerState: connection ? "pending" : null,
      handoverSecretId: handoverId,
    });
    return had;
  });
  await audit(
    actor,
    replaced ? "repository.webhook_replaced" : "repository.webhook_created",
    { type: "repository", id: repositoryId },
    connection ? { via: "connection", connection: connection.id, forge: connection.forgeKind } : undefined,
  );
  if (connection && handoverId) {
    const job: WebhookRegisterJob = {
      webhookId: id,
      organizationId: actor.organizationId,
      secretId: handoverId,
    };
    try {
      await boss.send(QUEUES.webhookRegister, job, {
        retryLimit: 0,
        expireInSeconds: JOB_EXPIRY_SECONDS,
        singletonKey: id,
      });
    } catch (error) {
      // Nothing will register it: say so on the webhook, and leave no copy of the secret behind.
      await db
        .update(w)
        .set({ registerState: "failed", registerReason: "unexpected", handoverSecretId: null })
        .where(eq(w.id, id));
      await db.delete(schema.secret).where(eq(schema.secret.id, handoverId));
      throw error;
    }
  }
  return { url: hookUrl(pathId), secret, replaced, registering: Boolean(connection) };
}
