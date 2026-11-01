/**
 * Scan on push (ADR 0045, "Registering through a connected account"): the worker creates the repository's webhook in the
 * forge with the connected account of the person who switched it on, and removes it again when it is switched off or
 * replaced. The worker is the only process that opens the connection's token and the handed-over copy of the webhook
 * secret.
 *
 * Before anything is opened the job checks again what the API checked: the webhook still exists and waits to be registered,
 * the connection belongs to the webhook's creator in the same organisation and is on the repository's forge, and a
 * Gitea/Forgejo sign-in has its write scope. A connection's token is never used for anybody else's webhook. The handed-over
 * secret is deleted in every outcome; it is never logged, never in a job and never in an error, and failures are stored as
 * short codes.
 */
import { connectionCoversRepository, parseRepoLocation } from "@garnetops/core/fix-prs";
import {
  FORGE_HOOK_ID_PATTERN,
  registerConnectionProblem,
  type WebhookRegisterJob,
  type WebhookRegisterReason,
  type WebhookUnregisterJob,
  webhookAddress,
} from "@garnetops/core/webhook";
import { schema } from "@garnetops/db";
import { and, eq, lt } from "drizzle-orm";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { createPushHook, deletePushHook, ForgeError, type ForgeTarget } from "./forge.ts";
import { accountOf } from "./forge-connection.ts";
import { openSecretText } from "./vault-secrets.ts";

export const WEBHOOK_REGISTER_QUEUE = "repository-webhook.register";
export const WEBHOOK_UNREGISTER_QUEUE = "repository-webhook.unregister";

/** A registration still pending after this long has lost its job (expired, or the worker stopped): it ends as failed. */
export const PENDING_TIMEOUT_MS = 30 * 60_000;

const w = schema.repositoryWebhook;
type ConnectionRow = typeof schema.forgeConnection.$inferSelect;
type RepoRow = typeof schema.repository.$inferSelect;

/** A short code for a failure: the forge client's own, or "unexpected" (logged without details that could hold a secret). */
const reasonOf = (error: unknown): WebhookRegisterReason =>
  error instanceof ForgeError ? error.code : "unexpected";

async function audit(
  organizationId: string,
  actorUserId: string | null,
  action: string,
  repositoryId: string,
  data: Record<string, unknown>,
) {
  await db.insert(schema.auditLog).values({
    organizationId,
    actorUserId,
    action,
    targetType: "repository",
    targetId: repositoryId,
    data,
  });
}

/** Deletes the handed-over copy of the secret: only a webhook secret of this organisation, whatever the job names. */
async function dropHandover(secretId: string | null | undefined, organizationId: string) {
  if (!secretId) return;
  await db
    .delete(schema.secret)
    .where(
      and(
        eq(schema.secret.id, secretId),
        eq(schema.secret.organizationId, organizationId),
        eq(schema.secret.purpose, "webhook-secret"),
      ),
    );
}

/**
 * The connection, only while it belongs to `ownerUserId` in the organisation and is on the repository's forge, with the
 * repository. Anything else is a reason code.
 */
async function ownersConnection(input: {
  organizationId: string;
  repositoryId: string;
  connectionId: string | null;
  ownerUserId: string | null;
}): Promise<{ connection: ConnectionRow; repo: RepoRow } | { problem: WebhookRegisterReason }> {
  const [repo] = await db
    .select()
    .from(schema.repository)
    .where(
      and(
        eq(schema.repository.id, input.repositoryId),
        eq(schema.repository.organizationId, input.organizationId),
      ),
    )
    .limit(1);
  if (!repo) return { problem: "repository-gone" };
  if (!input.connectionId || !input.ownerUserId) return { problem: "connection-missing" };
  const [connection] = await db
    .select()
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.id, input.connectionId),
        eq(schema.forgeConnection.organizationId, input.organizationId),
        eq(schema.forgeConnection.userId, input.ownerUserId),
      ),
    )
    .limit(1);
  if (!connection || !connectionCoversRepository(connection.webBaseUrl, repo.url))
    return { problem: "connection-missing" };
  const problem = registerConnectionProblem(connection);
  if (problem === "write-scope-missing") return { problem };
  // A failed check or a missing token: the forge decides with the token as it is (opening it fails if it is gone).
  return { connection, repo };
}

/** The connection's token for one repository. Lives only in the returned object. */
async function targetFor(connection: ConnectionRow, repo: RepoRow): Promise<ForgeTarget> {
  const location = parseRepoLocation(repo.url);
  if (!location) throw new ForgeError("not-found");
  const account = await accountOf(connection);
  return { ...account, owner: location.owner, repo: location.repo };
}

/**
 * Creates the webhook in the forge for one pending registration. Stores the forge's id and "ok", or "failed" with a code,
 * audits either, and deletes the handed-over secret in every outcome. Nothing is thrown to the queue: a retry could create
 * a second webhook.
 */
export async function runWebhookRegister(job: WebhookRegisterJob): Promise<void> {
  try {
    await register(job);
  } catch (error) {
    // Only reached when the database itself fails; the row is swept later. The error may name a query, never the secret.
    console.error(`webhook register ${job.webhookId}:`, (error as Error)?.name ?? "error");
  } finally {
    await dropHandover(job.secretId, job.organizationId).catch((error: Error) =>
      console.error(`webhook register ${job.webhookId}: handover not deleted:`, error.name),
    );
  }
}

async function register(job: WebhookRegisterJob): Promise<void> {
  const [row] = await db
    .select()
    .from(w)
    .where(and(eq(w.id, job.webhookId), eq(w.organizationId, job.organizationId)))
    .limit(1);
  // Switched off, replaced or already handled: nothing to register.
  if (row?.registerState !== "pending" || row.handoverSecretId !== job.secretId) return;

  const fail = async (reason: WebhookRegisterReason) => {
    const [failed] = await db
      .update(w)
      .set({ registerState: "failed", registerReason: reason, handoverSecretId: null })
      .where(and(eq(w.id, row.id), eq(w.registerState, "pending")))
      .returning({ id: w.id });
    if (failed)
      await audit(row.organizationId, row.createdBy, "repository.webhook_register_failed", row.repositoryId, {
        reason,
        connection: row.connectionId,
      });
  };

  const owned = await ownersConnection({
    organizationId: row.organizationId,
    repositoryId: row.repositoryId,
    connectionId: row.connectionId,
    ownerUserId: row.createdBy,
  });
  if ("problem" in owned) return fail(owned.problem);
  if (!env.PUBLIC_URL) return fail("no-public-url");
  const secret = await openSecretText(row.handoverSecretId, row.organizationId, "webhook-secret");
  if (!secret) return fail("secret-missing");

  let target: ForgeTarget;
  let hookId: string;
  try {
    target = await targetFor(owned.connection, owned.repo);
    hookId = await createPushHook(target, webhookAddress(env.PUBLIC_URL, row.pathId), secret);
  } catch (error) {
    if (!(error instanceof ForgeError)) console.error(`webhook register ${row.id}:`, (error as Error)?.name);
    return fail(reasonOf(error));
  }
  const [stored] = await db
    .update(w)
    .set({ forgeHookId: hookId, registerState: "ok", registerReason: null, handoverSecretId: null })
    .where(and(eq(w.id, row.id), eq(w.registerState, "pending")))
    .returning({ id: w.id });
  if (!stored) {
    // Switched off or replaced while the forge was asked: nothing tracks this webhook, so it goes again.
    await deletePushHook(target, hookId).catch(() => {});
    return;
  }
  await audit(row.organizationId, row.createdBy, "repository.webhook_registered", row.repositoryId, {
    forge: target.kind,
    connection: owned.connection.id,
  });
}

/**
 * Removes a webhook GarnetOps registered, with the connection that registered it and only while it still belongs to the
 * person who did. Best effort: a webhook that is gone already counts as removed; any other outcome is audited with a code.
 */
export async function runWebhookUnregister(job: WebhookUnregisterJob): Promise<void> {
  const done = (action: string, data: Record<string, unknown>) =>
    audit(job.organizationId, job.requestedBy, action, job.repositoryId, {
      connection: job.connectionId,
      ...data,
    });
  try {
    if (!FORGE_HOOK_ID_PATTERN.test(job.forgeHookId))
      return void (await done("repository.webhook_unregister_failed", { reason: "rejected" }));
    const owned = await ownersConnection(job);
    if ("problem" in owned)
      return void (await done("repository.webhook_unregister_failed", { reason: owned.problem }));
    const target = await targetFor(owned.connection, owned.repo);
    await deletePushHook(target, job.forgeHookId);
    await done("repository.webhook_unregistered", { forge: target.kind });
  } catch (error) {
    if (!(error instanceof ForgeError))
      console.error(`webhook unregister ${job.repositoryId}:`, (error as Error)?.name);
    await done("repository.webhook_unregister_failed", { reason: reasonOf(error) }).catch(() => {});
  }
}

/**
 * Registrations whose job never ran (expired, or the worker stopped in between) end as failed ("expired"), and their
 * handed-over secret is deleted, so no copy of a secret stays in the vault longer than needed.
 */
export async function sweepWebhookRegistrations(now = new Date()): Promise<number> {
  const stale = await db
    .update(w)
    .set({ registerState: "failed", registerReason: "expired", handoverSecretId: null })
    .where(and(eq(w.registerState, "pending"), lt(w.createdAt, new Date(now.getTime() - PENDING_TIMEOUT_MS))))
    .returning({
      id: w.id,
      organizationId: w.organizationId,
      repositoryId: w.repositoryId,
      createdBy: w.createdBy,
    });
  for (const row of stale) {
    await audit(row.organizationId, row.createdBy, "repository.webhook_register_failed", row.repositoryId, {
      reason: "expired",
    });
  }
  // Every copy older than that belongs to a registration that ended above or before (each is made with its webhook).
  await db
    .delete(schema.secret)
    .where(
      and(
        eq(schema.secret.purpose, "webhook-secret"),
        lt(schema.secret.createdAt, new Date(now.getTime() - PENDING_TIMEOUT_MS)),
      ),
    );
  return stale.length;
}
