/**
 * Backups of the whole installation (ADR 0046), for owners. The API never builds one: it cannot open the stored secrets, only
 * the worker can. Asking for a backup seals the passphrase and this API's session secret for the worker (purpose
 * "backup-request") and queues a job with ids only; the worker deletes the sealed copy as soon as it has read it. The finished
 * file is encrypted to the passphrase (age); the API only streams it out to the owner who asked, within an hour, after a recent
 * sign-in. Every request and download is audited, and every owner is told about a download.
 */
import { newId } from "@garnetops/core";
import { BACKUP_PASSPHRASE_MAX, backupFileName, passphraseProblem } from "@garnetops/core/backup";
import { seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { stream } from "hono/streaming";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { env, vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notifyUsers } from "../lib/notify-users.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const run = schema.backupRun;
const body = z.object({ passphrase: z.string().min(1).max(BACKUP_PASSPHRASE_MAX) });

/** What a backup row may show: state, sizes and times. Never the request's secret. */
const view = (row: typeof run.$inferSelect, requesterName: string | null, mine: boolean) => ({
  id: row.id,
  state: row.state,
  error: row.error,
  sizeBytes: row.sizeBytes,
  sha256: row.sha256,
  rowCount: row.rowCount,
  appVersion: row.appVersion,
  createdAt: row.createdAt.toISOString(),
  readyAt: row.readyAt?.toISOString() ?? null,
  expiresAt: row.expiresAt?.toISOString() ?? null,
  downloadedAt: row.downloadedAt?.toISOString() ?? null,
  requestedBy: requesterName,
  /** Only the owner who asked can download it. */
  canDownload: mine && row.state === "ready",
  fileName: backupFileName(row.createdAt),
});

/**
 * A backup holds every organisation's data, so it is only offered while the installation has exactly one organisation (the
 * case today; ADR 0046 says what changes when there are several).
 */
async function requireSingleOrganisation() {
  const [row] = await db.select({ n: count() }).from(schema.organization);
  if ((row?.n ?? 0) !== 1) {
    throw new ProblemError(
      409,
      "backup-several-organisations",
      "Backups need an installation with one organisation",
    );
  }
}

export const backupRoutes = new Hono<AppEnv>()
  /** The last backups, newest first. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "owner");
    const rows = await db
      .select({ run, name: schema.user.name })
      .from(run)
      .leftJoin(schema.user, eq(schema.user.id, run.requestedBy))
      .where(eq(run.organizationId, actor.organizationId))
      .orderBy(desc(run.createdAt))
      .limit(10);
    c.header("cache-control", "no-store");
    return c.json({
      items: rows.map((row) => view(row.run, row.name, row.run.requestedBy === actor.userId)),
    });
  })
  /** Asks the worker for a backup encrypted to `passphrase`. */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "owner");
    requireRecentSignIn(actor);
    const input = body.parse(await c.req.json());
    const problem = passphraseProblem(input.passphrase);
    if (problem)
      throw new ProblemError(422, `passphrase-${problem}`, "The passphrase is too short or too long");
    await requireSingleOrganisation();
    await rateLimit(`backup:${actor.userId}`, 3, 60 * 60_000);
    const [busy] = await db
      .select({ id: run.id })
      .from(run)
      .where(and(eq(run.organizationId, actor.organizationId), inArray(run.state, ["pending", "building"])))
      .limit(1);
    if (busy) throw new ProblemError(409, "backup-running", "A backup is being made");

    const runId = newId("bkp");
    const secretId = newId("sec");
    const binding = {
      organizationId: actor.organizationId,
      recordId: secretId,
      purpose: "backup-request" as const,
    };
    await db.transaction(async (tx) => {
      await tx.insert(schema.secret).values({
        id: secretId,
        organizationId: actor.organizationId,
        purpose: "backup-request",
        sealed: seal(
          JSON.stringify({ passphrase: input.passphrase, authSecret: env.BETTER_AUTH_SECRET }),
          binding,
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      await tx.insert(run).values({
        id: runId,
        organizationId: actor.organizationId,
        requestedBy: actor.userId,
        state: "pending",
        secretId,
      });
    });
    await boss.send(QUEUES.backupBuild, { runId, organizationId: actor.organizationId }, { retryLimit: 0 });
    await audit(actor, "backup.requested", { type: "backup", id: runId });
    return c.json({ id: runId }, 202);
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "owner");
    const [row] = await db
      .select({ run, name: schema.user.name })
      .from(run)
      .leftJoin(schema.user, eq(schema.user.id, run.requestedBy))
      .where(and(eq(run.id, c.req.param("id")), eq(run.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw new ProblemError(404, "not-found", "Backup not found");
    c.header("cache-control", "no-store");
    return c.json(view(row.run, row.name, row.run.requestedBy === actor.userId));
  })
  /**
   * The encrypted file, for the owner who asked for it, while it has not expired (an hour after it was ready). Asking needed a
   * recent sign-in; the download itself does not, so a slow build does not end in a second sign-in.
   */
  .get("/:id/download", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "owner");
    const [row] = await db
      .select()
      .from(run)
      .where(and(eq(run.id, c.req.param("id")), eq(run.organizationId, actor.organizationId)))
      .limit(1);
    if (!row || row.requestedBy !== actor.userId)
      throw new ProblemError(404, "not-found", "Backup not found");
    if (row.state !== "ready" || !row.expiresAt || row.expiresAt.getTime() < Date.now()) {
      throw new ProblemError(410, "backup-gone", "This backup can no longer be downloaded");
    }
    const first = row.downloadedAt === null;
    await db.update(run).set({ downloadedAt: new Date() }).where(eq(run.id, row.id));
    await audit(
      actor,
      "backup.downloaded",
      { type: "backup", id: row.id },
      {
        sizeBytes: row.sizeBytes,
        sha256: row.sha256,
      },
    );
    if (first) {
      const [me] = await db
        .select({ name: schema.user.name })
        .from(schema.user)
        .where(eq(schema.user.id, actor.userId))
        .limit(1);
      await notifyUsers({
        organizationId: actor.organizationId,
        titleKey: "backupDownloaded",
        params: { person: me?.name ?? "" },
        link: "/settings?section=backup",
      });
    }
    c.header("content-type", "application/octet-stream");
    c.header("content-disposition", `attachment; filename="${backupFileName(row.createdAt)}"`);
    c.header("cache-control", "no-store");
    if (row.sizeBytes !== null) c.header("content-length", String(row.sizeBytes));
    return stream(c, async (out) => {
      for (let seq = 0; ; seq++) {
        const [chunk] = await db
          .select({ data: schema.backupChunk.data })
          .from(schema.backupChunk)
          .where(and(eq(schema.backupChunk.runId, row.id), eq(schema.backupChunk.seq, seq)))
          .limit(1);
        if (!chunk) break;
        await out.write(new Uint8Array(chunk.data));
      }
    });
  });
