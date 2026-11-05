/**
 * Building a backup of the whole installation (ADR 0046). The worker does it because only the worker holds the vault's private
 * key, which the backup must carry so that a restore can open the stored secrets. The owner's passphrase and the API's session
 * secret reach it sealed in the vault (purpose "backup-request"); the worker reads them once and deletes the sealed copy at once,
 * whatever happens next. The rows are read in one read-only, repeatable-read transaction, so the backup is one consistent
 * moment; they are written as lines of JSON, compressed, encrypted with age to the passphrase and stored in `backup_chunk`
 * until the backup expires. Nothing readable of the backup, no passphrase and no key is ever logged or stored.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { createGzip } from "node:zlib";
import {
  BACKUP_CHUNK_BYTES,
  BACKUP_SCRYPT_LOG_N,
  BACKUP_TTL_MS,
  type BackupError,
  type BackupKeys,
} from "@garnetops/core/backup";
import { backupLines, schema } from "@garnetops/db";
import { Encrypter } from "age-encryption";
import { and, eq, inArray, lt } from "drizzle-orm";
import { z } from "zod";
import { db, pool } from "./db.ts";
import { env } from "./env.ts";
import { workerVersion } from "./system-report.ts";
import { openSecretText } from "./vault-secrets.ts";

export const BACKUP_QUEUE = "backup.build";

export interface BackupJob {
  runId: string;
  organizationId: string;
}

const requestSchema = z.object({ passphrase: z.string().min(1), authSecret: z.string().min(32) });

const run = schema.backupRun;

async function fail(runId: string, error: BackupError) {
  await db.delete(schema.backupChunk).where(eq(schema.backupChunk.runId, runId));
  await db.update(run).set({ state: "failed", error }).where(eq(run.id, runId));
}

/** Reads and deletes the sealed request of a run, whatever its outcome; null when it is gone or cannot be opened. */
async function takeRequest(runId: string, organizationId: string) {
  const [row] = await db
    .update(run)
    .set({ state: "building" })
    .where(and(eq(run.id, runId), eq(run.state, "pending")))
    .returning({ secretId: run.secretId });
  if (!row) return { claimed: false as const };
  let text: string | null = null;
  try {
    text = await openSecretText(row.secretId, organizationId, "backup-request");
  } finally {
    if (row.secretId) await db.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    await db.update(run).set({ secretId: null }).where(eq(run.id, runId));
  }
  const parsed = text ? requestSchema.safeParse(JSON.parse(text)) : null;
  return { claimed: true as const, request: parsed?.success ? parsed.data : null };
}

/** Builds one backup. Safe to call twice for the same run: only a pending run is built. */
export async function runBackupBuild(job: BackupJob): Promise<void> {
  const taken = await takeRequest(job.runId, job.organizationId);
  if (!taken.claimed) return;
  if (!taken.request) {
    await fail(job.runId, "secret-missing");
    return;
  }
  const { passphrase, authSecret } = taken.request;
  try {
    const keys: BackupKeys = {
      kind: "keys",
      vaultPrivateKey: readFileSync(env.GARNETOPS_VAULT_PRIVATE_KEY_FILE, "utf8"),
      authSecret,
    };
    const count = { rows: 0 };
    const plain = Readable.from(backupLines(pool, keys, workerVersion ?? "unknown", count)).pipe(
      createGzip({ level: 6 }),
    );
    const encrypter = new Encrypter();
    encrypter.setScryptWorkFactor(BACKUP_SCRYPT_LOG_N);
    encrypter.setPassphrase(passphrase);
    const encrypted = await encrypter.encrypt(Readable.toWeb(plain) as ReadableStream<Uint8Array>);

    const hash = createHash("sha256");
    let size = 0;
    let seq = 0;
    let pending: Buffer[] = [];
    let pendingBytes = 0;
    const flush = async () => {
      if (pendingBytes === 0) return;
      const data = Buffer.concat(pending, pendingBytes);
      pending = [];
      pendingBytes = 0;
      await db.insert(schema.backupChunk).values({ runId: job.runId, seq, data });
      seq += 1;
    };
    for await (const piece of encrypted as unknown as AsyncIterable<Uint8Array>) {
      const buffer = Buffer.from(piece.buffer, piece.byteOffset, piece.byteLength);
      hash.update(buffer);
      size += buffer.length;
      let offset = 0;
      while (offset < buffer.length) {
        const take = Math.min(BACKUP_CHUNK_BYTES - pendingBytes, buffer.length - offset);
        pending.push(Buffer.from(buffer.subarray(offset, offset + take)));
        pendingBytes += take;
        offset += take;
        if (pendingBytes === BACKUP_CHUNK_BYTES) await flush();
      }
    }
    await flush();
    const now = new Date();
    await db
      .update(run)
      .set({
        state: "ready",
        sizeBytes: size,
        sha256: hash.digest("hex"),
        rowCount: count.rows,
        appVersion: workerVersion ?? null,
        readyAt: now,
        expiresAt: new Date(now.getTime() + BACKUP_TTL_MS),
      })
      .where(and(eq(run.id, job.runId), eq(run.state, "building")));
    console.log(`backup ${job.runId}: ${count.rows} rows, ${size} bytes`);
  } catch (error) {
    console.error(`backup ${job.runId} failed: ${(error as Error)?.name ?? "error"}`);
    await fail(job.runId, "build-failed");
  }
}

/**
 * Deletes what a backup leaves: the file of a backup an hour after it was ready, and a run that never finished within an hour
 * (with its sealed request, if the worker never read it).
 */
export async function sweepBackups(now = new Date()): Promise<void> {
  const expired = await db
    .update(run)
    .set({ state: "expired" })
    .where(and(eq(run.state, "ready"), lt(run.expiresAt, now)))
    .returning({ id: run.id });
  const stale = await db
    .update(run)
    .set({ state: "failed", error: "expired" })
    .where(
      and(
        inArray(run.state, ["pending", "building"]),
        lt(run.createdAt, new Date(now.getTime() - BACKUP_TTL_MS)),
      ),
    )
    .returning({ id: run.id, secretId: run.secretId });
  const ids = [...expired, ...stale].map((row) => row.id);
  if (ids.length > 0) await db.delete(schema.backupChunk).where(inArray(schema.backupChunk.runId, ids));
  const secrets = stale.map((row) => row.secretId).filter((id): id is string => Boolean(id));
  if (secrets.length > 0) {
    await db.delete(schema.secret).where(inArray(schema.secret.id, secrets));
    await db
      .update(run)
      .set({ secretId: null })
      .where(
        inArray(
          run.id,
          stale.map((row) => row.id),
        ),
      );
  }
}
