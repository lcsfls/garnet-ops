/**
 * The backup file of a whole installation (ADR 0046). An age file (https://age-encryption.org, passphrase recipient, scrypt),
 * so it can also be opened without GarnetOps: `age -d garnetops-backup-….age | gunzip`. Inside, gzip-compressed lines of
 * JSON, in this order:
 *
 *   {"kind":"garnetops-backup","format":1,...}   what made it: version, the migrations applied, the tables
 *   {"kind":"keys",...}                          the vault's private key and the session secret
 *   {"kind":"table","name":"…"}                   then one {"kind":"row","d":{…}} per row of that table
 *   …
 *   {"kind":"end","rows":N}                      the last line; a file without it is incomplete
 *
 * A row is the table's row as PostgreSQL's row_to_json writes it, so a restore hands it back to json_populate_record and
 * PostgreSQL converts every type itself. The file holds every secret of the installation; the passphrase is all that protects it.
 */
import { z } from "zod";

export const BACKUP_FORMAT = 1;
/** A passphrase shorter than this is refused: the file holds every secret of the installation. */
export const BACKUP_PASSPHRASE_MIN = 16;
export const BACKUP_PASSPHRASE_MAX = 1024;
/** age's default scrypt work factor (2^18); the age tools accept it, and GarnetOps reads files up to 2^20. */
export const BACKUP_SCRYPT_LOG_N = 18;
/** The encrypted file is kept in the database in pieces of this size. */
export const BACKUP_CHUNK_BYTES = 4 * 1024 * 1024;
/** How long a finished backup can be downloaded before the worker deletes it. */
export const BACKUP_TTL_MS = 60 * 60_000;
/** A line longer than this is refused when restoring (a row of the largest tables is far below it). */
export const BACKUP_MAX_LINE_BYTES = 64 * 1024 * 1024;

export const BACKUP_ERRORS = [
  /** The worker could not read the passphrase (it was gone or sealed for another vault key). */
  "secret-missing",
  /** Building the file failed; the worker log has the reason. */
  "build-failed",
  /** The worker did not finish within an hour. */
  "expired",
] as const;
export type BackupError = (typeof BACKUP_ERRORS)[number];

export const RESTORE_ERRORS = [
  /** The passphrase does not open the file, or it is not an age file. */
  "passphrase",
  /** The file is not a GarnetOps backup, or a line of it is malformed. */
  "not-a-backup",
  /** The file ends before its last line: it was cut off. */
  "incomplete",
  /** Made by a newer GarnetOps: update this installation first. */
  "newer",
  /** Its migrations are not this product's. */
  "foreign",
  /** Restoring is only possible before the first account exists. */
  "not-empty",
  /** The data did not fit (a broken file or a database problem); nothing was changed. */
  "failed",
] as const;
export type RestoreError = (typeof RESTORE_ERRORS)[number];

const tableName = z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/);

export const backupManifestSchema = z.object({
  kind: z.literal("garnetops-backup"),
  format: z.literal(BACKUP_FORMAT),
  appVersion: z.string().min(1).max(40),
  createdAt: z.string().datetime({ offset: true }),
  /** SHA-256 of every migration applied when the backup was made, oldest first. */
  migrations: z
    .array(z.string().regex(/^[0-9a-f]{64}$/))
    .min(1)
    .max(10_000),
  tables: z.array(tableName).max(1000),
});
export type BackupManifest = z.infer<typeof backupManifestSchema>;

export const backupKeysSchema = z.object({
  kind: z.literal("keys"),
  /** PEM of the vault's private key (ADR 0004), so a restore can open the stored secrets and seal them for its own key. */
  vaultPrivateKey: z
    .string()
    .min(1)
    .max(64 * 1024),
  /** BETTER_AUTH_SECRET of the installation, so a restore can re-encrypt the second factors and webhook secrets. */
  authSecret: z.string().min(32).max(4096),
});
export type BackupKeys = z.infer<typeof backupKeysSchema>;

export const backupLineSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("table"), name: tableName }),
  z.object({ kind: z.literal("row"), d: z.record(z.string(), z.unknown()) }),
  z.object({ kind: z.literal("end"), rows: z.number().int().min(0) }),
]);
export type BackupLine = z.infer<typeof backupLineSchema>;

/** Whether a passphrase is acceptable: long enough, not only blanks. */
export function passphraseProblem(passphrase: string): "too-short" | "too-long" | null {
  if (passphrase.trim().length < BACKUP_PASSPHRASE_MIN) return "too-short";
  if (passphrase.length > BACKUP_PASSPHRASE_MAX) return "too-long";
  return null;
}

/** The file name offered for the download, by the day the backup was made (UTC). */
export function backupFileName(createdAt: Date): string {
  return `garnetops-backup-${createdAt.toISOString().slice(0, 10)}.age`;
}

/**
 * Whether this installation can restore a backup made after the migrations `backup`, given its own `ours`: the backup's must
 * be the first of ours, in order. Returns how many of ours the backup was made at.
 */
export function restoreLevel(
  backup: readonly string[],
  ours: readonly string[],
): { ok: true; level: number } | { ok: false; reason: "newer" | "foreign" } {
  for (let i = 0; i < backup.length; i++) {
    if (i >= ours.length) return { ok: false, reason: "newer" };
    if (backup[i] !== ours[i]) return { ok: false, reason: "foreign" };
  }
  return { ok: true, level: backup.length };
}
