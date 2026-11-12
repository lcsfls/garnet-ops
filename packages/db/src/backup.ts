/**
 * What backup and restore (ADR 0046) share about the database: which tables a backup carries, and the migrations, applied
 * the way drizzle's migrator applies them (same statements, same bookkeeping in `drizzle.__drizzle_migrations`) but inside a
 * transaction the caller holds, and only up to a given migration. A restore needs that: the rows of a backup fit the schema
 * of the migration the backup was made at; the later migrations then move them forward as they move any installation.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BACKUP_FORMAT, type BackupKeys, type BackupManifest } from "@garnetops/core/backup";
import type pg from "pg";

const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

export interface Migration {
  tag: string;
  /** The journal's timestamp; drizzle records it as `created_at` and compares by it. */
  when: number;
  /** SHA-256 of the file, as drizzle records it. */
  hash: string;
  statements: string[];
}

let cached: Migration[] | null = null;

/** Every migration this version knows, in order, read exactly as drizzle reads them. */
export function readMigrations(folder = migrationsFolder): Migration[] {
  if (folder === migrationsFolder && cached) return cached;
  const journal = JSON.parse(readFileSync(`${folder}/meta/_journal.json`, "utf8")) as {
    entries: { tag: string; when: number }[];
  };
  const migrations = journal.entries.map((entry) => {
    const text = readFileSync(`${folder}/${entry.tag}.sql`, "utf8");
    return {
      tag: entry.tag,
      when: entry.when,
      hash: createHash("sha256").update(text).digest("hex"),
      statements: text.split("--> statement-breakpoint"),
    };
  });
  if (folder === migrationsFolder) cached = migrations;
  return migrations;
}

type Client = Pick<pg.PoolClient, "query">;

/** The hashes of the migrations applied to this database, oldest first; empty when none are. */
export async function appliedMigrationHashes(client: Client): Promise<string[]> {
  const exists = await client.query<{ present: boolean }>(
    "select to_regclass('drizzle.__drizzle_migrations') is not null as present",
  );
  if (!exists.rows[0]?.present) return [];
  const rows = await client.query<{ hash: string }>(
    "select hash from drizzle.__drizzle_migrations order by created_at asc, id asc",
  );
  return rows.rows.map((row) => row.hash);
}

/**
 * Applies `migrations[from..to)` in the caller's transaction and records each as drizzle does, so the migrator at the next
 * start sees them as applied and runs only what comes after.
 */
export async function applyMigrations(
  client: Client,
  migrations: readonly Migration[],
  from: number,
  to: number,
): Promise<void> {
  await client.query("create schema if not exists drizzle");
  await client.query(
    "create table if not exists drizzle.__drizzle_migrations (id serial primary key, hash text not null, created_at bigint)",
  );
  for (const migration of migrations.slice(from, to)) {
    for (const statement of migration.statements) {
      if (statement.trim()) await client.query(statement);
    }
    await client.query('insert into drizzle.__drizzle_migrations ("hash", "created_at") values ($1, $2)', [
      migration.hash,
      migration.when,
    ]);
  }
}

/**
 * Tables a backup leaves out: sign-in sessions and one-time tokens (a restored installation starts with everyone signed out),
 * rate-limit counters, the backups themselves, the worker's heartbeat and how far the update sidecar's journal was copied
 * (both belong to the machine, not to the data).
 */
export const BACKUP_EXCLUDED_TABLES: ReadonlySet<string> = new Set([
  "session",
  "verification",
  "rate_limit",
  "backup_run",
  "backup_chunk",
  "worker_heartbeat",
  // Code a person viewed (ADR 0048): never kept beyond the hand-over, never in a backup.
  "code_request",
  "updater_journal_cursor",
]);

/** Secrets a backup leaves out: the sealed request of the backup run itself. */
export const BACKUP_EXCLUDED_SECRET_PURPOSES: ReadonlySet<string> = new Set(["backup-request"]);

/** The tables of the `public` schema a backup carries, by name. */
export async function backupTables(client: Client): Promise<string[]> {
  const rows = await client.query<{ name: string }>(
    "select tablename as name from pg_tables where schemaname = 'public' order by tablename",
  );
  return rows.rows.map((row) => row.name).filter((name) => !BACKUP_EXCLUDED_TABLES.has(name));
}

/** Quotes an identifier for SQL. Table and column names come from the catalogue or the backup and are checked first. */
export function ident(name: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error("unexpected identifier");
  return `"${name}"`;
}

/** The secret purposes left out, as an SQL list; the names are constants of a fixed shape. */
const excludedPurposes = [...BACKUP_EXCLUDED_SECRET_PURPOSES]
  .map((purpose) => {
    if (!/^[a-z-]+$/.test(purpose)) throw new Error("unexpected secret purpose");
    return `'${purpose}'`;
  })
  .join(", ");

/** Rows read from the database per round trip. */
const FETCH_ROWS = 500;

/**
 * The lines of a backup file (packages/core/src/backup.ts), as buffers, from one consistent read of the database: a read-only,
 * repeatable-read transaction. `count` is filled in as rows go out. The caller compresses and encrypts them.
 */
export async function* backupLines(
  pool: pg.Pool,
  keys: BackupKeys,
  appVersion: string,
  count: { rows: number },
): AsyncGenerator<Buffer> {
  const client = await pool.connect();
  let open = false;
  try {
    await client.query("begin isolation level repeatable read read only");
    open = true;
    const migrations = await appliedMigrationHashes(client);
    const tables = await backupTables(client);
    const manifest: BackupManifest = {
      kind: "garnetops-backup",
      format: BACKUP_FORMAT,
      appVersion,
      createdAt: new Date().toISOString(),
      migrations,
      tables,
    };
    yield Buffer.from(`${JSON.stringify(manifest)}\n`);
    yield Buffer.from(`${JSON.stringify(keys)}\n`);
    for (const table of tables) {
      yield Buffer.from(`${JSON.stringify({ kind: "table", name: table })}\n`);
      const where = table === "secret" ? ` where t.purpose not in (${excludedPurposes})` : "";
      await client.query(
        `declare backup_rows no scroll cursor for select row_to_json(t)::text as j from ${ident(table)} t${where}`,
      );
      for (;;) {
        const batch = await client.query<{ j: string }>(`fetch ${FETCH_ROWS} from backup_rows`);
        if (batch.rows.length === 0) break;
        const text = batch.rows.map((row) => `{"kind":"row","d":${row.j}}\n`).join("");
        count.rows += batch.rows.length;
        yield Buffer.from(text);
      }
      await client.query("close backup_rows");
    }
    yield Buffer.from(`${JSON.stringify({ kind: "end", rows: count.rows })}\n`);
    await client.query("commit");
    open = false;
  } finally {
    if (open) await client.query("rollback").catch(() => undefined);
    client.release();
  }
}
