/**
 * Restoring a backup (ADR 0046) onto an installation that has no account yet. Everything happens in one transaction: if any
 * step fails, the fresh installation stays exactly as it was.
 *
 * 1. The file is decrypted with the passphrase as it streams in; its first lines say which migrations it was made at and carry
 *    the old vault private key and session secret. Nothing in the database is touched before they check out.
 * 2. The tables of `public` are dropped and the migrations are applied again, up to the backup's; foreign keys are lifted.
 * 3. The rows go in table by table, as PostgreSQL wrote them (json_populate_recordset converts every type itself); then the
 *    foreign keys come back (which checks every row) and the sequences continue after the highest id.
 * 4. The remaining migrations of this version move the data forward, as on any update.
 * 5. Every stored secret is opened with the old vault key and sealed for this installation's key; second factors and webhook
 *    secrets are re-encrypted from the old session secret to this one. The old keys exist only in memory, only for this request.
 */
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";
import {
  BACKUP_MAX_LINE_BYTES,
  type BackupKeys,
  type BackupManifest,
  backupKeysSchema,
  backupLineSchema,
  backupManifestSchema,
  type RestoreError,
  restoreLevel,
} from "@garnetops/core/backup";
import {
  loadVaultPrivateKey,
  open,
  type SecretPurpose,
  seal,
  type VaultPublicKey,
} from "@garnetops/core/vault";
import {
  appliedMigrationHashes,
  applyMigrations,
  ident,
  type Pool,
  type PoolClient,
  readMigrations,
} from "@garnetops/db";
import { Decrypter } from "age-encryption";
import { parseEnvelope, symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { openWebhookSecret, sealWebhookSecret, webhookKeyFrom } from "./webhook-secret.ts";

type AuthKey = Parameters<typeof symmetricEncrypt>[0]["key"];

type Client = PoolClient;

export class RestoreFailure extends Error {
  readonly code: RestoreError;
  constructor(code: RestoreError) {
    super(code);
    this.code = code;
    this.name = "RestoreFailure";
  }
}

export interface RestoreDeps {
  pool: Pool;
  vaultPublicKey: VaultPublicKey;
  /** This installation's session secret configuration, as better-auth encrypts with it. */
  authKey: AuthKey;
  /** This installation's session secret, for the webhook secrets. */
  authSecret: string;
}

export interface RestoreSummary {
  appVersion: string;
  createdAt: string;
  rows: number;
  tables: number;
  secrets: number;
  /** Secrets that did not open with the backup's key; they stay as they were and will not work. */
  secretsNotOpened: number;
}

/** Splits a byte stream into lines, refusing any line longer than the limit. */
async function* lines(input: AsyncIterable<Buffer>): AsyncGenerator<string> {
  let parts: Buffer[] = [];
  let size = 0;
  for await (const piece of input) {
    let start = 0;
    for (;;) {
      const nl = piece.indexOf(10, start);
      const end = nl === -1 ? piece.length : nl;
      size += end - start;
      if (size > BACKUP_MAX_LINE_BYTES) throw new RestoreFailure("not-a-backup");
      parts.push(piece.subarray(start, end));
      if (nl === -1) break;
      yield Buffer.concat(parts).toString("utf8");
      parts = [];
      size = 0;
      start = nl + 1;
    }
  }
  if (size > 0) yield Buffer.concat(parts).toString("utf8");
}

function parseLine(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new RestoreFailure("not-a-backup");
  }
}

/** Opens the stream with the passphrase; a wrong passphrase or a file that is no age file fails here. */
async function decrypt(
  input: ReadableStream<Uint8Array>,
  passphrase: string,
): Promise<AsyncIterable<Buffer>> {
  const decrypter = new Decrypter();
  decrypter.addPassphrase(passphrase);
  let plain: ReadableStream<Uint8Array>;
  try {
    plain = await decrypter.decrypt(input);
  } catch {
    throw new RestoreFailure("passphrase");
  }
  const gunzip = createGunzip();
  const source = Readable.fromWeb(plain as import("node:stream/web").ReadableStream<Uint8Array>);
  source.on("error", (error) => gunzip.destroy(error));
  return source.pipe(gunzip);
}

const ROWS_PER_INSERT = 500;
const BYTES_PER_INSERT = 8 * 1024 * 1024;

/** Re-encrypts a value better-auth encrypted with the old secret, for the new one. */
async function reencryptAuth(data: string, oldSecret: string, newKey: AuthKey): Promise<string> {
  const envelope = parseEnvelope(data);
  const plain = await symmetricDecrypt({ key: oldSecret, data: envelope ? envelope.ciphertext : data });
  return symmetricEncrypt({ key: newKey, data: plain });
}

async function replaceSchema(client: Client, level: number) {
  const tables = await client.query<{ name: string }>(
    "select tablename as name from pg_tables where schemaname = 'public'",
  );
  if (tables.rows.length > 0) {
    await client.query(
      `drop table ${tables.rows.map((row) => `public.${ident(row.name)}`).join(", ")} cascade`,
    );
  }
  await client.query("drop table if exists drizzle.__drizzle_migrations");
  await applyMigrations(client, readMigrations(), 0, level);
}

async function liftForeignKeys(client: Client) {
  const fks = await client.query<{ tbl: string; name: string; def: string }>(
    `select c.relname as tbl, k.conname as name, pg_get_constraintdef(k.oid) as def
       from pg_constraint k join pg_class c on c.oid = k.conrelid
      where k.contype = 'f' and k.connamespace = 'public'::regnamespace`,
  );
  for (const fk of fks.rows) {
    await client.query(`alter table public.${ident(fk.tbl)} drop constraint ${ident(fk.name)}`);
  }
  return fks.rows;
}

async function insertableColumns(client: Client, table: string): Promise<string[]> {
  const columns = await client.query<{ name: string }>(
    `select column_name as name from information_schema.columns
      where table_schema = 'public' and table_name = $1 and is_generated = 'NEVER' and is_identity = 'NO'
      order by ordinal_position`,
    [table],
  );
  return columns.rows.map((row) => row.name);
}

async function continueSequences(client: Client) {
  const serials = await client.query<{ tbl: string; col: string }>(
    `select table_name as tbl, column_name as col from information_schema.columns
      where table_schema = 'public' and column_default like 'nextval(%'`,
  );
  for (const { tbl, col } of serials.rows) {
    await client.query(
      `select setval(pg_get_serial_sequence($1, $2), coalesce((select max(${ident(col)}) from public.${ident(tbl)}), 0) + 1, false)`,
      [`public.${ident(tbl)}`, col],
    );
  }
}

async function resealSecrets(client: Client, keys: BackupKeys, deps: RestoreDeps) {
  const oldKey = loadVaultPrivateKey(keys.vaultPrivateKey);
  const secrets = await client.query<{
    id: string;
    organization_id: string;
    purpose: SecretPurpose;
    sealed: unknown;
  }>("select id, organization_id, purpose, sealed from public.secret");
  let notOpened = 0;
  for (const row of secrets.rows) {
    const binding = { organizationId: row.organization_id, recordId: row.id, purpose: row.purpose };
    let plain: Buffer;
    try {
      plain = open(row.sealed as Parameters<typeof open>[0], binding, oldKey);
    } catch {
      notOpened += 1;
      continue;
    }
    try {
      await client.query("update public.secret set sealed = $1, vault_key_id = $2 where id = $3", [
        JSON.stringify(seal(plain, binding, deps.vaultPublicKey)),
        deps.vaultPublicKey.id,
        row.id,
      ]);
    } finally {
      plain.fill(0);
    }
  }
  return { secrets: secrets.rows.length, notOpened };
}

async function reencryptSessionSecrets(client: Client, keys: BackupKeys, deps: RestoreDeps) {
  const factors = await client.query<{ id: string; secret: string; backup_codes: string }>(
    "select id, secret, backup_codes from public.two_factor",
  );
  for (const row of factors.rows) {
    await client.query("update public.two_factor set secret = $1, backup_codes = $2 where id = $3", [
      await reencryptAuth(row.secret, keys.authSecret, deps.authKey),
      await reencryptAuth(row.backup_codes, keys.authSecret, deps.authKey),
      row.id,
    ]);
  }
  const oldWebhookKey = webhookKeyFrom(keys.authSecret);
  const newWebhookKey = webhookKeyFrom(deps.authSecret);
  const hooks = await client.query<{ id: string; secret_sealed: string }>(
    "select id, secret_sealed from public.repository_webhook",
  );
  for (const hook of hooks.rows) {
    const secret = openWebhookSecret(hook.secret_sealed, hook.id, oldWebhookKey);
    // A secret that does not open stays as it is: the webhook answers "bad signature" until it gets a new one.
    if (secret === null) continue;
    await client.query("update public.repository_webhook set secret_sealed = $1 where id = $2", [
      sealWebhookSecret(secret, hook.id, newWebhookKey),
      hook.id,
    ]);
  }
}

/**
 * Restores the backup in `input` with `passphrase`. Throws RestoreFailure with a code; any other error means the database
 * refused something, and the transaction was rolled back.
 */
export async function restoreBackup(
  input: ReadableStream<Uint8Array>,
  passphrase: string,
  deps: RestoreDeps,
): Promise<RestoreSummary> {
  const reader = lines(await decrypt(input, passphrase))[Symbol.asyncIterator]();
  /** The next line; a stream that was cut off or changed fails while it is read (age checks every 64 KiB piece). */
  const read = async () => {
    try {
      return await reader.next();
    } catch (error) {
      if (error instanceof RestoreFailure) throw error;
      throw new RestoreFailure("incomplete");
    }
  };
  const next = async () => {
    const line = await read();
    if (line.done) throw new RestoreFailure("incomplete");
    return parseLine(line.value);
  };

  const manifestParsed = backupManifestSchema.safeParse(await next());
  if (!manifestParsed.success) throw new RestoreFailure("not-a-backup");
  const manifest: BackupManifest = manifestParsed.data;
  const keysParsed = backupKeysSchema.safeParse(await next());
  if (!keysParsed.success) throw new RestoreFailure("not-a-backup");
  const keys = keysParsed.data;
  try {
    loadVaultPrivateKey(keys.vaultPrivateKey);
  } catch {
    throw new RestoreFailure("not-a-backup");
  }

  const ours = readMigrations();
  const level = restoreLevel(
    manifest.migrations,
    ours.map((migration) => migration.hash),
  );
  if (!level.ok) throw new RestoreFailure(level.reason);

  const client = await deps.pool.connect();
  let inTransaction = false;
  try {
    await client.query("begin");
    inTransaction = true;
    await client.query("select pg_advisory_xact_lock(hashtext('garnetops.setup'))");
    const users = await client.query<{ n: string }>("select count(*)::text as n from public.user");
    if (Number(users.rows[0]?.n ?? "0") > 0) throw new RestoreFailure("not-empty");
    const applied = await appliedMigrationHashes(client);
    if (applied.length !== ours.length) throw new RestoreFailure("failed");

    await replaceSchema(client, level.level);
    const fks = await liftForeignKeys(client);

    let table: string | null = null;
    let columns: string[] = [];
    let batch: string[] = [];
    let batchBytes = 0;
    let rows = 0;
    const seen = new Set<string>();
    const flush = async () => {
      if (!table || batch.length === 0) return;
      const list = columns.map(ident).join(", ");
      await client.query(
        `insert into public.${ident(table)} (${list}) select ${list} from json_populate_recordset(null::public.${ident(table)}, $1::json)`,
        [`[${batch.join(",")}]`],
      );
      batch = [];
      batchBytes = 0;
    };
    let ended = false;
    for (;;) {
      const raw = await next();
      const parsed = backupLineSchema.safeParse(raw);
      if (!parsed.success) throw new RestoreFailure("not-a-backup");
      const line = parsed.data;
      if (line.kind === "end") {
        await flush();
        if (line.rows !== rows) throw new RestoreFailure("incomplete");
        ended = true;
        break;
      }
      if (line.kind === "table") {
        await flush();
        if (!manifest.tables.includes(line.name) || seen.has(line.name))
          throw new RestoreFailure("not-a-backup");
        seen.add(line.name);
        table = line.name;
        columns = await insertableColumns(client, table);
        if (columns.length === 0) throw new RestoreFailure("not-a-backup");
        continue;
      }
      if (!table) throw new RestoreFailure("not-a-backup");
      const text = JSON.stringify(line.d);
      batch.push(text);
      batchBytes += text.length;
      rows += 1;
      if (batch.length >= ROWS_PER_INSERT || batchBytes >= BYTES_PER_INSERT) await flush();
    }
    if (!ended) throw new RestoreFailure("incomplete");
    // The age stream checks its integrity at the very end; read to the end so a cut-off or changed file fails here.
    for (;;) {
      const rest = await read();
      if (rest.done) break;
      if (rest.value.trim()) throw new RestoreFailure("not-a-backup");
    }

    for (const fk of fks) {
      await client.query(`alter table public.${ident(fk.tbl)} add constraint ${ident(fk.name)} ${fk.def}`);
    }
    await continueSequences(client);
    await applyMigrations(client, ours, level.level, ours.length);
    const resealed = await resealSecrets(client, keys, deps);
    await reencryptSessionSecrets(client, keys, deps);
    await client.query("delete from public.session");
    await client.query(
      `insert into public.audit_log (organization_id, action, target_type, data)
       select id, 'backup.restored', 'installation', $1::jsonb from public.organization`,
      [
        JSON.stringify({
          backupCreatedAt: manifest.createdAt,
          backupVersion: manifest.appVersion,
          rows,
          secretsNotOpened: resealed.notOpened,
        }),
      ],
    );
    await client.query("commit");
    inTransaction = false;
    return {
      appVersion: manifest.appVersion,
      createdAt: manifest.createdAt,
      rows,
      tables: seen.size,
      secrets: resealed.secrets,
      secretsNotOpened: resealed.notOpened,
    };
  } catch (error) {
    if (error instanceof RestoreFailure) throw error;
    console.error(`restore failed: ${(error as Error)?.name ?? "error"}`);
    throw new RestoreFailure("failed");
  } finally {
    if (inTransaction) await client.query("rollback").catch(() => undefined);
    client.release();
  }
}
