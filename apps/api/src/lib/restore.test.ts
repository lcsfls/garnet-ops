/**
 * Backup and restore (ADR 0046) end to end against two throw-away PostgreSQL databases on the development server: a backup of
 * one installation, made with the same code the worker uses, restored onto a fresh installation with its own vault key and
 * session secret. Checks that the data arrives, that every secret, second factor and webhook secret works with the new keys and
 * no longer with the old ones, that sessions are gone, and that a wrong passphrase, a cut-off file, a file of a newer version
 * and an installation that already has accounts change nothing. Skipped without the development PostgreSQL.
 */
import { Readable } from "node:stream";
import { createGzip } from "node:zlib";
import { BACKUP_FORMAT, type BackupKeys } from "@garnetops/core/backup";
import {
  generateVaultKeyPair,
  loadVaultPrivateKey,
  loadVaultPublicKey,
  open,
  seal,
  vaultPublicKeyOf,
} from "@garnetops/core/vault";
import { applyMigrations, backupLines, createDb, readMigrations, schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Encrypter } from "age-encryption";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { count, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("../env.ts", () => ({ env: { BETTER_AUTH_SECRET: "n".repeat(48) } }));

const { RestoreFailure, restoreBackup } = await import("./restore.ts");
const { openWebhookSecret, sealWebhookSecret, webhookKeyFrom } = await import("./webhook-secret.ts");

const adminUrl = devDatabaseUrl();
const OLD_AUTH = "o".repeat(48);
const NEW_AUTH = "n".repeat(48);
const PASSPHRASE = "correct horse battery staple";
const ORG = "org_backup";

/** A backup file of `source`, as the worker makes it. */
async function backupOf(
  source: TestDatabase,
  keys: BackupKeys,
  passphrase = PASSPHRASE,
): Promise<Uint8Array> {
  const plain = Readable.from(backupLines(source.pool, keys, "0.1.0", { rows: 0 })).pipe(createGzip());
  const encrypter = new Encrypter();
  encrypter.setScryptWorkFactor(10);
  encrypter.setPassphrase(passphrase);
  const chunks: Buffer[] = [];
  for await (const piece of plain) chunks.push(piece as Buffer);
  return encrypter.encrypt(new Uint8Array(Buffer.concat(chunks)));
}

const streamOf = (bytes: Uint8Array) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

describe.skipIf(!adminUrl)("restoring a backup", () => {
  let source: TestDatabase;
  let target: TestDatabase;
  const oldVault = generateVaultKeyPair();
  const newVault = generateVaultKeyPair();
  const deps = () => ({
    pool: target.pool,
    vaultPublicKey: loadVaultPublicKey(newVault.publicKeyPem),
    authKey: NEW_AUTH,
    authSecret: NEW_AUTH,
  });
  const keys: BackupKeys = { kind: "keys", vaultPrivateKey: oldVault.privateKeyPem, authSecret: OLD_AUTH };
  let file: Uint8Array;

  beforeAll(async () => {
    source = await createTestDatabase(adminUrl as string, "backup_source");
    target = await createTestDatabase(adminUrl as string, "backup_target");
    const s = source.db;
    await s.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await s
      .insert(schema.user)
      .values({ id: "usr_owner", name: "Owner", email: "owner@example.com", emailVerified: true });
    await s.insert(schema.membership).values({ organizationId: ORG, userId: "usr_owner", role: "owner" });
    await s.insert(schema.twoFactor).values({
      id: "tf_1",
      userId: "usr_owner",
      secret: await symmetricEncrypt({ key: OLD_AUTH, data: "totp-secret" }),
      backupCodes: await symmetricEncrypt({ key: OLD_AUTH, data: JSON.stringify(["code-1"]) }),
    });
    await s.insert(schema.session).values({
      id: "ses_1",
      userId: "usr_owner",
      token: "t".repeat(32),
      expiresAt: new Date(Date.now() + 3600_000),
    });
    const oldPublic = vaultPublicKeyOf(loadVaultPrivateKey(oldVault.privateKeyPem));
    for (const [id, purpose, value] of [
      ["sec_token", "forge-token", "forge-token-value"],
      ["sec_request", "backup-request", "never in a backup"],
    ] as const) {
      await s.insert(schema.secret).values({
        id,
        organizationId: ORG,
        purpose,
        sealed: seal(value, { organizationId: ORG, recordId: id, purpose }, oldPublic),
        vaultKeyId: oldPublic.id,
      });
    }
    await s.insert(schema.repository).values({
      id: "repo_1",
      organizationId: ORG,
      name: "example/app",
      url: "https://git.example.com/example/app.git",
      authKind: "none",
    });
    await s.insert(schema.repositoryWebhook).values({
      id: "hook_1",
      organizationId: ORG,
      repositoryId: "repo_1",
      pathId: "p".repeat(43),
      secretSealed: sealWebhookSecret("hook-secret", "hook_1", webhookKeyFrom(OLD_AUTH)),
    });
    await s.insert(schema.auditLog).values([{ organizationId: ORG, action: "setup.completed" }]);
    file = await backupOf(source, keys);
  }, 120_000);

  afterAll(async () => {
    await source?.drop();
    await target?.drop();
  });

  it("refuses a wrong passphrase and changes nothing", async () => {
    await expect(restoreBackup(streamOf(file), "a wrong passphrase!", deps())).rejects.toMatchObject({
      code: "passphrase",
    });
    const [orgs] = await target.db.select({ n: count() }).from(schema.organization);
    expect(orgs?.n).toBe(0);
  });

  it("refuses a file that was cut off and changes nothing", async () => {
    const cut = file.subarray(0, file.length - 40);
    const error = await restoreBackup(streamOf(cut), PASSPHRASE, deps()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RestoreFailure);
    expect((error as InstanceType<typeof RestoreFailure>).code).toBe("incomplete");
    const [orgs] = await target.db.select({ n: count() }).from(schema.organization);
    expect(orgs?.n).toBe(0);
  });

  it("refuses a backup made by a newer version", async () => {
    const lines = [
      JSON.stringify({
        kind: "garnetops-backup",
        format: BACKUP_FORMAT,
        appVersion: "9.0.0",
        createdAt: new Date().toISOString(),
        migrations: [...readMigrations().map((m) => m.hash), "f".repeat(64)],
        tables: [],
      }),
      JSON.stringify(keys),
      JSON.stringify({ kind: "end", rows: 0 }),
    ];
    const gz = await new Promise<Buffer>((resolve) => {
      const chunks: Buffer[] = [];
      const z = createGzip();
      z.on("data", (c: Buffer) => chunks.push(c));
      z.on("end", () => resolve(Buffer.concat(chunks)));
      z.end(`${lines.join("\n")}\n`);
    });
    const e = new Encrypter();
    e.setScryptWorkFactor(10);
    e.setPassphrase(PASSPHRASE);
    await expect(
      restoreBackup(streamOf(await e.encrypt(new Uint8Array(gz))), PASSPHRASE, deps()),
    ).rejects.toMatchObject({ code: "newer" });
  });

  it("restores the data and moves every secret to the new keys", async () => {
    const summary = await restoreBackup(streamOf(file), PASSPHRASE, deps());
    expect(summary.secretsNotOpened).toBe(0);
    expect(summary.secrets).toBe(1);

    const t = target.db;
    const [org] = await t.select().from(schema.organization).where(eq(schema.organization.id, ORG));
    expect(org?.name).toBe("Example Org");
    expect(await t.select().from(schema.session)).toHaveLength(0);

    // The vault secret opens with the new key only; the backup's own request was never in the file.
    const secrets = await t.select().from(schema.secret);
    expect(secrets.map((row) => row.id)).toEqual(["sec_token"]);
    const binding = { organizationId: ORG, recordId: "sec_token", purpose: "forge-token" as const };
    expect(open(secrets[0]?.sealed, binding, loadVaultPrivateKey(newVault.privateKeyPem)).toString()).toBe(
      "forge-token-value",
    );
    expect(() => open(secrets[0]?.sealed, binding, loadVaultPrivateKey(oldVault.privateKeyPem))).toThrow();

    // Second factors and webhook secrets follow the new session secret.
    const [factor] = await t.select().from(schema.twoFactor);
    expect(await symmetricDecrypt({ key: NEW_AUTH, data: factor?.secret as string })).toBe("totp-secret");
    const [hook] = await t.select().from(schema.repositoryWebhook);
    expect(openWebhookSecret(hook?.secretSealed as string, "hook_1", webhookKeyFrom(NEW_AUTH))).toBe(
      "hook-secret",
    );
    expect(openWebhookSecret(hook?.secretSealed as string, "hook_1", webhookKeyFrom(OLD_AUTH))).toBeNull();

    // Sequences continue after the restored rows, and the restore is in the audit log.
    await t.insert(schema.auditLog).values({ organizationId: ORG, action: "test.after" });
    const actions = (await t.select().from(schema.auditLog)).map((row) => row.action);
    expect(actions).toEqual(expect.arrayContaining(["setup.completed", "backup.restored", "test.after"]));
  }, 60_000);

  it("restores a backup of an older version and applies the newer migrations", async () => {
    const all = readMigrations();
    const older = createDb(
      (adminUrl as string).replace(/\/[^/]*$/, `/garnetops_backup_older_${process.pid}`),
      { max: 2 },
    );
    const admin = createDb(adminUrl as string, { max: 1 });
    const name = `garnetops_backup_older_${process.pid}`;
    await admin.pool.query(`drop database if exists ${name} with (force)`);
    await admin.pool.query(`create database ${name}`);
    const fresh = await createTestDatabase(adminUrl as string, "backup_fresh");
    try {
      const client = await older.pool.connect();
      try {
        await client.query("begin");
        await applyMigrations(client, all, 0, all.length - 1);
        await client.query("commit");
      } finally {
        client.release();
      }
      await older.pool.query("insert into organization (id, name) values ($1, $2)", [ORG, "Older Org"]);
      const plain = Readable.from(backupLines(older.pool, keys, "0.0.18", { rows: 0 })).pipe(createGzip());
      const chunks: Buffer[] = [];
      for await (const piece of plain) chunks.push(piece as Buffer);
      const e = new Encrypter();
      e.setScryptWorkFactor(10);
      e.setPassphrase(PASSPHRASE);
      const olderFile = await e.encrypt(new Uint8Array(Buffer.concat(chunks)));
      await restoreBackup(streamOf(olderFile), PASSPHRASE, { ...deps(), pool: fresh.pool });
      const [org] = await fresh.db.select().from(schema.organization);
      expect(org?.name).toBe("Older Org");
      const applied = await fresh.pool.query<{ hash: string }>(
        "select hash from drizzle.__drizzle_migrations order by created_at",
      );
      expect(applied.rows.map((row) => row.hash)).toEqual(all.map((m) => m.hash));
    } finally {
      await older.pool.end();
      await fresh.drop();
      await admin.pool.query(`drop database if exists ${name} with (force)`);
      await admin.pool.end();
    }
  }, 120_000);

  it("refuses to restore onto an installation that has accounts", async () => {
    await expect(restoreBackup(streamOf(file), PASSPHRASE, deps())).rejects.toMatchObject({
      code: "not-empty",
    });
  });
});
