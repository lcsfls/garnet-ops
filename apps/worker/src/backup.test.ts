/**
 * Building a backup (ADR 0046) in the worker against a throw-away PostgreSQL database on the development server, with a real
 * vault key: the sealed request is read once and deleted in every outcome, the stored file decrypts with the passphrase to a
 * complete backup that carries the vault key and leaves out sessions and the request itself, a run is built only once, and the
 * sweep removes the file of an expired backup. Skipped without the development PostgreSQL.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Decrypter } from "age-encryption";
import { asc, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-backup-test-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_backup_w";
const PASSPHRASE = "a passphrase of some length";
const AUTH = "s".repeat(40);

describe.skipIf(!adminUrl)("building a backup", () => {
  let t: TestDatabase;
  let mod: typeof import("./backup.ts");
  let publicKey: ReturnType<typeof loadVaultPublicKey>;
  let privateKeyPem: string;

  async function request(runId: string, body: unknown) {
    const secretId = `sec_${runId}`;
    await t.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "backup-request",
      sealed: seal(
        JSON.stringify(body),
        { organizationId: ORG, recordId: secretId, purpose: "backup-request" },
        publicKey,
      ),
      vaultKeyId: publicKey.id,
    });
    await t.db
      .insert(schema.backupRun)
      .values({ id: runId, organizationId: ORG, state: "pending", secretId });
    return secretId;
  }

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    privateKeyPem = pair.privateKeyPem;
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_backup");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
    });
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    await t.db
      .insert(schema.user)
      .values({ id: "usr_w", name: "Owner", email: "owner@example.com", emailVerified: true });
    await t.db.insert(schema.session).values({
      id: "ses_w",
      userId: "usr_w",
      token: "t".repeat(32),
      expiresAt: new Date(Date.now() + 3600_000),
    });
    mod = await import("./backup.ts");
  }, 60_000);

  afterAll(async () => {
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  it("builds an encrypted backup and deletes the sealed request", async () => {
    const secretId = await request("bkp_1", { passphrase: PASSPHRASE, authSecret: AUTH });
    await mod.runBackupBuild({ runId: "bkp_1", organizationId: ORG });

    const [run] = await t.db.select().from(schema.backupRun).where(eq(schema.backupRun.id, "bkp_1"));
    expect(run?.state).toBe("ready");
    expect(run?.secretId).toBeNull();
    expect(run?.expiresAt?.getTime()).toBeGreaterThan(Date.now());
    expect(await t.db.select().from(schema.secret).where(eq(schema.secret.id, secretId))).toHaveLength(0);

    const chunks = await t.db
      .select()
      .from(schema.backupChunk)
      .where(eq(schema.backupChunk.runId, "bkp_1"))
      .orderBy(asc(schema.backupChunk.seq));
    const file = Buffer.concat(chunks.map((chunk) => chunk.data));
    expect(file.length).toBe(run?.sizeBytes);
    const d = new Decrypter();
    d.addPassphrase(PASSPHRASE);
    const lines = gunzipSync(await d.decrypt(new Uint8Array(file)))
      .toString("utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(lines[0]).toMatchObject({ kind: "garnetops-backup", format: 1 });
    expect(lines[0].tables).toContain("organization");
    expect(lines[0].tables).not.toContain("session");
    expect(lines[1]).toEqual({ kind: "keys", vaultPrivateKey: privateKeyPem, authSecret: AUTH });
    expect(lines.at(-1)).toEqual({ kind: "end", rows: run?.rowCount });
    const text = JSON.stringify(lines);
    expect(text).not.toContain('"purpose":"backup-request"');
    expect(text).toContain("Example Org");
  }, 60_000);

  it("builds a run only once", async () => {
    const before = await t.db.select().from(schema.backupChunk).where(eq(schema.backupChunk.runId, "bkp_1"));
    await mod.runBackupBuild({ runId: "bkp_1", organizationId: ORG });
    const after = await t.db.select().from(schema.backupChunk).where(eq(schema.backupChunk.runId, "bkp_1"));
    expect(after).toHaveLength(before.length);
  });

  it("fails without a readable request and still deletes it", async () => {
    const secretId = await request("bkp_2", { nothing: true });
    await mod.runBackupBuild({ runId: "bkp_2", organizationId: ORG });
    const [run] = await t.db.select().from(schema.backupRun).where(eq(schema.backupRun.id, "bkp_2"));
    expect(run).toMatchObject({ state: "failed", error: "secret-missing", secretId: null });
    expect(await t.db.select().from(schema.secret).where(eq(schema.secret.id, secretId))).toHaveLength(0);
  });

  it("deletes the file of an expired backup", async () => {
    await mod.sweepBackups(new Date(Date.now() + 2 * 3600_000));
    const [run] = await t.db.select().from(schema.backupRun).where(eq(schema.backupRun.id, "bkp_1"));
    expect(run?.state).toBe("expired");
    expect(await t.db.select().from(schema.backupChunk)).toHaveLength(0);
  });
});
