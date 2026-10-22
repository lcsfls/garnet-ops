/**
 * How the API hands a question to the worker (ADR 0020): the password typed at sign-in is sealed
 * for the vault key, lives in one row for the length of the request and is deleted whatever
 * happens; the answer is read from the request row, which is deleted too. Skipped without the
 * development PostgreSQL.
 */
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const ORG = "org_askdir";
const PASSWORD = "test-only-directory-password";

const holder = vi.hoisted(() => ({ db: null as unknown, privateKey: "", sent: [] as unknown[][] }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_askdir");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: { send: async (...args: unknown[]) => void holder.sent.push(args) },
    QUEUES: { directory: "directory.request" },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair, loadVaultPublicKey } = await import("@garnetops/core/vault");
  const pair = generateVaultKeyPair();
  holder.privateKey = pair.privateKeyPem;
  return { env: {}, isProduction: false, vaultPublicKey: loadVaultPublicKey(pair.publicKeyPem) };
});

describe.skipIf(!adminUrl)("askDirectory", () => {
  let t: TestDatabase;
  let askDirectory: typeof import("./directory.ts").askDirectory;
  const requests = () => t.db.select().from(schema.directoryRequest);
  const secrets = () => t.db.select().from(schema.secret);

  beforeAll(async () => {
    ({ askDirectory } = await import("./directory.ts"));
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Org" });
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    holder.sent.length = 0;
    await t.pool.query("truncate directory_request, secret restart identity cascade");
  });

  /** The worker: takes the request, deletes the sealed password and answers. */
  async function worker(
    answer: Record<string, unknown>,
    onTaken?: (row: typeof schema.directoryRequest.$inferSelect) => void,
  ) {
    for (let i = 0; i < 200; i++) {
      const [row] = await requests();
      if (row) {
        onTaken?.(row);
        if (row.passwordSecretId)
          await t.db.delete(schema.secret).where(eq(schema.secret.id, row.passwordSecretId));
        await t.db
          .update(schema.directoryRequest)
          .set({ status: "done", result: answer })
          .where(eq(schema.directoryRequest.id, row.id));
        return;
      }
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  it("seals the password for the worker, queues the request and returns the answer", async () => {
    let sealedRow: typeof schema.secret.$inferSelect | undefined;
    let taken: typeof schema.directoryRequest.$inferSelect | undefined;
    const answering = worker({ outcome: "ok" }, async (row) => {
      taken = row;
      [sealedRow] = await secrets();
    });
    const answer = await askDirectory({
      organizationId: ORG,
      kind: "sign-in",
      params: { username: "jdoe" },
      password: PASSWORD,
      requestedBy: null,
    });
    await answering;
    expect(answer).toEqual({ outcome: "ok" });
    expect(taken).toMatchObject({ kind: "sign-in", params: { username: "jdoe" }, organizationId: ORG });
    expect(holder.sent).toHaveLength(1);
    expect(holder.sent[0]).toEqual([
      "directory.request",
      { requestId: taken?.id },
      { retryLimit: 0, expireInSeconds: 120 },
    ]);
    // Sealed for the vault key and bound to the organisation, the record and the purpose.
    expect(sealedRow).toMatchObject({ purpose: "ldap-user-password", organizationId: ORG });
    expect(JSON.stringify(sealedRow?.sealed)).not.toContain(PASSWORD);
    expect(JSON.stringify(taken)).not.toContain(PASSWORD);
    const key = loadVaultPrivateKey(holder.privateKey);
    const binding = {
      organizationId: ORG,
      recordId: sealedRow?.id as string,
      purpose: "ldap-user-password" as const,
    };
    expect(open(sealedRow?.sealed, binding, key).toString()).toBe(PASSWORD);
    expect(() => open(sealedRow?.sealed, { ...binding, purpose: "ldap-bind-password" }, key)).toThrow();
    // Nothing is left behind.
    expect(await requests()).toEqual([]);
    expect(await secrets()).toEqual([]);
  });

  it("makes no secret when there is no password", async () => {
    const answering = worker({ ok: true });
    await askDirectory({ organizationId: ORG, kind: "test", params: {} });
    await answering;
    expect(await secrets()).toEqual([]);
  });

  it("deletes the password and the request when the worker never answers, and says 503", async () => {
    await expect(
      askDirectory({
        organizationId: ORG,
        kind: "sign-in",
        params: { username: "jdoe" },
        password: PASSWORD,
        waitMs: 200,
      }),
    ).rejects.toMatchObject({ status: 503, code: "directory-unavailable" });
    expect(await requests()).toEqual([]);
    expect(await secrets()).toEqual([]);
  });

  it("deletes the password even when queueing fails", async () => {
    const db = await import("../db.ts");
    const original = db.boss.send;
    (db.boss as { send: unknown }).send = async () => {
      throw new Error("queue down");
    };
    try {
      await expect(
        askDirectory({
          organizationId: ORG,
          kind: "sign-in",
          params: { username: "jdoe" },
          password: PASSWORD,
          waitMs: 200,
        }),
      ).rejects.toThrow("queue down");
    } finally {
      (db.boss as { send: unknown }).send = original;
    }
    expect(await requests()).toEqual([]);
    expect(await secrets()).toEqual([]);
  });
});
