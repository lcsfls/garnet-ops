/**
 * What a directory may do to a membership (ADR 0020), against a throw-away database on the
 * development PostgreSQL: the role follows the groups, no allowed group means no membership and
 * no session, and an owner is never touched. Skipped without the development PostgreSQL.
 */
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyDirectoryRole } from "./directory.ts";
import { schema } from "./index.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();
const ORG = "org_dir";

describe.skipIf(!adminUrl)("applyDirectoryRole", () => {
  let t: TestDatabase;
  const role = async (userId: string) =>
    (await t.db.select().from(schema.membership).where(eq(schema.membership.userId, userId)))[0]?.role ??
    null;
  const sessions = async (userId: string) =>
    (await t.db.select().from(schema.session).where(eq(schema.session.userId, userId))).length;

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "db_directory");
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    for (const id of ["u_a", "u_b", "u_owner"]) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test` });
    }
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    await t.pool.query("truncate membership, session restart identity cascade");
    await t.db.insert(schema.membership).values([
      { organizationId: ORG, userId: "u_a", role: "member" },
      { organizationId: ORG, userId: "u_owner", role: "owner" },
    ]);
    for (const userId of ["u_a", "u_owner"]) {
      await t.db.insert(schema.session).values({
        id: `s_${userId}`,
        token: `t_${userId}`,
        userId,
        expiresAt: new Date(Date.now() + 3600_000),
      });
    }
  });

  const apply = (userId: string, r: "admin" | "member" | "viewer" | null) =>
    applyDirectoryRole(t.db, { organizationId: ORG, userId, role: r });

  it("changes the role to what the groups say", async () => {
    expect(await apply("u_a", "admin")).toEqual({ kind: "changed", before: "member", after: "admin" });
    expect(await role("u_a")).toBe("admin");
    expect(await apply("u_a", "viewer")).toEqual({ kind: "changed", before: "admin", after: "viewer" });
    // A demotion leaves the session: the role is read on every request.
    expect(await sessions("u_a")).toBe(1);
  });

  it("leaves a matching role alone", async () => {
    expect(await apply("u_a", "member")).toEqual({ kind: "unchanged", before: "member", after: "member" });
  });

  it("removes the membership and every session of someone in no allowed group", async () => {
    expect(await apply("u_a", null)).toEqual({ kind: "removed", before: "member", after: null });
    expect(await role("u_a")).toBeNull();
    expect(await sessions("u_a")).toBe(0);
    // Nothing more to do the second time.
    expect(await apply("u_a", null)).toEqual({ kind: "unchanged", before: null, after: null });
  });

  it("restores the membership when the person is back in a group", async () => {
    await apply("u_a", null);
    expect(await apply("u_a", "viewer")).toEqual({ kind: "restored", before: null, after: "viewer" });
    expect(await role("u_a")).toBe("viewer");
  });

  it("creates a membership for a new account", async () => {
    expect(await apply("u_b", "member")).toEqual({ kind: "restored", before: null, after: "member" });
  });

  it("never touches an owner, whatever the groups say", async () => {
    expect(await apply("u_owner", null)).toEqual({ kind: "owner", before: "owner", after: "owner" });
    expect(await apply("u_owner", "viewer")).toEqual({ kind: "owner", before: "owner", after: "owner" });
    expect(await role("u_owner")).toBe("owner");
    expect(await sessions("u_owner")).toBe(1);
  });

  it("refuses to write a role a directory may not give", async () => {
    await expect(apply("u_a", "owner" as never)).rejects.toThrow("cannot give");
    expect(await role("u_a")).toBe("member");
  });

  it("works inside a transaction that is rolled back", async () => {
    await expect(
      t.db.transaction(async (tx) => {
        await applyDirectoryRole(tx, { organizationId: ORG, userId: "u_a", role: null });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(await role("u_a")).toBe("member");
    expect(await sessions("u_a")).toBe(1);
  });
});
