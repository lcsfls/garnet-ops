import { newId } from "@garnetops/core";
import type { DirectoryUser } from "@garnetops/core/directory";
import { applyDirectoryRole, type RoleChange, schema } from "@garnetops/db";
import { and, eq, ne, sql } from "drizzle-orm";
import { db } from "../db.ts";

/**
 * Turning what the directory said about a person into an account (ADR 0020).
 *
 * The rules, in the order they matter:
 * - an account is linked to a person by the directory's immutable unique id, never by mail
 *   address, so changing a mail attribute cannot take over someone else's account;
 * - a person who has no account yet gets one only if they are in an allowed group and the
 *   directory gave a usable mail address that no other account has: an existing account with
 *   the same address is never linked automatically (an administrator links it explicitly);
 * - the role is whatever the groups say, every time; a person in no allowed group has no
 *   membership and no session;
 * - nothing here creates a password. A directory account signs in with the directory only.
 */

export type Provisioned =
  | {
      kind: "ok";
      userId: string;
      created: boolean;
      change: RoleChange;
      email: string;
      /** The address changed in the directory and the account follows (never onto an address another account has). */
      emailChange: { from: string; to: string } | null;
      /** The directory gave an address another account already has: the account keeps its own. */
      emailConflict: boolean;
    }
  | {
      kind: "refused";
      reason: "not-allowed" | "no-email" | "email-collision";
      /** The account of this person, if there is one (its access was ended if they are in no allowed group). */
      userId: string | null;
      change: RoleChange | null;
      /** For a collision: the account that already has the address. */
      collidesWith: string | null;
      email: string | null;
    };

const MAX_NAME = 100;
const cleanName = (name: string | null, email: string | null) =>
  (name ?? email?.split("@")[0] ?? "").slice(0, MAX_NAME).trim() || "Directory user";

export async function provisionDirectoryUser(input: {
  organizationId: string;
  person: DirectoryUser;
  loginName: string;
  emailVerified: boolean;
}): Promise<Provisioned> {
  const { organizationId, person, loginName } = input;
  return db.transaction(async (tx) => {
    // One sign-in at a time per person: two first sign-ins must not both create an account.
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`garnetops.directory.${organizationId}.${person.uniqueId}`}))`,
    );
    const [identity] = await tx
      .select()
      .from(schema.directoryIdentity)
      .where(
        and(
          eq(schema.directoryIdentity.organizationId, organizationId),
          eq(schema.directoryIdentity.uniqueId, person.uniqueId),
        ),
      )
      .limit(1);

    if (identity) {
      const change = await applyDirectoryRole(tx, {
        organizationId,
        userId: identity.userId,
        role: person.role,
      });
      if (person.role === null) {
        return {
          kind: "refused",
          reason: "not-allowed",
          userId: identity.userId,
          change,
          collidesWith: null,
          email: person.email,
        };
      }
      const [user] = await tx.select().from(schema.user).where(eq(schema.user.id, identity.userId)).limit(1);
      if (!user) throw new Error("directory identity without an account");
      let emailChange: { from: string; to: string } | null = null;
      let emailConflict = false;
      const patch: Partial<typeof schema.user.$inferInsert> = {};
      if (person.email && person.email !== user.email) {
        const [taken] = await tx
          .select({ id: schema.user.id })
          .from(schema.user)
          .where(and(eq(schema.user.email, person.email), ne(schema.user.id, user.id)))
          .limit(1);
        if (taken) emailConflict = true;
        else {
          patch.email = person.email;
          patch.emailVerified = input.emailVerified;
          emailChange = { from: user.email, to: person.email };
        }
      }
      const name = cleanName(person.name, person.email ?? user.email);
      if (name !== user.name && person.name) patch.name = name;
      if (Object.keys(patch).length > 0) {
        await tx
          .update(schema.user)
          .set({ ...patch, updatedAt: new Date() })
          .where(eq(schema.user.id, user.id));
      }
      await tx
        .update(schema.directoryIdentity)
        .set({ dn: person.dn, loginName, lastSignInAt: new Date() })
        .where(eq(schema.directoryIdentity.id, identity.id));
      return {
        kind: "ok",
        userId: user.id,
        created: false,
        change,
        email: patch.email ?? user.email,
        emailChange,
        emailConflict,
      };
    }

    // A person we have not seen: only an allowed group lets them in, and only with a usable address.
    if (person.role === null) {
      return {
        kind: "refused",
        reason: "not-allowed",
        userId: null,
        change: null,
        collidesWith: null,
        email: person.email,
      };
    }
    if (!person.email) {
      return {
        kind: "refused",
        reason: "no-email",
        userId: null,
        change: null,
        collidesWith: null,
        email: null,
      };
    }
    const [collision] = await tx
      .select({ id: schema.user.id })
      .from(schema.user)
      .where(eq(schema.user.email, person.email))
      .limit(1);
    if (collision) {
      return {
        kind: "refused",
        reason: "email-collision",
        userId: null,
        change: null,
        collidesWith: collision.id,
        email: person.email,
      };
    }
    const userId = newId("usr");
    await tx.insert(schema.user).values({
      id: userId,
      name: cleanName(person.name, person.email),
      email: person.email,
      emailVerified: input.emailVerified,
      twoFactorEnabled: false,
    });
    await tx.insert(schema.directoryIdentity).values({
      id: newId("dri"),
      organizationId,
      userId,
      uniqueId: person.uniqueId,
      dn: person.dn,
      loginName,
      lastSignInAt: new Date(),
    });
    const change = await applyDirectoryRole(tx, { organizationId, userId, role: person.role });
    return {
      kind: "ok",
      userId,
      created: true,
      change,
      email: person.email,
      emailChange: null,
      emailConflict: false,
    };
  });
}

/** Whether the account comes from the directory (it has no local password and its role follows its groups). */
export async function isDirectoryAccount(userId: string): Promise<boolean> {
  const [row] = await db
    .select({ id: schema.directoryIdentity.id })
    .from(schema.directoryIdentity)
    .where(eq(schema.directoryIdentity.userId, userId))
    .limit(1);
  return Boolean(row);
}

export async function isDirectoryEmail(email: string): Promise<boolean> {
  const [row] = await db
    .select({ id: schema.directoryIdentity.id })
    .from(schema.directoryIdentity)
    .innerJoin(schema.user, eq(schema.user.id, schema.directoryIdentity.userId))
    .where(eq(schema.user.email, email.trim().toLowerCase()))
    .limit(1);
  return Boolean(row);
}
