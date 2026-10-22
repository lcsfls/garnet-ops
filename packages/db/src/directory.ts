import type { Role } from "@garnetops/core";
import type { DirectoryRole } from "@garnetops/core/directory";
import { and, eq } from "drizzle-orm";
import type { Database } from "./index.ts";
import { membership, session } from "./schema.ts";

/** A database or a transaction of it. */
export type Executor = Database | Parameters<Parameters<Database["transaction"]>[0]>[0];

export interface RoleChange {
  /** `unchanged`; `changed` (another role); `removed` (no allowed group any more: membership and sessions gone); `restored` (back in an allowed group); `owner` (never touched). */
  kind: "unchanged" | "changed" | "removed" | "restored" | "owner";
  before: Role | null;
  after: Role | null;
}

/**
 * Makes an account's membership say what the directory says (ADR 0020): its role comes from its
 * groups, and a person in none of the allowed groups has no membership and no session. Used by
 * the sign-in (API) and by the periodic check (worker), so both apply exactly the same rule.
 *
 * An owner is never touched: owners are local accounts, and no group can demote one or end its
 * sessions. (The API refuses to link an owner, so this is a second wall.)
 * The caller writes the audit entry and the notification; this function only changes rows.
 */
export async function applyDirectoryRole(
  db: Executor,
  input: { organizationId: string; userId: string; role: DirectoryRole | null },
): Promise<RoleChange> {
  const { organizationId, userId, role } = input;
  // A second wall behind the group mapping: nothing but these roles is ever written.
  if (role !== null && !(["admin", "member", "viewer"] as const).includes(role)) {
    throw new Error("A directory cannot give this role");
  }
  const [current] = await db
    .select({ role: membership.role })
    .from(membership)
    .where(and(eq(membership.organizationId, organizationId), eq(membership.userId, userId)))
    .for("update")
    .limit(1);
  if (current?.role === "owner") return { kind: "owner", before: "owner", after: "owner" };
  if (role === null) {
    if (!current) return { kind: "unchanged", before: null, after: null };
    await db
      .delete(membership)
      .where(and(eq(membership.organizationId, organizationId), eq(membership.userId, userId)));
    await db.delete(session).where(eq(session.userId, userId));
    return { kind: "removed", before: current.role, after: null };
  }
  if (!current) {
    await db.insert(membership).values({ organizationId, userId, role });
    return { kind: "restored", before: null, after: role };
  }
  if (current.role === role) return { kind: "unchanged", before: role, after: role };
  await db
    .update(membership)
    .set({ role })
    .where(and(eq(membership.organizationId, organizationId), eq(membership.userId, userId)));
  return { kind: "changed", before: current.role, after: role };
}
