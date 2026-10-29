import { createHash, randomBytes } from "node:crypto";
import { newId, ROLES, type Role } from "@garnetops/core";
import { canAssignRole, canManageMember } from "@garnetops/core/team";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, gt, inArray, isNull, max } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, requireRole } from "../lib/context.ts";
import { isDirectoryEmail } from "../lib/directory-accounts.ts";
import { notifyUsers } from "../lib/notify-users.ts";
import { forbidden, notFound, ProblemError } from "../lib/problem.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

/** How long an invitation link works (ADR 0009). */
export const INVITATION_DAYS = 7;

const m = schema.membership;
const inv = schema.invitation;

export function hashInvitationToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

const inviteBody = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  role: z.enum(ROLES),
});
const roleBody = z.object({ role: z.enum(ROLES) });

async function memberOf(organizationId: string, userId: string) {
  const [row] = await db
    .select({ role: m.role, email: schema.user.email, name: schema.user.name })
    .from(m)
    .innerJoin(schema.user, eq(schema.user.id, m.userId))
    .where(and(eq(m.organizationId, organizationId), eq(m.userId, userId)))
    .limit(1);
  if (!row) throw notFound("Member");
  return row;
}

async function ownerCount(organizationId: string): Promise<number> {
  const [row] = await db
    .select({ n: count() })
    .from(m)
    .where(and(eq(m.organizationId, organizationId), eq(m.role, "owner")));
  return row?.n ?? 0;
}

/** The checks every change to someone else's membership goes through (ADR 0009). */
async function guardChange(actor: Actor, userId: string, nextRole: Role | null) {
  requireRole(actor, "admin");
  if (userId === actor.userId) throw forbidden("You cannot change your own membership");
  const target = await memberOf(actor.organizationId, userId);
  // Access of a directory account is the directory's decision: a role set or a removal here would be undone at the next sign-in.
  if (await isDirectoryEmail(target.email)) {
    throw new ProblemError(
      409,
      "managed-by-directory",
      "This account's role comes from its directory groups",
    );
  }
  if (!canManageMember(actor.role, target.role)) throw forbidden(`Only owners can change a ${target.role}`);
  if (nextRole && !canAssignRole(actor.role, nextRole)) throw forbidden(`Only owners can grant ${nextRole}`);
  if (target.role === "owner" && nextRole !== "owner" && (await ownerCount(actor.organizationId)) <= 1) {
    throw new ProblemError(409, "last-owner", "The last owner cannot be demoted or removed");
  }
  requireRecentSignIn(actor);
  return target;
}

/** Team management for owners and admins (ADR 0009). */
export const teamRoutes = new Hono<AppEnv>()
  .use("*", async (c, next) => {
    requireRole(c.get("actor"), "admin");
    await next();
  })
  .get("/members", async (c) => {
    const actor = c.get("actor");
    const lastSession = db
      .select({ userId: schema.session.userId, at: max(schema.session.createdAt).as("at") })
      .from(schema.session)
      .groupBy(schema.session.userId)
      .as("last_session");
    const rows = await db
      .select({
        userId: m.userId,
        role: m.role,
        joinedAt: m.createdAt,
        name: schema.user.name,
        email: schema.user.email,
        twoFactorEnabled: schema.user.twoFactorEnabled,
        lastSignInAt: lastSession.at,
        directoryIdentityId: schema.directoryIdentity.id,
      })
      .from(m)
      .innerJoin(schema.user, eq(schema.user.id, m.userId))
      .leftJoin(lastSession, eq(lastSession.userId, m.userId))
      .leftJoin(schema.directoryIdentity, eq(schema.directoryIdentity.userId, m.userId))
      .where(eq(m.organizationId, actor.organizationId))
      .orderBy(schema.user.name);
    return c.json(
      rows.map(({ directoryIdentityId, ...r }) => ({
        ...r,
        twoFactorEnabled: Boolean(r.twoFactorEnabled),
        /** Where the account comes from: `directory` accounts sign in with the directory and their role follows their groups (ADR 0020). */
        source: directoryIdentityId ? ("directory" as const) : ("local" as const),
      })),
    );
  })
  .patch("/members/:userId", async (c) => {
    const actor = c.get("actor");
    const { role } = roleBody.parse(await c.req.json());
    const userId = c.req.param("userId");
    const target = await guardChange(actor, userId, role);
    if (target.role === role) return c.body(null, 204);
    await db
      .update(m)
      .set({ role })
      .where(and(eq(m.organizationId, actor.organizationId), eq(m.userId, userId)));
    await audit(
      actor,
      "team.role_changed",
      { type: "user", id: userId },
      {
        email: target.email,
        before: target.role,
        after: role,
      },
    );
    // Tells the person whose access changed (ADR 0019).
    await notifyUsers({
      organizationId: actor.organizationId,
      titleKey: "roleChanged",
      params: { role },
      link: "/account",
      context: { targetUserId: userId },
    });
    return c.body(null, 204);
  })
  /** Ends access at once: the membership and every session go; the account stays for the audit trail. */
  .delete("/members/:userId", async (c) => {
    const actor = c.get("actor");
    const userId = c.req.param("userId");
    const target = await guardChange(actor, userId, null);
    const removed = await db.transaction(async (tx) => {
      await tx.delete(m).where(and(eq(m.organizationId, actor.organizationId), eq(m.userId, userId)));
      await tx.delete(schema.session).where(eq(schema.session.userId, userId));
      return removePersonalData(tx, actor.organizationId, userId);
    });
    await audit(
      actor,
      "team.member_removed",
      { type: "user", id: userId },
      { email: target.email, role: target.role, ...removed },
    );
    return c.body(null, 204);
  })
  .get("/invitations", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({
        id: inv.id,
        email: inv.email,
        role: inv.role,
        createdAt: inv.createdAt,
        expiresAt: inv.expiresAt,
        invitedBy: schema.user.name,
      })
      .from(inv)
      .leftJoin(schema.user, eq(schema.user.id, inv.invitedBy))
      .where(
        and(
          eq(inv.organizationId, actor.organizationId),
          isNull(inv.acceptedAt),
          isNull(inv.revokedAt),
          gt(inv.expiresAt, new Date()),
        ),
      )
      .orderBy(desc(inv.createdAt));
    return c.json(rows);
  })
  /** The link is in this answer once; GarnetOps keeps only the token's hash. */
  .post("/invitations", async (c) => {
    const actor = c.get("actor");
    const input = inviteBody.parse(await c.req.json());
    if (!canAssignRole(actor.role, input.role)) throw forbidden(`Only owners can invite a ${input.role}`);
    requireRecentSignIn(actor);
    const [member] = await db
      .select({ userId: m.userId })
      .from(m)
      .innerJoin(schema.user, eq(schema.user.id, m.userId))
      .where(and(eq(m.organizationId, actor.organizationId), eq(schema.user.email, input.email)))
      .limit(1);
    if (member) throw new ProblemError(409, "already-member", "This address already belongs to a member");
    // A person who signs in with the directory gets their access from its groups, not from an invitation.
    if (await isDirectoryEmail(input.email)) {
      throw new ProblemError(409, "directory-account", "This person signs in with the directory");
    }

    const token = randomBytes(32).toString("base64url");
    const id = newId("inv");
    const expiresAt = new Date(Date.now() + INVITATION_DAYS * 24 * 3600 * 1000);
    await db.transaction(async (tx) => {
      // A new invitation for the same address replaces the open one.
      await tx
        .update(inv)
        .set({ revokedAt: new Date() })
        .where(
          and(
            eq(inv.organizationId, actor.organizationId),
            eq(inv.email, input.email),
            isNull(inv.acceptedAt),
            isNull(inv.revokedAt),
          ),
        );
      await tx.insert(inv).values({
        id,
        organizationId: actor.organizationId,
        email: input.email,
        role: input.role,
        tokenHash: hashInvitationToken(token),
        invitedBy: actor.userId,
        expiresAt,
      });
    });
    await audit(
      actor,
      "team.invitation_created",
      { type: "invitation", id },
      { email: input.email, role: input.role },
    );
    // The token travels in the fragment, so it never reaches a server or proxy log.
    return c.json({ id, link: `${new URL(env.PUBLIC_URL).origin}/invite#${token}`, expiresAt }, 201);
  })
  .delete("/invitations/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .update(inv)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(inv.id, c.req.param("id")),
          eq(inv.organizationId, actor.organizationId),
          isNull(inv.acceptedAt),
          isNull(inv.revokedAt),
        ),
      )
      .returning({ email: inv.email, role: inv.role });
    if (!row) throw notFound("Invitation");
    await audit(actor, "team.invitation_revoked", { type: "invitation", id: c.req.param("id") }, row);
    return c.body(null, 204);
  });

/**
 * What belonged to a person alone goes with their membership (ADR 0030): their forge connections with the sealed
 * tokens, and their private repositories with everything found in them. Repositories they shared stay; a shared one
 * that used their connection fails its next scan with "connection removed" until an admin replaces the credential.
 */
async function removePersonalData(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  organizationId: string,
  userId: string,
) {
  const repos = await tx
    .select({ id: schema.repository.id, secretId: schema.repository.secretId })
    .from(schema.repository)
    .where(
      and(
        eq(schema.repository.organizationId, organizationId),
        eq(schema.repository.ownerUserId, userId),
        eq(schema.repository.visibility, "private"),
      ),
    );
  const repoIds = repos.map((r) => r.id);
  const writeTokens = repoIds.length
    ? await tx
        .select({ secretId: schema.repositoryWriteAccess.secretId })
        .from(schema.repositoryWriteAccess)
        .where(inArray(schema.repositoryWriteAccess.repositoryId, repoIds))
    : [];
  const connections = await tx
    .select({ id: schema.forgeConnection.id, secretId: schema.forgeConnection.secretId })
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.organizationId, organizationId),
        eq(schema.forgeConnection.userId, userId),
      ),
    );
  if (repoIds.length) await tx.delete(schema.repository).where(inArray(schema.repository.id, repoIds));
  if (connections.length) {
    await tx.delete(schema.forgeConnection).where(
      inArray(
        schema.forgeConnection.id,
        connections.map((c) => c.id),
      ),
    );
  }
  const secrets = [
    ...repos.map((r) => r.secretId),
    ...writeTokens.map((w) => w.secretId),
    ...connections.map((c) => c.secretId),
  ].filter((id): id is string => Boolean(id));
  if (secrets.length) await tx.delete(schema.secret).where(inArray(schema.secret.id, secrets));
  return { connectionsRemoved: connections.length, privateRepositoriesRemoved: repoIds.length };
}
