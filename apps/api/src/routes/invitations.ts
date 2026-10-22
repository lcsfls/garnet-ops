import { schema } from "@garnetops/db";
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { auth } from "../auth.ts";
import { db, pool } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { clientIp } from "../lib/ip.ts";
import { notifyUsers } from "../lib/notify-users.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { hashInvitationToken } from "./team.ts";

const inv = schema.invitation;
/** Requests per client address and minute for both endpoints; tokens have 256 random bits anyway. */
const LIMIT = 20;

const tokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, "Not an invitation link");
const acceptBody = z.object({
  token: tokenSchema,
  name: z.string().trim().min(1).max(100).optional(),
  password: z.string().min(12).max(256).optional(),
});

const gone = () =>
  new ProblemError(410, "invitation-invalid", "This invitation link is not valid: used, revoked or expired");

async function openInvitation(token: string) {
  const [row] = await db
    .select({
      id: inv.id,
      organizationId: inv.organizationId,
      email: inv.email,
      role: inv.role,
      organizationName: schema.organization.name,
      invitedBy: schema.user.name,
    })
    .from(inv)
    .innerJoin(schema.organization, eq(schema.organization.id, inv.organizationId))
    .leftJoin(schema.user, eq(schema.user.id, inv.invitedBy))
    .where(
      and(
        eq(inv.tokenHash, hashInvitationToken(token)),
        isNull(inv.acceptedAt),
        isNull(inv.revokedAt),
        gt(inv.expiresAt, new Date()),
      ),
    )
    .limit(1);
  if (!row) throw gone();
  return row;
}

async function existingAccount(email: string) {
  const [row] = await db
    .select({ id: schema.user.id })
    .from(schema.user)
    .where(eq(schema.user.email, email))
    .limit(1);
  return row ?? null;
}

/**
 * Accepting an invitation (ADR 0009), without a session. The token is the only proof;
 * both endpoints are rate-limited per client address and answer the same for unknown,
 * used, revoked and expired links.
 */
export const invitationRoutes = new Hono()
  .post("/lookup", async (c) => {
    await rateLimit(`invite:${clientIp(c.req.raw.headers) ?? "unknown"}`, LIMIT);
    const { token } = z.object({ token: tokenSchema }).parse(await c.req.json());
    const row = await openInvitation(token);
    return c.json({
      organizationName: row.organizationName,
      email: row.email,
      role: row.role,
      invitedBy: row.invitedBy,
      /** A person whose access was removed keeps their account and only gets the membership back. */
      hasAccount: Boolean(await existingAccount(row.email)),
    });
  })
  .post("/accept", async (c) => {
    const ip = clientIp(c.req.raw.headers);
    await rateLimit(`invite:${ip ?? "unknown"}`, LIMIT);
    const input = acceptBody.parse(await c.req.json());
    // One acceptance at a time per installation keeps "used once" exact without a race.
    const client = await pool.connect();
    try {
      await client.query("select pg_advisory_lock(hashtext('garnetops.invitation'))");
      const row = await openInvitation(input.token);
      const existing = await existingAccount(row.email);
      let userId: string;
      if (existing) {
        const [member] = await db
          .select({ organizationId: schema.membership.organizationId })
          .from(schema.membership)
          .where(eq(schema.membership.userId, existing.id))
          .limit(1);
        if (member)
          throw new ProblemError(409, "already-member", "This account already belongs to an organisation");
        userId = existing.id;
      } else {
        if (!input.name || !input.password) {
          throw new ProblemError(422, "validation", "Name and password are required", undefined, {
            errors: [
              ...(input.name ? [] : [{ path: "name", message: "Enter your name" }]),
              ...(input.password ? [] : [{ path: "password", message: "At least 12 characters" }]),
            ],
          });
        }
        const ctx = await auth.$context;
        const user = await ctx.internalAdapter.createUser(
          // The address is the one an owner or admin invited; the link proves it reached that person.
          { email: row.email, name: input.name, emailVerified: true },
          { method: "admin" },
        );
        userId = user.id;
        try {
          await ctx.internalAdapter.linkAccount({
            userId,
            providerId: "credential",
            accountId: userId,
            password: await ctx.password.hash(input.password),
          });
        } catch (error) {
          await db.delete(schema.user).where(eq(schema.user.id, userId));
          throw error;
        }
      }
      await db.transaction(async (tx) => {
        await tx
          .insert(schema.membership)
          .values({ organizationId: row.organizationId, userId, role: row.role });
        await tx
          .update(inv)
          .set({ acceptedAt: sql`now()`, acceptedUserId: userId })
          .where(eq(inv.id, row.id));
      });
      await audit(
        { organizationId: row.organizationId, userId, ip },
        "team.invitation_accepted",
        {
          type: "invitation",
          id: row.id,
        },
        { email: row.email, role: row.role, existingAccount: Boolean(existing) },
      );
      // Tells the owners and admins that someone joined (ADR 0019).
      const [joined] = await db
        .select({ name: schema.user.name })
        .from(schema.user)
        .where(eq(schema.user.id, userId))
        .limit(1);
      await notifyUsers({
        organizationId: row.organizationId,
        titleKey: "invitationAccepted",
        params: { person: joined?.name ?? "", role: row.role },
        link: "/team",
      });
      return c.json({ email: row.email, existingAccount: Boolean(existing) }, 201);
    } finally {
      await client.query("select pg_advisory_unlock(hashtext('garnetops.invitation'))").catch(() => {});
      client.release();
    }
  });
