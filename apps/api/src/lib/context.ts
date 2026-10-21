import type { Role } from "@garnetops/core";
import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { createMiddleware } from "hono/factory";
import { auth } from "../auth.ts";
import { db } from "../db.ts";
import { clientIp } from "./ip.ts";
import { forbidden, ProblemError } from "./problem.ts";

export interface Actor {
  userId: string;
  email: string;
  name: string;
  organizationId: string;
  role: Role;
  ip: string | null;
  /**
   * When this session was created. Every session starts with password and TOTP (the
   * second factor is mandatory and "trust this device" is refused), so this is the time
   * of the last strong sign-in; sensitive actions ask for a recent one (step-up).
   */
  strongAuthAt: Date;
}

export type AppEnv = { Variables: { actor: Actor } };

const ROLE_RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

/**
 * Requires a signed-in user with an enrolled second factor and an organisation membership.
 * Users without a second factor get 403 `mfa-enrollment-required` on every API route;
 * the web app then shows the enrolment screen (better-auth routes stay reachable).
 */
export const requireActor = createMiddleware<AppEnv>(async (c, next) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) throw new ProblemError(401, "unauthenticated", "Please sign in");
  if (!session.user.twoFactorEnabled) {
    throw new ProblemError(403, "mfa-enrollment-required", "Set up two-factor authentication to continue");
  }
  const [member] = await db
    .select({ organizationId: schema.membership.organizationId, role: schema.membership.role })
    .from(schema.membership)
    .where(eq(schema.membership.userId, session.user.id))
    .limit(1);
  if (!member) throw forbidden("Your account is not a member of any organisation");
  c.set("actor", {
    userId: session.user.id,
    email: session.user.email,
    name: session.user.name,
    organizationId: member.organizationId,
    role: member.role,
    ip: clientIp(c.req.raw.headers),
    strongAuthAt: new Date(session.session.createdAt),
  });
  await next();
});

/** Owners and admins manage the installation (updates); everyone else may only read. */
export const isAdmin = (actor: Actor) => actor.role === "owner" || actor.role === "admin";

export function requireRole(actor: Actor, minimum: Role): void {
  if (ROLE_RANK[actor.role] < ROLE_RANK[minimum]) throw forbidden(`This needs the ${minimum} role or higher`);
}
