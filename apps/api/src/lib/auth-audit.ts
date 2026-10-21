import { schema } from "@garnetops/db";
import { isAPIError } from "better-auth/api";
import { eq } from "drizzle-orm";
import { db } from "../db.ts";
import { audit } from "./audit.ts";
import { clientIp } from "./ip.ts";

/**
 * Audit log entries for sign-in events (AGENTS.md: audit log for every
 * security-relevant action, including login). Successful and failed attempts
 * are recorded; passwords, codes and secrets never are.
 */

/** The parts of better-auth's hook context we read. */
interface HookContext {
  path: string;
  body?: Record<string, unknown> | undefined;
  headers?: Headers | undefined;
  request?: Request | undefined;
  getSignedCookie(name: string, secret: string): Promise<string | null | false>;
  context: {
    secret: string;
    returned?: unknown;
    newSession?: { user: { id: string } } | null;
    session?: { user: { id: string } } | null;
    createAuthCookie(name: string): { name: string };
    internalAdapter: { findVerificationValue(identifier: string): Promise<{ value: string } | null> };
  };
}

/** better-auth endpoint -> audit action. */
export const AUTH_ACTIONS: Record<string, string> = {
  "/sign-in/email": "auth.sign_in",
  "/two-factor/verify-totp": "auth.second_factor",
  "/two-factor/verify-backup-code": "auth.backup_code",
  "/two-factor/enable": "auth.second_factor_enrolment",
  "/sign-out": "auth.sign_out",
  "/two-factor/disable": "auth.second_factor_disable_refused",
};

async function organizationOf(userId: string): Promise<string | null> {
  const [row] = await db
    .select({ organizationId: schema.membership.organizationId })
    .from(schema.membership)
    .where(eq(schema.membership.userId, userId))
    .limit(1);
  return row?.organizationId ?? null;
}

async function userIdByEmail(email: unknown): Promise<string | null> {
  if (typeof email !== "string" || email.length > 254) return null;
  const [row] = await db
    .select({ id: schema.user.id })
    .from(schema.user)
    .where(eq(schema.user.email, email.trim().toLowerCase()))
    .limit(1);
  return row?.id ?? null;
}

/** The user of a sign-in that still waits for its second factor (read from the signed two-factor cookie). */
async function pendingSecondFactorUser(ctx: HookContext): Promise<string | null> {
  const cookie = ctx.context.createAuthCookie("two_factor");
  const identifier = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (!identifier) return null;
  const verification = await ctx.context.internalAdapter.findVerificationValue(identifier);
  return verification?.value ?? null;
}

/**
 * "success" or "failure" of the step itself. For a password sign-in that needs a
 * second factor, the password step succeeded; the second factor is its own entry.
 */
function outcomeOf(returned: unknown): "success" | "failure" {
  return isAPIError(returned) ? "failure" : "success";
}

/** Writes one audit entry for an auth endpoint. Call after the endpoint ran (or was refused). */
export async function auditAuthEvent(ctx: HookContext, refused = false): Promise<void> {
  const action = AUTH_ACTIONS[ctx.path];
  if (!action) return;
  const outcome = refused ? "failure" : outcomeOf(ctx.context.returned);
  const userId =
    ctx.context.newSession?.user.id ??
    ctx.context.session?.user.id ??
    (ctx.path.startsWith("/two-factor/verify") ? await pendingSecondFactorUser(ctx) : null) ??
    (ctx.path === "/sign-in/email" ? await userIdByEmail(ctx.body?.email) : null);
  const headers = ctx.headers ?? ctx.request?.headers ?? new Headers();
  await audit(
    { userId, organizationId: userId ? await organizationOf(userId) : null, ip: clientIp(headers) },
    action,
    userId ? { type: "user", id: userId } : undefined,
    {
      outcome,
      // An unknown account is recorded by the address that was tried, never with the password.
      ...(userId === null && typeof ctx.body?.email === "string"
        ? { email: ctx.body.email.slice(0, 254) }
        : {}),
    },
  );
}
