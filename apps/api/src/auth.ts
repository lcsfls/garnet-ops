import { hashPassword, verifyPassword } from "@garnetops/core/password";
import { schema } from "@garnetops/db";
import { APIError, betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";
import { db } from "./db.ts";
import { env, isProduction } from "./env.ts";
import { auditAuthEvent } from "./lib/auth-audit.ts";

/**
 * Authentication (AGENTS.md rule 1):
 * - open email sign-up is disabled; the first admin is created by the setup endpoint,
 *   further users by invitation (later) or an identity provider (later);
 * - passwords are hashed with Argon2id (@garnetops/core/password), not better-auth's scrypt default;
 * - TOTP is mandatory: a session without an enrolled second factor may only
 *   enrol one or sign out (enforced in lib/context.ts). Users cannot switch it
 *   off, and "trust this device" is refused, so every sign-in asks for it;
 * - every sign-in, second-factor check, enrolment and sign-out is audit-logged,
 *   failed attempts included (lib/auth-audit.ts);
 * - rate limits are stored in Postgres so restarts do not reset them.
 */
const beforeAuth = createAuthMiddleware(async (ctx) => {
  if (ctx.path === "/two-factor/disable") {
    // Before hooks run ahead of the session middleware, so load the session to know who tried.
    const session = await getSessionFromCtx(ctx);
    await auditAuthEvent({ ...ctx, context: { ...ctx.context, session } }, true);
    throw new APIError("FORBIDDEN", { message: "The second factor cannot be switched off" });
  }
  if (ctx.path.startsWith("/two-factor/verify") && ctx.body?.trustDevice) {
    throw new APIError("BAD_REQUEST", { message: "Trusted devices are not supported" });
  }
  // Signing out ends the session, so record it while the session still exists.
  if (ctx.path === "/sign-out") {
    const session = await getSessionFromCtx(ctx);
    if (session) await auditAuthEvent({ ...ctx, context: { ...ctx.context, session } });
  }
});

const afterAuth = createAuthMiddleware(async (ctx) => {
  if (ctx.path !== "/sign-out") await auditAuthEvent(ctx);
});

export const auth = betterAuth({
  appName: "GarnetOps",
  baseURL: env.PUBLIC_URL,
  basePath: "/api/auth",
  secret: env.BETTER_AUTH_SECRET,
  trustedOrigins: [env.PUBLIC_URL],
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.account,
      verification: schema.verification,
      twoFactor: schema.twoFactor,
      rateLimit: schema.rateLimit,
    },
  }),
  emailAndPassword: {
    enabled: true,
    disableSignUp: true,
    minPasswordLength: 12,
    maxPasswordLength: 256,
    password: { hash: hashPassword, verify: ({ hash, password }) => verifyPassword(hash, password) },
  },
  session: {
    expiresIn: 60 * 60 * 12,
    updateAge: 60 * 30,
    freshAge: 60 * 10,
  },
  rateLimit: {
    enabled: true,
    storage: "database",
    window: 60,
    max: 100,
    customRules: {
      "/sign-in/email": { window: 60, max: 5 },
      "/two-factor/verify-totp": { window: 60, max: 5 },
      "/two-factor/verify-backup-code": { window: 60, max: 5 },
    },
  },
  advanced: {
    useSecureCookies: isProduction,
    cookiePrefix: "garnetops",
    defaultCookieAttributes: { httpOnly: true, sameSite: "lax", secure: isProduction },
  },
  // No telemetry, ever, unless the operator opts in (AGENTS.md rule 1).
  telemetry: { enabled: false },
  hooks: { before: beforeAuth, after: afterAuth },
  plugins: [twoFactor({ issuer: "GarnetOps", skipVerificationOnEnable: false })],
});

export type Session = typeof auth.$Infer.Session;
