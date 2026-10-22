import { passkey } from "@better-auth/passkey";
import { hashPassword, verifyPassword } from "@garnetops/core/password";
import { schema } from "@garnetops/db";
import { APIError, betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";
import { eq } from "drizzle-orm";
import { db } from "./db.ts";
import { env, isProduction } from "./env.ts";
import { audit } from "./lib/audit.ts";
import { auditAuthEvent, organizationOf } from "./lib/auth-audit.ts";
import { isDirectoryEmail } from "./lib/directory-accounts.ts";
import { directoryAuth } from "./lib/directory-auth.ts";
import { clientIp } from "./lib/ip.ts";
import { cleanPasskeyName, PASSKEY_NAME_MAX, passkeyOptions } from "./lib/passkey-policy.ts";
import { STEP_UP_MAX_AGE_SECONDS } from "./lib/step-up.ts";

/**
 * Authentication (AGENTS.md rule 1):
 * - open email sign-up is disabled; the first admin is created by the setup endpoint,
 *   further users by invitation (ADR 0009) or an identity provider (later);
 * - passwords are hashed with Argon2id (@garnetops/core/password), not better-auth's scrypt default;
 * - TOTP is mandatory: a session without an enrolled second factor may only
 *   enrol one or sign out (enforced in lib/context.ts). Users cannot switch it
 *   off, and "trust this device" is refused, so every sign-in asks for it;
 * - passkeys (WebAuthn) are an additional second factor and a sign-in method of their own,
 *   with user verification required (lib/passkey-policy.ts, ADR 0017); relying party and
 *   origin come from PUBLIC_URL, never from a request header;
 * - changing a factor, a password or a session goes through the account API (routes/account.ts),
 *   which asks for a recent sign-in and writes the audit log; the matching better-auth
 *   endpoints are closed here so they cannot be used around it;
 * - every sign-in, second-factor check, enrolment and sign-out is audit-logged,
 *   failed attempts included (lib/auth-audit.ts);
 * - signing in with a directory (LDAP, Active Directory) is a plugin of its own (lib/directory-auth.ts, ADR 0020):
 *   same sessions, same mandatory second factor; directory accounts have no local password and cannot use the
 *   local sign-in;
 * - rate limits are stored in Postgres so restarts do not reset them.
 */

/**
 * better-auth endpoints the account API replaces. Closing them keeps every password, factor and
 * session change behind a recent sign-in and in the audit log. Some, like changing the password
 * with "sign out everywhere", would also hand out a fresh session without a second factor, which
 * would reset the step-up clock.
 */
const CLOSED_ENDPOINTS = new Set([
  "/change-password",
  "/set-password",
  "/change-email",
  "/delete-user",
  "/update-user",
  "/list-sessions",
  "/revoke-session",
  "/revoke-sessions",
  "/revoke-other-sessions",
  "/two-factor/get-totp-uri",
  "/two-factor/generate-backup-codes",
  "/passkey/list-user-passkeys",
  "/passkey/update-passkey",
  "/passkey/delete-passkey",
]);

/** Registering a passkey is a factor change: it needs a sign-in from the last ten minutes (ADR 0009). */
const STEP_UP_ENDPOINTS = new Set(["/passkey/generate-register-options", "/passkey/verify-registration"]);

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
  if (CLOSED_ENDPOINTS.has(ctx.path)) {
    const session = await getSessionFromCtx(ctx);
    await audit(
      {
        userId: session?.user.id ?? null,
        organizationId: session ? await organizationOf(session.user.id) : null,
        ip: clientIp(ctx.headers ?? ctx.request?.headers ?? new Headers()),
      },
      "auth.endpoint_refused",
      undefined,
      { outcome: "failure", path: ctx.path },
    );
    throw new APIError("FORBIDDEN", {
      message: "This is done on the account page",
      code: "USE_ACCOUNT_PAGE",
    });
  }
  if (ctx.path === "/sign-in/email" && typeof ctx.body?.email === "string" && ctx.body.email.length <= 254) {
    // An account that comes from the directory has no local password, and none may be used for it.
    if (await isDirectoryEmail(ctx.body.email)) {
      // Same work as for a wrong password, so the answer does not give the account type away.
      await hashPassword("x".repeat(16));
      await auditAuthEvent(ctx, true);
      throw new APIError("UNAUTHORIZED", {
        message: "Invalid email or password",
        code: "INVALID_EMAIL_OR_PASSWORD",
      });
    }
  }
  if (STEP_UP_ENDPOINTS.has(ctx.path)) {
    const session = await getSessionFromCtx(ctx);
    if (!session) throw new APIError("UNAUTHORIZED", { message: "Please sign in" });
    // Same clock as requireRecentSignIn: sessions only come from a password and second factor or a passkey.
    if (Date.now() - new Date(session.session.createdAt).getTime() > STEP_UP_MAX_AGE_SECONDS * 1000) {
      throw new APIError("FORBIDDEN", {
        message: "Sign in again to confirm it is you",
        code: "STEP_UP_REQUIRED",
      });
    }
    if (ctx.path === "/passkey/verify-registration" && ctx.body?.name !== undefined) {
      const name = cleanPasskeyName(ctx.body.name);
      if (!name || typeof ctx.body.name !== "string" || [...ctx.body.name.trim()].length > PASSKEY_NAME_MAX) {
        throw new APIError("BAD_REQUEST", { message: "The name is not valid", code: "INVALID_PASSKEY_NAME" });
      }
    }
  }
  // Signing out ends the session, so record it while the session still exists.
  if (ctx.path === "/sign-out") {
    const session = await getSessionFromCtx(ctx);
    if (session) await auditAuthEvent({ ...ctx, context: { ...ctx.context, session } });
  }
});

/** A fresh sign-in (step-up, second factor, passkey) replaces the session it was started from. */
const REPLACING_SIGN_INS = new Set([
  "/two-factor/verify-totp",
  "/two-factor/verify-backup-code",
  "/passkey/verify-authentication",
]);

const afterAuth = createAuthMiddleware(async (ctx) => {
  if (REPLACING_SIGN_INS.has(ctx.path) && ctx.context.newSession) {
    const previous = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
    if (previous && previous !== ctx.context.newSession.session.token) {
      await ctx.context.internalAdapter.deleteSession(previous);
    }
  }
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
      passkey: schema.passkey,
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
      "/passkey/generate-authenticate-options": { window: 60, max: 20 },
      "/passkey/verify-authentication": { window: 60, max: 10 },
      "/passkey/generate-register-options": { window: 60, max: 10 },
      "/passkey/verify-registration": { window: 60, max: 10 },
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
  plugins: [
    // `allowPasswordless`: an account without a local password (a directory account) enrols its authenticator app
    // without one; an account that has a password is still asked for it.
    twoFactor({ issuer: "GarnetOps", skipVerificationOnEnable: false, allowPasswordless: true }),
    directoryAuth(),
    passkey(
      passkeyOptions(env.PUBLIC_URL, async (credentialId) => {
        await db
          .update(schema.passkey)
          .set({ lastUsedAt: new Date() })
          .where(eq(schema.passkey.credentialID, credentialId));
      }),
    ),
  ],
});

export type Session = typeof auth.$Infer.Session;
