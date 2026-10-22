import { createHash } from "node:crypto";
import {
  checkPassword,
  checkUsername,
  type DirectoryUser,
  type SignInResult,
  usernameKey,
} from "@garnetops/core/directory";
import { schema } from "@garnetops/db";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "./audit.ts";
import { activeDirectory, askDirectory } from "./directory.ts";
import { type Provisioned, provisionDirectoryUser } from "./directory-accounts.ts";
import { clientIp } from "./ip.ts";
import { notifyUsers } from "./notify-users.ts";
import { ProblemError } from "./problem.ts";
import { clearFailures, failureCount, recordFailure } from "./rate-limit.ts";

/**
 * Directory sign-in (ADR 0020), as a better-auth plugin so it joins the same session, cookie,
 * second-factor and rate-limit machinery as the local sign-in.
 *
 * The endpoint is `POST /api/auth/sign-in/username`. That path is the one better-auth's
 * two-factor plugin watches after a password sign-in: when the account has a second factor, the
 * session this endpoint creates is swapped for the pending second-factor step by the same code
 * that does it for `/sign-in/email`, so a directory sign-in can never be a way around it. (The
 * `username` plugin of better-auth, which uses the same path, is not installed.)
 *
 * The person's password goes to the directory through the worker and nowhere else. It is never
 * stored, never logged and never part of an audit entry. Every refusal looks the same to the
 * person; the audit log says why.
 */

/** Failed attempts allowed per user name in {@link WINDOW_MS}: below the usual lock-out threshold of a directory (5 to 10). */
export const USER_FAILURES = 3;
/** Failed attempts allowed per client address in {@link WINDOW_MS}, over all user names (password spraying). */
export const IP_FAILURES = 20;
export const WINDOW_MS = 15 * 60_000;

/** A refused sign-in takes at least this long, so unknown names, wrong passwords and refused groups cannot be told apart by time. */
let failureFloorMs = 1000;
export function setFailureFloorForTests(ms: number): void {
  failureFloorMs = ms;
}
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function floor(started: number): Promise<void> {
  const wait = failureFloorMs - (Date.now() - started);
  if (wait > 0) await sleep(wait + Math.floor(Math.random() * 120));
}

const refusal = () =>
  new APIError("UNAUTHORIZED", {
    message: "Invalid username or password",
    code: "INVALID_USERNAME_OR_PASSWORD",
  });

const body = z.object({
  username: z.string().max(512),
  password: z.string().max(2048),
});

const keyOf = (organizationId: string, username: string) =>
  createHash("sha256")
    .update(`${organizationId}\n${usernameKey(username)}`)
    .digest("hex")
    .slice(0, 32);

/** What the audit log shows of a typed name: a short reference, never the text (people paste passwords into name fields). */
const referenceOf = (organizationId: string, username: string) =>
  keyOf(organizationId, username).slice(0, 12);

interface Who {
  userId: string | null;
  organizationId: string | null;
  ip: string | null;
}

async function logAudits(who: Who, provisioned: Extract<Provisioned, { kind: "ok" }>, person: DirectoryUser) {
  const target = { type: "user", id: provisioned.userId };
  const actor = { ...who, userId: provisioned.userId };
  const { change } = provisioned;
  if (provisioned.created) {
    await audit(actor, "directory.account_created", target, {
      email: provisioned.email,
      role: change.after,
      uniqueId: person.uniqueId,
      groups: person.groups,
    });
  } else if (change.kind === "restored") {
    await audit(actor, "directory.access_restored", target, {
      email: provisioned.email,
      role: change.after,
      via: "sign-in",
    });
  } else if (change.kind === "changed") {
    await audit(actor, "directory.role_changed", target, {
      email: provisioned.email,
      before: change.before,
      after: change.after,
      via: "sign-in",
    });
  }
  if (provisioned.emailChange) {
    await audit(actor, "directory.email_changed", target, provisioned.emailChange);
  }
  if (provisioned.emailConflict) {
    await audit(actor, "directory.email_conflict", target, { directoryEmail: person.email });
  }
  if (!provisioned.created && change.kind === "changed") {
    await notifyUsers({
      organizationId: who.organizationId as string,
      titleKey: "roleChanged",
      params: { role: change.after ?? "" },
      link: "/account",
      context: { targetUserId: provisioned.userId },
    });
  }
}

export const directoryAuth = (): BetterAuthPlugin => ({
  id: "garnetops-directory",
  rateLimit: [{ pathMatcher: (path: string) => path === "/sign-in/username", window: 60, max: 5 }],
  endpoints: {
    directorySignIn: createAuthEndpoint("/sign-in/username", { method: "POST", body }, async (ctx) => {
      const started = Date.now();
      const ip = clientIp(ctx.headers ?? ctx.request?.headers ?? new Headers());
      const directory = await activeDirectory();
      const who: Who = { userId: null, organizationId: directory?.organizationId ?? null, ip };
      const refuse = async (
        reason: string,
        data: Record<string, unknown> = {},
        userId: string | null = null,
      ) => {
        await audit(
          { ...who, userId },
          "auth.directory_sign_in",
          userId ? { type: "user", id: userId } : undefined,
          {
            outcome: "failure",
            reason,
            ...data,
          },
        );
        await floor(started);
        throw refusal();
      };

      // Not switched on: the same answer as a wrong password, so the endpoint does not announce itself.
      if (!directory) return refuse("not-enabled");
      const organizationId = directory.organizationId;
      const username = checkUsername(ctx.body.username);
      const password = checkPassword(ctx.body.password);
      const ipKey = `ldap:ip:${ip ?? "unknown"}`;
      const userKey = username ? `ldap:user:${keyOf(organizationId, username)}` : null;
      if (!username || !password || !userKey) {
        await recordFailure(ipKey, WINDOW_MS);
        return refuse("invalid-input");
      }
      // Too many failures: no more attempts reach the directory, so a guessing run cannot lock a real account there.
      if (
        (await failureCount(userKey, WINDOW_MS)) >= USER_FAILURES ||
        (await failureCount(ipKey, WINDOW_MS)) >= IP_FAILURES
      ) {
        await audit(who, "auth.directory_sign_in", undefined, {
          outcome: "failure",
          reason: "rate-limited",
          usernameRef: referenceOf(organizationId, username),
        });
        await floor(started);
        throw new APIError("TOO_MANY_REQUESTS", { message: "Too many attempts", code: "TOO_MANY_ATTEMPTS" });
      }
      const fail = async (
        reason: string,
        data: Record<string, unknown> = {},
        userId: string | null = null,
      ) => {
        await recordFailure(userKey, WINDOW_MS);
        await recordFailure(ipKey, WINDOW_MS);
        return refuse(reason, { usernameRef: referenceOf(organizationId, username), ...data }, userId);
      };

      let result: SignInResult;
      try {
        result = (await askDirectory({
          organizationId,
          kind: "sign-in",
          params: { username },
          password,
        })) as unknown as SignInResult;
      } catch (error) {
        if (!(error instanceof ProblemError)) throw error;
        await audit(who, "auth.directory_sign_in", undefined, {
          outcome: "failure",
          reason: "unavailable",
          problem: "timeout",
        });
        throw new APIError("SERVICE_UNAVAILABLE", {
          message: "The directory is not available",
          code: "DIRECTORY_UNAVAILABLE",
        });
      }

      if (result.outcome === "unavailable" || result.outcome === "misconfigured") {
        // Not the person's doing: not counted against them, and said honestly.
        await audit(who, "auth.directory_sign_in", undefined, {
          outcome: "failure",
          reason: result.outcome,
          problem: result.problem ?? null,
        });
        throw new APIError("SERVICE_UNAVAILABLE", {
          message: "The directory is not available",
          code: "DIRECTORY_UNAVAILABLE",
        });
      }

      if (result.outcome === "invalid-credentials" || !result.user) {
        const existing = result.subject
          ? (
              await db
                .select({ userId: schema.directoryIdentity.userId })
                .from(schema.directoryIdentity)
                .where(eq(schema.directoryIdentity.uniqueId, result.subject.uniqueId))
                .limit(1)
            )[0]
          : undefined;
        return fail(
          "invalid-credentials",
          result.subject ? { dn: result.subject.dn } : {},
          existing?.userId ?? null,
        );
      }

      // The directory accepted the password. From here on the question is only whether GarnetOps lets the person in.
      const person = result.user;
      const provisioned = await provisionDirectoryUser({
        organizationId,
        person: result.outcome === "ok" ? person : { ...person, role: null },
        loginName: username,
        emailVerified: directory.emailVerified,
      });

      if (provisioned.kind === "refused") {
        if (provisioned.change?.kind === "removed") {
          await audit(
            { ...who, userId: provisioned.userId },
            "directory.access_removed",
            { type: "user", id: provisioned.userId as string },
            { email: provisioned.email, before: provisioned.change.before, via: "sign-in" },
          );
        }
        const data: Record<string, unknown> = { dn: person.dn, groups: person.groups };
        if (provisioned.reason === "email-collision") {
          // The clear entry for the administrator: this person exists in the directory and an account with their address exists locally.
          data.email = provisioned.email;
          data.existingUserId = provisioned.collidesWith;
          data.hint = "Link the account to the directory on the Team page, or remove the other account";
        }
        if (provisioned.reason === "no-email") data.hint = "The directory entry has no usable mail attribute";
        return fail(provisioned.reason, data, provisioned.userId ?? provisioned.collidesWith);
      }

      await clearFailures(userKey);
      const actor: Who = { userId: provisioned.userId, organizationId, ip };
      await logAudits(actor, provisioned, person);
      await audit(
        actor,
        "auth.directory_sign_in",
        { type: "user", id: provisioned.userId },
        { outcome: "success", dn: person.dn },
      );

      const user = await ctx.context.internalAdapter.findUserById(provisioned.userId);
      if (!user) throw refusal();
      const session = await ctx.context.internalAdapter.createSession(user.id, false);
      if (!session) throw refusal();
      await setSessionCookie(ctx, { session, user });
      // For an account with a second factor the two-factor plugin replaces this answer and this session (see above).
      return ctx.json({ token: session.token, user: { id: user.id, email: user.email, name: user.name } });
    }),

    /** Whether the signed-in account comes from the directory; the enrolment page uses it to skip the password it does not have. */
    directoryMe: createAuthEndpoint(
      "/directory/me",
      { method: "GET", use: [sessionMiddleware] },
      async (ctx) => {
        const [identity] = await db
          .select({ loginName: schema.directoryIdentity.loginName })
          .from(schema.directoryIdentity)
          .where(eq(schema.directoryIdentity.userId, ctx.context.session.user.id))
          .limit(1);
        return ctx.json({ managed: Boolean(identity), loginName: identity?.loginName ?? null });
      },
    ),
  },
});
