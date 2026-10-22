import { schema } from "@garnetops/db";
import { and, count, eq, like, or } from "drizzle-orm";
import { db } from "../db.ts";
import { audit } from "./audit.ts";

/**
 * Recovery for a lost second factor (ADR 0017). It is not an API route and the web app never
 * offers it: an operator with a shell in the API container runs it (`cli.ts`). It removes the
 * authenticator app and every passkey of one account, signs the account out everywhere and
 * leaves the password alone, so the person signs in with the password and is sent to the
 * mandatory setup of a new second factor, like a new account.
 */

export interface SecondFactorSummary {
  userId: string;
  name: string;
  email: string;
  organizationId: string | null;
  totpEnrolled: boolean;
  passkeys: number;
  sessions: number;
}

/** What is there to reset for the account with this address, or null if there is no such account. */
export async function inspectSecondFactor(email: string): Promise<SecondFactorSummary | null> {
  const [user] = await db
    .select({ id: schema.user.id, name: schema.user.name, email: schema.user.email })
    .from(schema.user)
    .where(eq(schema.user.email, email.trim().toLowerCase()))
    .limit(1);
  if (!user) return null;
  const [membership] = await db
    .select({ organizationId: schema.membership.organizationId })
    .from(schema.membership)
    .where(eq(schema.membership.userId, user.id))
    .limit(1);
  const [totp] = await db
    .select({ n: count() })
    .from(schema.twoFactor)
    .where(eq(schema.twoFactor.userId, user.id));
  const [passkeys] = await db
    .select({ n: count() })
    .from(schema.passkey)
    .where(eq(schema.passkey.userId, user.id));
  const [sessions] = await db
    .select({ n: count() })
    .from(schema.session)
    .where(eq(schema.session.userId, user.id));
  return {
    userId: user.id,
    name: user.name,
    email: user.email,
    organizationId: membership?.organizationId ?? null,
    totpEnrolled: (totp?.n ?? 0) > 0,
    passkeys: passkeys?.n ?? 0,
    sessions: sessions?.n ?? 0,
  };
}

/** Removes the second factors and sessions of the account and writes the audit entry. */
export async function resetSecondFactor(summary: SecondFactorSummary): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .update(schema.user)
      .set({ twoFactorEnabled: false, updatedAt: new Date() })
      .where(eq(schema.user.id, summary.userId));
    await tx.delete(schema.twoFactor).where(eq(schema.twoFactor.userId, summary.userId));
    await tx.delete(schema.passkey).where(eq(schema.passkey.userId, summary.userId));
    await tx.delete(schema.session).where(eq(schema.session.userId, summary.userId));
    // A sign-in waiting for its code and a half-finished authenticator replacement die with the factor.
    await tx
      .delete(schema.verification)
      .where(
        or(
          and(like(schema.verification.identifier, "2fa-%"), eq(schema.verification.value, summary.userId)),
          eq(schema.verification.identifier, `totp-reenrol:${summary.userId}`),
        ),
      );
  });
  await audit(
    { organizationId: summary.organizationId, userId: null, ip: null },
    "account.second_factor_reset",
    { type: "user", id: summary.userId },
    {
      via: "cli",
      account: summary.email,
      authenticatorRemoved: summary.totpEnrolled,
      passkeysRemoved: summary.passkeys,
      sessionsEnded: summary.sessions,
    },
  );
}
