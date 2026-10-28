import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import type { MessageKey } from "./i18n.svelte.ts";

export const authClient = createAuthClient({
  baseURL: window.location.origin,
  basePath: "/api/auth",
  plugins: [twoFactorClient()],
});

/**
 * Signs in with a directory account (LDAP, Active Directory; ADR 0020). The same answers as
 * the local sign-in: `twoFactorRedirect` when the second step follows, otherwise a session that
 * may only enrol a second factor.
 */
export function directorySignIn(username: string, password: string) {
  return authClient.$fetch<{ twoFactorRedirect?: boolean }>("/sign-in/username", {
    method: "POST",
    body: { username, password },
  });
}

/** Whether the signed-in account comes from the directory, and the name it used to sign in. */
export function directoryMe() {
  return authClient.$fetch<{ managed: boolean; loginName: string | null }>("/directory/me", {
    method: "GET",
  });
}

/** Maps a better-auth error to a translated message. Server text is never shown as-is. */
export function authErrorKey(error: { status: number; code?: string | undefined } | null): MessageKey {
  if (!error) return "errors.generic";
  if (error.status === 429 || error.code === "ACCOUNT_TEMPORARILY_LOCKED") return "errors.tooManyAttempts";
  if (error.code === "INVALID_TWO_FACTOR_COOKIE") return "errors.sessionExpired";
  if (error.code === "INVALID_CODE" || error.code === "INVALID_BACKUP_CODE") return "errors.invalidCode";
  if (error.code === "INVALID_EMAIL_OR_PASSWORD" || error.code === "INVALID_PASSWORD") {
    return "errors.invalidCredentials";
  }
  if (error.code === "INVALID_USERNAME_OR_PASSWORD") return "errors.invalidDirectoryCredentials";
  if (error.code === "DIRECTORY_UNAVAILABLE") return "errors.directoryUnavailable";
  if (error.status === 0) return "errors.network";
  return "errors.generic";
}
