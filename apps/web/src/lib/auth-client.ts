import { twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import type { MessageKey } from "./i18n.ts";

export const authClient = createAuthClient({
  baseURL: window.location.origin,
  basePath: "/api/auth",
  plugins: [twoFactorClient()],
});

/** Maps a better-auth error to a translated message. Server text is never shown as-is. */
export function authErrorKey(error: { status: number; code?: string | undefined } | null): MessageKey {
  if (!error) return "errors.generic";
  if (error.status === 429 || error.code === "ACCOUNT_TEMPORARILY_LOCKED") return "errors.tooManyAttempts";
  if (error.code === "INVALID_TWO_FACTOR_COOKIE") return "errors.sessionExpired";
  if (error.code === "INVALID_CODE" || error.code === "INVALID_BACKUP_CODE") return "errors.invalidCode";
  if (error.code === "INVALID_EMAIL_OR_PASSWORD" || error.code === "INVALID_PASSWORD") {
    return "errors.invalidCredentials";
  }
  if (error.status === 0) return "errors.network";
  return "errors.generic";
}
