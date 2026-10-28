import type { Role } from "@garnetops/core";
import { ApiError } from "../../api.ts";
import { t } from "../../i18n.svelte.ts";

export interface Member {
  userId: string;
  role: Role;
  name: string;
  email: string;
  twoFactorEnabled: boolean;
  lastSignInAt: string | null;
  joinedAt: string;
  /** `directory`: signs in with the directory and the role comes from its groups (ADR 0020). */
  source: "local" | "directory";
}

export interface Invitation {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  expiresAt: string;
  invitedBy: string | null;
}

/** The text for a failed team action (React: `useTeamError`). */
export function explainTeamError(error: unknown): string {
  if (!(error instanceof ApiError)) return t("errors.network");
  if (error.code === "already-member") return t("team.errorAlreadyMember");
  if (error.code === "last-owner") return t("team.errorLastOwner");
  if (error.code === "managed-by-directory") return t("team.errorManaged");
  if (error.code === "directory-account") return t("team.errorDirectoryAccount");
  if (error.status === 403) return t("team.errorForbidden");
  return t("errors.actionFailed");
}
