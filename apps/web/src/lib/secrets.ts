import { isSensitiveFileRule, type SecretSeverity } from "@garnetops/core/secrets";
import { api } from "./api.ts";
import { type MessageKey, t } from "./i18n.svelte.ts";

/** Secrets and sensitive files (ADR 0049), as the API returns them. No value is ever part of it. */
export type SecretState = "open" | "revoked" | "dismissed";

export interface SecretPlace {
  path: string;
  line: number | null;
  commit?: string;
  committedAt?: string | null;
}

export interface SecretRow {
  id: string;
  repositoryId: string;
  repositoryName: string;
  ruleId: string;
  severity: SecretSeverity;
  state: SecretState;
  inTree: boolean;
  place: SecretPlace | null;
  treeLocationCount: number;
  historyLocationCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface SecretDetail extends Omit<SecretRow, "place"> {
  stateReason: string | null;
  stateAt: string | null;
  stateByName: string | null;
  treeLocations: SecretPlace[];
  historyLocations: SecretPlace[];
}

export interface SecretCounts {
  states: Record<SecretState, number>;
  open: Partial<Record<SecretSeverity, number>>;
}

export interface RepositorySecrets {
  open: Partial<Record<SecretSeverity, number>>;
  lastCheck: "done" | "skipped" | "failed" | null;
  history: { enabled: boolean; enabledAt: string | null; checkedAt: string | null };
}

/** Shared by the page and the menu's count. */
export const secretCountsQuery = (filters = "") => ({
  queryKey: ["secret-counts", filters],
  queryFn: () => api<SecretCounts>(`/secrets/counts${filters}`),
});

/** What the rule found, in words: GarnetOps' own file rules are named, gitleaks' rules keep their id. */
export function secretRuleName(ruleId: string): string {
  return isSensitiveFileRule(ruleId) ? t(`secrets.fileRule.${ruleId}` as MessageKey) : ruleId;
}

/** `path:line`, or the path alone for a rule about a whole file. */
export const placeText = (p: SecretPlace) => (p.line ? `${p.path}:${p.line}` : p.path);
