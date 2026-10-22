/** Small helpers for the Fix proposals page and the repository's fix pull request settings (ADR 0014). */
import type { BadgeTone } from "../components/ui/badge.tsx";
import type { FixPrState } from "./types.ts";

/** "edit-complex-range" -> "editComplexRange": the key of a reason code in the message catalogue. */
export const camelCode = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

/**
 * A pull request that is waiting or open is information; a merged or closed one is just
 * history (a merge is not proof that tests passed, so never green); a failed one needs a look.
 */
export const PR_TONE: Record<FixPrState, BadgeTone> = {
  queued: "info",
  running: "info",
  open: "info",
  merged: "neutral",
  closed: "neutral",
  failed: "critical",
};

/** Only an address the server built from the repository's own host is ever linked. */
export function safeHttpsUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}

/** True while the worker still has something to do for this pull request (the list refreshes itself). */
export const isBusy = (state: FixPrState | undefined) => state === "queued" || state === "running";

/** The host of a repository address (https or SSH form), or null. */
export function repoHost(url: string): string | null {
  const match =
    /^https:\/\/(?:[^@/]+@)?([^/]+)\//i.exec(url) ??
    /^ssh:\/\/(?:[^@/]+@)?([^/:]+)/i.exec(url) ??
    /^[^@/]+@([^:/]+):/.exec(url);
  return match?.[1]?.toLowerCase() ?? null;
}

/** The forge API address for a host: api.github.com, GitHub Enterprise `/api/v3`, Gitea and Forgejo `/api/v1`. */
export function defaultApiBase(kind: "github" | "gitea" | "forgejo", host: string): string {
  if (kind === "github") return host === "github.com" ? "https://api.github.com" : `https://${host}/api/v3`;
  return `https://${host}/api/v1`;
}
