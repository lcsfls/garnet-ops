import type { ProposalRef } from "../../types.ts";
import { href } from "../../url.ts";

/**
 * Where an upgrade is carried out: its fix proposals (the one proposal itself when there is exactly one), or the open
 * findings of the package when no proposal exists.
 */
export function remedyHref(packageName: string, proposals: ProposalRef): string {
  if (proposals.count === 0) return href("/findings", { q: packageName });
  return href("/fixes", {
    repositoryId: proposals.repositoryId ?? undefined,
    q: packageName,
    id: proposals.key ?? undefined,
  });
}
