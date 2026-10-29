import type { Language } from "@garnetops/i18n";

export const EVENTS = ["finding.new_critical", "finding.new", "gate.blocked", "scan.failed"] as const;
export const KINDS = ["webhook", "smtp", "graph"] as const;
export const FORMATS = ["discord", "slack", "generic"] as const;
export type Kind = (typeof KINDS)[number];
export type ChannelEvent = (typeof EVENTS)[number];
/** From which severity on a channel hears of new findings; high unless chosen otherwise. */
export const MIN_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type MinSeverity = (typeof MIN_SEVERITIES)[number];

export interface ChannelFilters {
  minSeverity?: MinSeverity;
  /** None: every repository, also the ones added later. */
  repositoryIds?: string[];
}

export interface Channel {
  id: string;
  name: string;
  kind: Kind;
  format: (typeof FORMATS)[number] | null;
  language: Language;
  events: ChannelEvent[];
  filters: ChannelFilters;
  enabled: boolean;
  config: Record<string, unknown>;
  lastDelivery: { status: "sent" | "failed"; error: string | null; event: string; createdAt: string } | null;
}

/** Message keys cannot contain dots (i18next reads them as nesting). */
export const eventKey = (event: ChannelEvent) =>
  event.replace(".", "_") as "finding_new_critical" | "finding_new" | "gate_blocked" | "scan_failed";

/** The filters as the API takes them: an empty repository choice is no choice. */
export function filtersBody(minSeverity: MinSeverity, repositoryIds: string[] | null): ChannelFilters {
  return { minSeverity, ...(repositoryIds?.length ? { repositoryIds } : {}) };
}

/** Where a channel sends to, without anything secret (ADR 0010). */
export function target(channel: Channel): string {
  const c = channel.config;
  if (channel.kind === "webhook") return String(c.host ?? "");
  const to = Array.isArray(c.to) ? c.to.join(", ") : "";
  return channel.kind === "smtp" ? `${c.host}:${c.port} → ${to}` : `${c.from} → ${to}`;
}
