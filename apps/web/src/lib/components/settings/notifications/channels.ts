import type { Language } from "@garnetops/i18n";

export const EVENTS = ["finding.new_critical", "gate.blocked", "scan.failed"] as const;
export const KINDS = ["webhook", "smtp", "graph"] as const;
export const FORMATS = ["discord", "slack", "generic"] as const;
export type Kind = (typeof KINDS)[number];
export type ChannelEvent = (typeof EVENTS)[number];

export interface Channel {
  id: string;
  name: string;
  kind: Kind;
  format: (typeof FORMATS)[number] | null;
  language: Language;
  events: ChannelEvent[];
  enabled: boolean;
  config: Record<string, unknown>;
  lastDelivery: { status: "sent" | "failed"; error: string | null; event: string; createdAt: string } | null;
}

/** Message keys cannot contain dots (i18next reads them as nesting). */
export const eventKey = (event: ChannelEvent) =>
  event.replace(".", "_") as "finding_new_critical" | "gate_blocked" | "scan_failed";

/** Where a channel sends to, without anything secret (ADR 0010). */
export function target(channel: Channel): string {
  const c = channel.config;
  if (channel.kind === "webhook") return String(c.host ?? "");
  const to = Array.isArray(c.to) ? c.to.join(", ") : "";
  return channel.kind === "smtp" ? `${c.host}:${c.port} → ${to}` : `${c.from} → ${to}`;
}
