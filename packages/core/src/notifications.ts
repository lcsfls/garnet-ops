import { isIP } from "node:net";
import { z } from "zod";
import { classifyAddress } from "./ai-endpoint.ts";

/**
 * What a channel can be told about (ADR 0010). "test" is sent on request only. `finding.new` (0.0.10)
 * counts every new finding of a scan from the channel's minimum severity on; `finding.new_critical`
 * stays as it was.
 */
export const NOTIFY_EVENTS = ["finding.new_critical", "gate.blocked", "scan.failed", "finding.new"] as const;
export type NotifyEvent = (typeof NOTIFY_EVENTS)[number] | "test";

/** The severities a channel can ask for, worst first. */
export const CHANNEL_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type ChannelSeverity = (typeof CHANNEL_SEVERITIES)[number];

/**
 * What a channel receives on top of its events: only from this severity on (for `finding.new`,
 * default high) and only for these repositories (none: every repository).
 */
export const channelFiltersSchema = z.object({
  minSeverity: z.enum(CHANNEL_SEVERITIES).optional(),
  repositoryIds: z.array(z.string().min(1).max(40)).max(200).optional(),
});
export type ChannelFilters = z.infer<typeof channelFiltersSchema>;

/** New findings of a scan per severity (`finding.new`). */
export type SeverityCounts = Record<ChannelSeverity, number>;

/** Whether a channel with these filters wants this notification. A test message always goes through. */
export function channelAccepts(filters: ChannelFilters, payload: NotifyPayload): boolean {
  if (payload.event === "test") return true;
  const only = filters.repositoryIds ?? [];
  if (only.length > 0 && payload.repository && !only.includes(payload.repository.id)) return false;
  if (payload.event === "finding.new") return countFrom(payload.findings, filters.minSeverity) > 0;
  return true;
}

/** How many findings of `counts` are at `minSeverity` (default high) or worse. */
export function countFrom(counts: SeverityCounts | undefined, minSeverity: ChannelSeverity = "high"): number {
  if (!counts) return 0;
  const last = CHANNEL_SEVERITIES.indexOf(minSeverity);
  return CHANNEL_SEVERITIES.slice(0, last + 1).reduce((sum, s) => sum + (counts[s] ?? 0), 0);
}

export const WEBHOOK_FORMATS = ["generic", "discord", "slack"] as const;
export type WebhookFormat = (typeof WEBHOOK_FORMATS)[number];

/**
 * The facts of one notification: a summary and a link, nothing more (ADR 0010). No
 * vulnerability ids, package names, paths, code or error output.
 */
export interface NotifyPayload {
  event: NotifyEvent;
  organization: string;
  repository: { id: string; name: string } | null;
  /** New critical and known exploited findings of the scan (finding.new_critical). */
  counts?: { critical: number; knownExploited: number };
  /** Gate result and how many rules set to Block matched (gate.blocked). */
  gate?: { blockingRules: number };
  /** New findings of the scan per severity (finding.new); the channel's minimum decides what is shown. */
  findings?: SeverityCounts;
  link: string;
  at: string;
}

/**
 * Addresses a webhook must never reach (ADR 0010): loopback, link-local (cloud metadata),
 * unspecified, multicast, broadcast, and every IPv6 notation of the same (IPv4-mapped in hex,
 * NAT64, 6to4, IPv4-compatible). Private networks are allowed, because an internal chat server
 * is a normal target. The parsing is shared with the AI endpoint policy (ai-endpoint.ts), so
 * webhooks and directory servers refuse exactly the same addresses.
 */
export function isForbiddenAddress(address: string): boolean {
  return classifyAddress(address) === "forbidden";
}

/** Why a webhook URL is not acceptable, or null. Checked when it is saved and before every send. */
export function webhookUrlProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Not a URL";
  }
  if (url.protocol !== "https:") return "Only https:// addresses are allowed";
  if (url.username || url.password) return "No user name or password in the address";
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) return "This address is not allowed";
  if (isIP(host) && isForbiddenAddress(host)) return "This address is not allowed";
  return null;
}

/** The request body for each webhook format. `text` is the localised summary line(s). */
export function webhookBody(
  format: WebhookFormat,
  payload: NotifyPayload,
  title: string,
  text: string,
): unknown {
  if (format === "discord") return discordBody(payload, title, text);
  if (format === "slack") return { text: `*${title}*\n${text}\n<${payload.link}>` };
  return { title, text, ...payload };
}

/**
 * Embed colours (sRGB of the product's fixed colours, AGENTS.md rule 6): vermilion for what is
 * critical or broken, orange for new findings, steel blue for information. Never green: a message
 * proves nothing about the code.
 */
const DISCORD_COLOURS: Record<NotifyEvent, number> = {
  "finding.new_critical": 0xd9481f,
  "gate.blocked": 0xd9481f,
  "scan.failed": 0xd9481f,
  "finding.new": 0xe07b1a,
  test: 0x4a78a8,
};

/** Discord reads markdown in titles and descriptions; a repository name must stay plain text. */
export function escapeDiscord(value: string): string {
  return value.replace(/([\\*_~`|>#[\]()<-])/g, "\\$1");
}

const clip = (value: string, max: number) => (value.length > max ? `${value.slice(0, max - 1)}…` : value);

/**
 * A Discord message with one embed: the title links to GarnetOps, the colour says what kind of event it
 * is. Mentions are switched off, so nothing in it can ping anyone.
 */
function discordBody(payload: NotifyPayload, title: string, text: string) {
  return {
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: clip(escapeDiscord(title), 256),
        url: payload.link,
        description: clip(`${escapeDiscord(text)}\n${payload.link}`, 4096),
        color: DISCORD_COLOURS[payload.event],
        timestamp: payload.at,
        footer: { text: clip(`GarnetOps · ${payload.organization}`, 2048) },
      },
    ],
  };
}
