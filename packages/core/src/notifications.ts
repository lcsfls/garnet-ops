import { isIP } from "node:net";
import { classifyAddress } from "./ai-endpoint.ts";

/** What a channel can be told about (ADR 0010). "test" is sent on request only. */
export const NOTIFY_EVENTS = ["finding.new_critical", "gate.blocked", "scan.failed"] as const;
export type NotifyEvent = (typeof NOTIFY_EVENTS)[number] | "test";

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
  if (format === "discord") {
    // Discord: content is plain text; mentions are switched off so a repository name cannot ping anyone.
    return { content: `**${title}**\n${text}\n${payload.link}`, allowed_mentions: { parse: [] } };
  }
  if (format === "slack") return { text: `*${title}*\n${text}\n<${payload.link}>` };
  return { title, text, ...payload };
}
