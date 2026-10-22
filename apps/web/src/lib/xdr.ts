/**
 * Helpers of the XDR screens (ADR 0015): the stored error texts in the user's language, the
 * order and tones of severities and the change against the previous period.
 */
import { parseWazuhError, WAZUH_ENDPOINT_NAMES } from "@garnetops/core";
import { useTranslation } from "react-i18next";
import type { BadgeTone } from "../components/ui/badge.tsx";
import { api } from "./api.ts";
import type { XdrAgentStatus, XdrCounts, XdrSeverity, XdrWindow } from "./types.ts";

/** Whether a Wazuh connection exists; the XDR entry is listed only then (ADR 0015). */
export const xdrStatusQuery = {
  queryKey: ["xdr-status"],
  queryFn: () => api<{ connected: boolean }>("/xdr/status"),
  staleTime: 60_000,
};

export const XDR_SEVERITIES: readonly XdrSeverity[] = ["critical", "high", "medium", "low"];

/** Keys of the period labels ("24h" is not a usable object key in a message path). */
export const PERIOD_KEY: Record<XdrWindow, "h24" | "d7" | "d30"> = { "24h": "h24", "7d": "d7", "30d": "d30" };

/**
 * Translates a failure the worker stored in English (packages/core wazuh-errors.ts). A text this
 * version does not know is shown unchanged.
 */
export function useWazuhErrorText(): (message: string) => string {
  const { t } = useTranslation();
  return (message) => {
    const parsed = parseWazuhError(message);
    if (!parsed) return message;
    const params = { ...parsed.params };
    // The stored text carries the English word for the endpoint; show it in the user's language.
    const endpoint = params.endpoint;
    if (typeof endpoint === "string") {
      const kind = (Object.entries(WAZUH_ENDPOINT_NAMES).find(([, english]) => english === endpoint)?.[0] ??
        "manager") as keyof typeof WAZUH_ENDPOINT_NAMES;
      params.endpoint = t(`xdr.endpointName.${kind}`);
    }
    return t(`wazuhError.${parsed.code}`, params);
  };
}

/** How the number of alerts changed against the period before. */
export type Change = { kind: "unknown" } | { kind: "same" } | { kind: "up" | "down"; by: number };

export function changeOf(now: number, before: number | null | undefined): Change {
  if (before === null || before === undefined) return { kind: "unknown" };
  if (now === before) return { kind: "same" };
  return now > before ? { kind: "up", by: now - before } : { kind: "down", by: before - now };
}

export const sumCounts = (c: XdrCounts) => c.critical + c.high + c.medium + c.low;

/** Agent status tones. A connected agent is neutral, not green: online proves nothing (AGENTS.md rule 6). */
export const AGENT_STATUS_TONE: Record<XdrAgentStatus, BadgeTone> = {
  active: "neutral",
  disconnected: "outline",
  never_connected: "neutral",
  pending: "info",
  unknown: "neutral",
};
