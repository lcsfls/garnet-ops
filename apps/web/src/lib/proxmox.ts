/**
 * Helpers of the Proxmox screens (ADR 0012): the stored error texts in the user's language,
 * usage figures, and the commands that create the read-only user and token. The commands are
 * code, not interface text, and use example names only.
 */
import { parseProxmoxError } from "@garnetops/core";
import { useTranslation } from "react-i18next";
import type { BadgeTone } from "../components/ui/badge.tsx";
import type { ProxmoxFlag } from "./types.ts";

/**
 * Translates a failure the worker stored in English (packages/core proxmox-errors.ts). A text
 * this version does not know is shown unchanged.
 */
export function useProxmoxErrorText(): (message: string) => string {
  const { t } = useTranslation();
  return (message) => {
    const parsed = parseProxmoxError(message);
    return parsed ? t(`proxmoxError.${parsed.code}`, parsed.params) : message;
  };
}

/** A share from 0 to 1 for used of total, or null if either is unknown or the total is zero. */
export function usage(used: number | null, total: number | null): number | null {
  if (used === null || total === null || total <= 0) return null;
  return Math.min(1, Math.max(0, used / total));
}

/** Badge tones of the flags. Colour is never the only signal: every flag has its word and an icon. */
export const FLAG_TONE: Record<ProxmoxFlag, BadgeTone> = {
  stoppedLong: "neutral",
  noRecentBackup: "neutral",
  oldSnapshot: "neutral",
  untracked: "info",
};

/** Order of the flags in a row. */
export const FLAG_ORDER: ProxmoxFlag[] = ["noRecentBackup", "stoppedLong", "oldSnapshot", "untracked"];

/**
 * The commands that create a dedicated read-only user and token on a Proxmox VE node, as the
 * documentation shows them (docs/proxmox.md). The token needs the role itself because its
 * privilege separation is switched on: its permissions are the intersection of the user's and
 * its own.
 */
export const PVEUM_COMMANDS = [
  'pveum user add garnetops@pve --comment "GarnetOps read-only inventory"',
  "pveum acl modify / --users garnetops@pve --roles PVEAuditor",
  "pveum user token add garnetops@pve inventory --privsep 1",
  "pveum acl modify / --tokens 'garnetops@pve!inventory' --roles PVEAuditor",
].join("\n");

/** The command that shows the certificate of a node, for comparing its fingerprint. */
export const PVENODE_CERT_COMMAND = "pvenode cert info";
