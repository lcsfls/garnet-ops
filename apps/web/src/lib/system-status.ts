/**
 * Helpers of the System status page (ADR 0024): how states look and which settings section each
 * row leads to. Colour is never the only signal: every level has its own icon and every row its
 * own word. "As expected" is a neutral grey, not green, because nothing on this page proves
 * anything (AGENTS.md rule 6).
 */
import type { StatusLevel } from "@garnetops/core/system-status";
import type { IntegrationKey } from "@garnetops/core/system-status-view";
import type { BadgeTone } from "../components/ui/badge.tsx";
import type { SettingsSection } from "./search.ts";

export const LEVEL_TONE: Record<StatusLevel, BadgeTone> = {
  ok: "neutral",
  attention: "medium",
  failed: "critical",
  inactive: "outline",
};

/** The settings section where an integration is set up. */
export const INTEGRATION_SECTION: Record<IntegrationKey, SettingsSection> = {
  wazuh: "xdr",
  proxmox: "proxmox",
  unifi: "unifi",
  directory: "signin",
  exposure: "exposure",
  ai: "ai",
  notifications: "notifications",
};

/** `scan.repository` -> `scanRepository`, `scan.schedule-tick` -> `scanScheduleTick`: the key of a queue's label. */
export const queueKey = (name: string): string =>
  name.replace(/[^A-Za-z0-9]+([A-Za-z0-9])/g, (_, c: string) => c.toUpperCase());

type Camel<S extends string> = S extends `${infer A}_${infer B}` ? `${A}${Capitalize<Camel<B>>}` : S;

/** `not_configured` -> `notConfigured`: the key of a state's word. */
export const camelState = <S extends string>(state: S): Camel<S> =>
  state.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase()) as Camel<S>;

/** Message key part of a vulnerability database source (`local-build` -> `localBuild`). */
export const SOURCE_KEY = { anchore: "anchore", manual: "manual", "local-build": "localBuild" } as const;

/** The `YYYY-MM` of a GeoIP release as "October 2026" in the UI language; anything else is shown as it is. */
export function monthLabel(month: string, language: string): string {
  const match = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(month);
  if (!match) return month;
  return new Intl.DateTimeFormat(language, { month: "long", year: "numeric", timeZone: "UTC" }).format(
    new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, 1)),
  );
}

/** Whether the current user can open a settings section from this page. The directory is for owners alone (ADR 0020). */
export const canOpenSection = (section: SettingsSection, role: string): boolean =>
  section === "signin" ? role === "owner" : true;
