/**
 * The attack overview (ADR 0016): what is made of the aggregated source addresses that the Wazuh
 * sync stores. Pure functions; the API and the worker both use them, so the page and the AI
 * summary count the same way.
 *
 * Counts are alerts of the attack and authentication-failure rule groups, per source address, for
 * the 100 busiest addresses of a window. A country or AS total is therefore the share of those
 * addresses, not of every alert, and the page says so.
 */
import { HIGH_ABUSE_SCORE } from "./attack-live.ts";
import { WINDOWS, type Window } from "./wazuh.ts";

export { WINDOWS, type Window };

export interface TargetedAgent {
  agentId: string;
  name: string;
  count: number;
}

export type Scope = "public" | "internal";

/** One aggregated source address with what the local GeoIP tables say about it. */
export interface AttackSource {
  ip: string;
  count: number;
  groups: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  agents: TargetedAgent[];
  scope: Scope;
  /** Null for an internal address, or one the tables do not cover. */
  country: string | null;
  asn: number | null;
  org: string | null;
}

export interface CountryTotal {
  /** ISO 3166-1 alpha-2; null collects public addresses the tables do not cover. */
  country: string | null;
  alerts: number;
  sources: number;
}
export interface AsnTotal {
  asn: number | null;
  org: string | null;
  alerts: number;
  sources: number;
}

const byAlerts = <T extends { alerts: number }>(a: T, b: T) => b.alerts - a.alerts;

/** Alerts and addresses per country, busiest first. Internal addresses are not part of any country. */
export function countryTotals(sources: readonly AttackSource[]): CountryTotal[] {
  const totals = new Map<string | null, CountryTotal>();
  for (const s of sources) {
    if (s.scope !== "public") continue;
    const key = s.country;
    const total = totals.get(key) ?? { country: key, alerts: 0, sources: 0 };
    total.alerts += s.count;
    total.sources += 1;
    totals.set(key, total);
  }
  return [...totals.values()].sort(
    (a, b) => byAlerts(a, b) || (a.country ?? "~").localeCompare(b.country ?? "~"),
  );
}

/** Alerts and addresses per autonomous system, busiest first. */
export function asnTotals(sources: readonly AttackSource[]): AsnTotal[] {
  const totals = new Map<number | null, AsnTotal>();
  for (const s of sources) {
    if (s.scope !== "public") continue;
    const key = s.asn;
    const total = totals.get(key) ?? { asn: key, org: s.org, alerts: 0, sources: 0 };
    total.alerts += s.count;
    total.sources += 1;
    if (!total.org && s.org) total.org = s.org;
    totals.set(key, total);
  }
  return [...totals.values()].sort((a, b) => byAlerts(a, b) || (a.asn ?? 0) - (b.asn ?? 0));
}

/** Alerts and addresses of internal (private or reserved) sources. */
export function internalTotals(sources: readonly AttackSource[]): { alerts: number; sources: number } {
  let alerts = 0;
  let n = 0;
  for (const s of sources) {
    if (s.scope === "internal") {
      alerts += s.count;
      n += 1;
    }
  }
  return { alerts, sources: n };
}

/** Number of distinct known countries among the sources. */
export const countryCount = (sources: readonly AttackSource[]): number =>
  new Set(
    sources.filter((s) => s.scope === "public" && s.country && s.country !== "ZZ").map((s) => s.country),
  ).size;

/** Targeted agents summed over the sources, busiest first. */
export function agentTotals(sources: readonly AttackSource[], limit = 10): TargetedAgent[] {
  const totals = new Map<string, TargetedAgent>();
  for (const s of sources) {
    for (const a of s.agents) {
      const total = totals.get(a.agentId) ?? { agentId: a.agentId, name: a.name, count: 0 };
      total.count += a.count;
      totals.set(a.agentId, total);
    }
  }
  return [...totals.values()]
    .sort((a, b) => b.count - a.count || a.agentId.localeCompare(b.agentId))
    .slice(0, limit);
}

/**
 * The colour step of a country on the map: 0 for none, then 1 to `steps` on a square-root scale
 * (a linear scale would show one country and nothing else). One hue, never a severity colour.
 */
export function shadeStep(count: number, max: number, steps = 5): number {
  if (count <= 0 || max <= 0) return 0;
  return Math.min(steps, Math.max(1, Math.ceil(Math.sqrt(count / max) * steps)));
}

/**
 * The stroke step of an arc on the globe (ADR 0021): 1 to `steps` on the same square-root scale as the map, so a
 * handful of discrete widths and no fake precision. 0 for no alerts.
 */
export const arcStep = (count: number, max: number, steps = ARC_STEPS): number =>
  shadeStep(count, max, steps);
export const ARC_STEPS = 3;

/**
 * The tone of an arc: "high" (vermilion) for an OSINT abuse score above 80, otherwise "observed" (orange). Only
 * when OSINT is switched on and a score exists; without a score an arc is never called high.
 */
export function arcTone(score: number | null | undefined, osintEnabled: boolean): "high" | "observed" {
  return osintEnabled && typeof score === "number" && score > HIGH_ABUSE_SCORE ? "high" : "observed";
}

/** How a count changed against the period before; null when there is nothing to compare. */
export function changeOf(
  now: number,
  before: number | null,
): { kind: "up" | "down" | "same"; by: number } | null {
  if (before === null) return null;
  if (now === before) return { kind: "same", by: 0 };
  return now > before ? { kind: "up", by: now - before } : { kind: "down", by: before - now };
}

/** The window an unknown value stands for, or the default. */
export const windowOf = (value: unknown): Window =>
  (WINDOWS as readonly unknown[]).includes(value) ? (value as Window) : "24h";
