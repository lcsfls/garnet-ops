/**
 * Helpers of the Attacks screens (ADR 0016): country names in the user's language, the colour
 * steps of the map and their legend, and the texts of stored error codes.
 */
import { shadeStep } from "@garnetops/core/attacks";
import { ATTACK_GROUPS } from "@garnetops/core/wazuh";
import { useTranslation } from "react-i18next";
import { ApiError } from "./api.ts";
import type { MessageKey } from "./i18n.ts";

export const ATTACK_SHADES = 5;

/** Tailwind classes of the five map colours (tokens in styles.css, one hue). Step 0 has no data. */
export const MAP_FILL: Record<number, string> = {
  0: "fill-border",
  1: "fill-map-1",
  2: "fill-map-2",
  3: "fill-map-3",
  4: "fill-map-4",
  5: "fill-map-5",
};
export const MAP_SWATCH: Record<number, string> = {
  1: "bg-map-1",
  2: "bg-map-2",
  3: "bg-map-3",
  4: "bg-map-4",
  5: "bg-map-5",
};

export { shadeStep };

/** The largest count that still gets colour step `step` (the inverse of `shadeStep`), for the legend. */
export function stepCeiling(step: number, max: number, steps = ATTACK_SHADES): number {
  let ceiling = 0;
  for (let n = 1; n <= max; n++) {
    if (shadeStep(n, max, steps) <= step) ceiling = n;
    else break;
  }
  return ceiling;
}

/** The legend: for each used step, the upper bound of its range. Steps whose range is empty are left out. */
export function legendSteps(max: number, steps = ATTACK_SHADES): { step: number; upTo: number }[] {
  const out: { step: number; upTo: number }[] = [];
  let previous = 0;
  for (let step = 1; step <= steps; step++) {
    const upTo = step === steps ? max : Math.min(max, stepCeiling(step, max, steps));
    if (upTo > previous) out.push({ step, upTo });
    previous = Math.max(previous, upTo);
  }
  return out;
}

const names = new Map<string, Intl.DisplayNames | null>();
/** A country code as a name in the UI language ("DE" -> "Germany"); the code itself if the platform does not know it. */
export function countryName(code: string, language: string): string {
  let display = names.get(language);
  if (display === undefined) {
    try {
      display = new Intl.DisplayNames([language], { type: "region" });
    } catch {
      display = null;
    }
    names.set(language, display);
  }
  try {
    return display?.of(code) ?? code;
  } catch {
    return code;
  }
}

export const RULE_GROUPS: readonly string[] = ATTACK_GROUPS;
export const isRuleGroup = (value: string): boolean => RULE_GROUPS.includes(value);

/** The best-known text key of an error stored as a code, or the generic one. */
export function geoipReasonKey(code: string | null | undefined): MessageKey {
  const known = [
    "tooLarge",
    "decompressedTooLarge",
    "notGzip",
    "corrupt",
    "lineTooLong",
    "empty",
    "tooManyRows",
    "tooManyInvalid",
    "wrongKind",
    "timeout",
    "storage",
    "busy",
    "notFound",
    "unreachable",
    "tls",
    "redirected",
    "refusedAddress",
    "unexpected",
  ];
  return `attacks.settings.errors.${known.includes(code ?? "") ? code : "generic"}` as MessageKey;
}

export function osintReasonKey(code: string): MessageKey | null {
  const known = [
    "keyRejected",
    "rateLimited",
    "budgetReached",
    "unreachable",
    "unexpectedAnswer",
    "redirected",
    "credentialsMissing",
  ];
  return known.includes(code) ? (`attacks.settings.osintErrors.${code}` as MessageKey) : null;
}

/** The reason an API answer gives for refusing an upload (`reason` in the problem details). */
export function uploadReason(error: unknown): string {
  if (error instanceof ApiError) {
    const reason = error.problem?.reason;
    if (typeof reason === "string") return reason;
    if (error.code === "geoip-busy") return "busy";
    if (error.status === 413) return "tooLarge";
  }
  return "generic";
}

/** Localised country name hook. */
export function useCountryName(): (code: string) => string {
  const { i18n } = useTranslation();
  return (code) => countryName(code, i18n.language);
}
