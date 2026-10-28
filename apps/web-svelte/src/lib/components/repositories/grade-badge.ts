import type { MessageKey } from "../../i18n.svelte.ts";
import type { Grade, GradeRule, Severity } from "../../types.ts";
import type { BadgeTone } from "../ui/tones.ts";

/**
 * Grade colours come from the fixed severity scale (AGENTS.md rule 6): F and E vermilion,
 * D orange, C amber, B grey, A neutral. Never green: a repository without open findings is
 * not proof of anything. The letter is always shown, so colour is never the only signal.
 */
export const GRADE_TONE: Record<Grade, BadgeTone> = {
  F: "critical",
  E: "critical",
  D: "high",
  C: "medium",
  B: "low",
  A: "neutral",
};

export const REASON_KEYS = {
  "known-exploited-with-fix": "grades.reason.knownExploitedWithFix",
  "critical-with-fix": "grades.reason.criticalWithFix",
  "high-with-fix": "grades.reason.highWithFix",
  "critical-without-fix": "grades.reason.criticalWithoutFix",
  "medium-with-fix": "grades.reason.mediumWithFix",
  "high-without-fix": "grades.reason.highWithoutFix",
  "other-open": "grades.reason.otherOpen",
  none: "grades.reason.none",
} as const satisfies Record<GradeRule, MessageKey>;

/**
 * The open findings a rule is about, as the filters of the findings list. A rule that is
 * "without a fix" needs no filter for that: a worse rule would have decided if a fix existed.
 */
export function gradeFindingFilter(rule: GradeRule): {
  severity?: Severity;
  fixable?: "1";
  kev?: "1";
} | null {
  switch (rule) {
    case "known-exploited-with-fix":
      return { kev: "1", fixable: "1" };
    case "critical-with-fix":
      return { severity: "critical", fixable: "1" };
    case "high-with-fix":
      return { severity: "high", fixable: "1" };
    case "critical-without-fix":
      return { severity: "critical" };
    case "medium-with-fix":
      return { severity: "medium", fixable: "1" };
    case "high-without-fix":
      return { severity: "high" };
    case "other-open":
      return {};
    case "none":
      return null;
  }
}
