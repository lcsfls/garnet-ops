import type { ScanState, Severity } from "../../types.ts";

/**
 * Badge tones (mockup). Severity tones only ever mean severity, success only ever means proof (a gate that passed, a
 * fix whose tests passed), never "online" or "finished".
 */
export const BADGE_TONE = {
  critical: "bg-destructive/15 text-destructive-text",
  high: "bg-high/16 text-high-text",
  medium: "bg-warning/18 text-warning-text",
  low: "bg-muted text-muted-foreground",
  neutral: "bg-muted text-muted-foreground",
  success: "bg-success/16 text-success-text",
  info: "bg-info/14 text-info-text",
  outline: "border-border text-foreground",
} as const;
export type BadgeTone = keyof typeof BADGE_TONE;

export const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  negligible: "low",
  unknown: "low",
};

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-destructive",
  high: "bg-high",
  medium: "bg-warning",
  low: "bg-muted-foreground/50",
  negligible: "bg-muted-foreground/50",
  unknown: "bg-muted-foreground/50",
};

/** Text colour of a severity, for its icon next to a title. */
export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-destructive-text",
  high: "text-high-text",
  medium: "text-warning-text",
  low: "text-muted-foreground",
  negligible: "text-muted-foreground",
  unknown: "text-muted-foreground",
};

/** A strip on the leading edge of a row that has a problem; low stays grey (AGENTS.md rule 6). */
export const SEVERITY_EDGE: Record<Severity, string> = {
  critical: "border-l-destructive",
  high: "border-l-high",
  medium: "border-l-warning",
  low: "border-l-muted-foreground/45",
  negligible: "border-l-muted-foreground/45",
  unknown: "border-l-muted-foreground/45",
};

/**
 * Background of a heat-table cell (statistics): four steps of the severity's colour by how much of the table's largest value a
 * cell holds. Fixed classes, because the CSP allows no inline styles; the number is always written in the cell as well.
 */
export const SEVERITY_HEAT: Record<
  "critical" | "high" | "medium" | "low",
  readonly [string, string, string, string]
> = {
  critical: ["bg-destructive/10", "bg-destructive/20", "bg-destructive/35", "bg-destructive/50"],
  high: ["bg-high/10", "bg-high/20", "bg-high/35", "bg-high/50"],
  medium: ["bg-warning/10", "bg-warning/20", "bg-warning/35", "bg-warning/50"],
  low: [
    "bg-muted-foreground/8",
    "bg-muted-foreground/15",
    "bg-muted-foreground/25",
    "bg-muted-foreground/35",
  ],
};

/** The step (0 to 3) of a value against the largest value of its table; null for zero. */
export function heatStep(value: number, max: number): 0 | 1 | 2 | 3 | null {
  if (value <= 0 || max <= 0) return null;
  const share = value / max;
  return share > 0.75 ? 3 : share > 0.5 ? 2 : share > 0.25 ? 1 : 0;
}

/** Scan state is neutral or informational: a finished scan is not proof of anything, so never green. */
export function scanStateTone(state: ScanState): BadgeTone {
  return state === "failed" ? "critical" : state === "succeeded" ? "neutral" : "info";
}
