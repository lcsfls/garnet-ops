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

/** Scan state is neutral or informational: a finished scan is not proof of anything, so never green. */
export function scanStateTone(state: ScanState): BadgeTone {
  return state === "failed" ? "critical" : state === "succeeded" ? "neutral" : "info";
}
