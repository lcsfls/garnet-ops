import type { MessageKey } from "./i18n.svelte.ts";
import type { GateResult, ScanState, Severity } from "./types.ts";

/**
 * The one source of how severities and states look (AGENTS.md rule 6): label, level, icon, tokens and the Tailwind classes
 * that use them. Badges, pills, dots, charts, heat tables, callouts, gate and scan badges all read from here; no component
 * keeps its own mapping. The classes are written out in full so Tailwind finds them in this file; the tokens they name are
 * defined in app.css with fixed values per theme and tested in contrast.test.ts.
 *
 * Severity is never told by colour alone: the pill carries the word and a level of four bars, a dot always has its word in
 * the same row or a legend, and every chart has its numbers as a table.
 */

/** The four severities that have a colour; negligible and unknown look like low. */
export const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;
export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

/** A state colour: a severity, proof (success), information, or none (neutral). */
export type Tone = SeverityLevel | "success" | "info" | "neutral";
/** The tones that have their own tokens in app.css. */
export type TokenTone = Exclude<Tone, "neutral">;
export const TOKEN_TONES = [
  "critical",
  "high",
  "medium",
  "low",
  "success",
  "info",
] as const satisfies TokenTone[];

/** Badge looks: a tone, or an outlined neutral tag (an identifier, a label that is no state). */
export type BadgeTone = Tone | "outline";

/** Icon names, mapped to icon components by the Svelte side (ui/StateIcon.svelte). */
export type IconName = "flame" | "triangle-alert" | "circle-alert" | "info" | "circle-check" | "circle-x";

/** The CSS custom properties of a tone, as defined in app.css. */
export function toneTokens(tone: TokenTone): { bg: string; fg: string; border: string; fill: string } {
  return { bg: `--${tone}-bg`, fg: `--${tone}-fg`, border: `--${tone}-border`, fill: `--${tone}-fill` };
}

export interface ToneClasses {
  /** A badge or pill: tone background and tone text. */
  badge: string;
  /** Text or an icon in the tone's colour on a neutral surface. */
  text: string;
  /** A callout (banner, alert, toast): tone background and tone border; its text stays the text colour. */
  callout: string;
  /** A small mark in a legend, a meter or a dot: the tone's fill. */
  swatch: string;
  /** SVG marks (columns, points) in the tone's fill. */
  fill: string;
  /** The line on top of an area. */
  stroke: string;
  /** The area under a line: the tone's background, so stacked areas stay opaque. */
  area: string;
}

export const TONE_CLASSES: Record<Tone, ToneClasses> = {
  critical: {
    badge: "bg-critical-bg text-critical",
    text: "text-critical",
    callout: "border-critical-border bg-critical-bg",
    swatch: "bg-critical-fill",
    fill: "fill-critical-fill",
    stroke: "stroke-critical-fill",
    area: "fill-critical-bg",
  },
  high: {
    badge: "bg-high-bg text-high",
    text: "text-high",
    callout: "border-high-border bg-high-bg",
    swatch: "bg-high-fill",
    fill: "fill-high-fill",
    stroke: "stroke-high-fill",
    area: "fill-high-bg",
  },
  medium: {
    badge: "bg-medium-bg text-medium",
    text: "text-medium",
    callout: "border-medium-border bg-medium-bg",
    swatch: "bg-medium-fill",
    fill: "fill-medium-fill",
    stroke: "stroke-medium-fill",
    area: "fill-medium-bg",
  },
  low: {
    badge: "bg-low-bg text-low",
    text: "text-low",
    callout: "border-low-border bg-low-bg",
    swatch: "bg-low-fill",
    fill: "fill-low-fill",
    stroke: "stroke-low-fill",
    area: "fill-low-bg",
  },
  success: {
    badge: "bg-success-bg text-success",
    text: "text-success",
    callout: "border-success-border bg-success-bg",
    swatch: "bg-success-fill",
    fill: "fill-success-fill",
    stroke: "stroke-success-fill",
    area: "fill-success-bg",
  },
  info: {
    badge: "bg-info-bg text-info",
    text: "text-info",
    callout: "border-info-border bg-info-bg",
    swatch: "bg-info-fill",
    fill: "fill-info-fill",
    stroke: "stroke-info-fill",
    area: "fill-info-bg",
  },
  neutral: {
    badge: "bg-muted text-muted-foreground",
    text: "text-muted-foreground",
    callout: "border-border bg-surface-2",
    swatch: "bg-muted-foreground",
    fill: "fill-muted-foreground",
    stroke: "stroke-muted-foreground",
    area: "fill-muted",
  },
};

/** Badge classes per look. */
export const BADGE_TONE: Record<BadgeTone, string> = {
  ...Object.fromEntries(Object.entries(TONE_CLASSES).map(([tone, c]) => [tone, c.badge])),
  outline: "border-border text-foreground",
} as Record<BadgeTone, string>;

export interface SeverityMeta {
  /** The severity whose colours it takes. */
  tone: SeverityLevel;
  /** 4 for critical down to 1 for low: the filled bars of the pill. */
  level: 1 | 2 | 3 | 4;
  label: MessageKey;
  /** One shape per severity, for places that show an icon alone (tabs): told apart without colour (WCAG 1.4.1). */
  icon: IconName;
  /**
   * Heat-table cell backgrounds (statistics), weakest to strongest; the cell always writes its number, in the text colour.
   */
  heat: readonly [string, string, string, string];
  /** The filled bars of the level indicator. */
  bar: string;
}

export const SEVERITY_META: Record<SeverityLevel, SeverityMeta> = {
  critical: {
    tone: "critical",
    level: 4,
    label: "severity.critical",
    icon: "flame",
    heat: ["bg-critical-bg", "bg-critical-heat-1", "bg-critical-heat-2", "bg-critical-heat-3"],
    bar: "bg-critical",
  },
  high: {
    tone: "high",
    level: 3,
    label: "severity.high",
    icon: "triangle-alert",
    heat: ["bg-high-bg", "bg-high-heat-1", "bg-high-heat-2", "bg-high-heat-3"],
    bar: "bg-high",
  },
  medium: {
    tone: "medium",
    level: 2,
    label: "severity.medium",
    icon: "circle-alert",
    heat: ["bg-medium-bg", "bg-medium-heat-1", "bg-medium-heat-2", "bg-medium-heat-3"],
    bar: "bg-medium",
  },
  low: {
    tone: "low",
    level: 1,
    label: "severity.low",
    icon: "info",
    heat: ["bg-low-bg", "bg-low-heat-1", "bg-low-heat-2", "bg-low-heat-3"],
    bar: "bg-low",
  },
};

/** The empty bars of the level indicator: neutral, so the filled ones carry the level. */
export const LEVEL_BAR_EMPTY = "bg-input";

/** The colour level of any severity: negligible and unknown look like low. */
export function severityLevel(severity: Severity): SeverityLevel {
  return severity === "negligible" || severity === "unknown" ? "low" : severity;
}

/** Look and label of a severity; negligible and unknown keep their own word but look like low. */
export function severityMeta(severity: Severity): SeverityMeta & { label: MessageKey } {
  return { ...SEVERITY_META[severityLevel(severity)], label: `severity.${severity}` };
}

export interface StateMeta {
  tone: Tone;
  label: MessageKey;
  icon: IconName | null;
}

/** Gate results. Green means proof (AGENTS.md rule 6): only a gate that passed is green; blocked is red. */
export const GATE_META: Record<GateResult, StateMeta> = {
  passed: { tone: "success", label: "gates.result.passed", icon: "circle-check" },
  notes: { tone: "medium", label: "gates.result.notes", icon: "circle-alert" },
  blocked: { tone: "critical", label: "gates.result.blocked", icon: "circle-x" },
};

/**
 * Scan states. A finished scan proves nothing, so it is neutral, never green; a failed one is red (a failure), a queued or
 * running one is information.
 */
export const SCAN_STATE_META: Record<ScanState | "never", StateMeta> = {
  queued: { tone: "info", label: "scanState.queued", icon: null },
  running: { tone: "info", label: "scanState.running", icon: null },
  succeeded: { tone: "neutral", label: "scanState.succeeded", icon: null },
  failed: { tone: "critical", label: "scanState.failed", icon: null },
  never: { tone: "neutral", label: "scanState.never", icon: null },
};

/** The step (0 to 3) of a value against the largest value of its table; null for zero. */
export function heatStep(value: number, max: number): 0 | 1 | 2 | 3 | null {
  if (value <= 0 || max <= 0) return null;
  const share = value / max;
  return share > 0.75 ? 3 : share > 0.5 ? 2 : share > 0.25 ? 1 : 0;
}
