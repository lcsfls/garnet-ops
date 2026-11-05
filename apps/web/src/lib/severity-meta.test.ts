import { readFileSync } from "node:fs";
import { SCAN_STATES, SEVERITIES } from "@garnetops/core";
import { LANGUAGES, resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";
import {
  BADGE_TONE,
  GATE_META,
  heatStep,
  LEVEL_BAR_EMPTY,
  SCAN_STATE_META,
  SEVERITY_LEVELS,
  SEVERITY_META,
  severityLevel,
  severityMeta,
  TOKEN_TONES,
  TONE_CLASSES,
  toneTokens,
} from "./severity-meta.ts";

const css = readFileSync(new URL("../app.css", import.meta.url), "utf8");

/** The text of a translation key in a language, or undefined. */
function message(language: (typeof LANGUAGES)[number], key: string): unknown {
  return key
    .split(".")
    .reduce<unknown>(
      (node, part) =>
        node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined,
      resources[language].translation,
    );
}

/** The Tailwind colours of app.css's @theme block, e.g. "critical-bg" for --color-critical-bg. */
const THEME_COLOURS = new Set(
  [...css.slice(css.indexOf("@theme inline {")).matchAll(/--color-([a-z0-9-]+):/g)].map((m) => m[1]),
);
const COLOUR_CLASS = /^(?:[a-z-]+:)*(?:bg|text|border|fill|stroke)-([a-z0-9-]+)$/;

describe("severity-meta", () => {
  it("maps every severity, with negligible and unknown looking like low but keeping their own word", () => {
    for (const s of SEVERITIES) {
      const meta = severityMeta(s);
      expect(meta.label).toBe(`severity.${s}`);
      expect(SEVERITY_LEVELS).toContain(meta.tone);
    }
    expect(severityLevel("negligible")).toBe("low");
    expect(severityLevel("unknown")).toBe("low");
    expect(severityMeta("unknown").level).toBe(1);
    expect(severityMeta("negligible").icon).toBe(SEVERITY_META.low.icon);
  });

  it("orders the levels critical 4, high 3, medium 2, low 1, each with its own icon", () => {
    expect(SEVERITY_LEVELS.map((s) => SEVERITY_META[s].level)).toEqual([4, 3, 2, 1]);
    expect(new Set(SEVERITY_LEVELS.map((s) => SEVERITY_META[s].icon)).size).toBe(4);
  });

  it("colours gates and scans by what they mean: green only for a passed gate, red only for blocked and failed", () => {
    expect(GATE_META.passed.tone).toBe("success");
    expect(GATE_META.notes.tone).toBe("medium");
    expect(GATE_META.blocked.tone).toBe("critical");
    for (const state of SCAN_STATES) expect(SCAN_STATE_META[state]).toBeDefined();
    expect(SCAN_STATE_META.failed.tone).toBe("critical");
    expect(SCAN_STATE_META.succeeded.tone).toBe("neutral");
    expect(SCAN_STATE_META.running.tone).toBe("info");
    expect(SCAN_STATE_META.queued.tone).toBe("info");
    expect(SCAN_STATE_META.never.tone).toBe("neutral");
    const tones = [...Object.values(GATE_META), ...Object.values(SCAN_STATE_META)].map((m) => m.tone);
    expect(tones.filter((t) => t === "success")).toHaveLength(1);
  });

  it("has every label in English and German", () => {
    const keys = [
      ...SEVERITIES.map((s) => severityMeta(s).label),
      ...Object.values(GATE_META).map((m) => m.label),
      ...Object.values(SCAN_STATE_META).map((m) => m.label),
    ];
    for (const language of LANGUAGES)
      for (const key of keys) expect(typeof message(language, key), `${language}: ${key}`).toBe("string");
  });

  it("only uses colours that app.css defines, with no opacity modifier", () => {
    const classes = [
      ...Object.values(TONE_CLASSES).flatMap((c) => Object.values(c)),
      ...Object.values(BADGE_TONE),
      ...SEVERITY_LEVELS.flatMap((s) => [...SEVERITY_META[s].heat, SEVERITY_META[s].bar]),
      LEVEL_BAR_EMPTY,
    ].flatMap((c) => c.split(" "));
    const unknown = classes
      .map((c) => COLOUR_CLASS.exec(c)?.[1])
      .filter((name): name is string => name !== undefined && !THEME_COLOURS.has(name));
    expect(unknown).toEqual([]);
    expect(classes.filter((c) => c.includes("/"))).toEqual([]);
  });

  it("names tokens that both themes define", () => {
    for (const tone of TOKEN_TONES)
      for (const token of Object.values(toneTokens(tone))) {
        expect(css, token).toContain(`  ${token}: oklch(`);
        expect(css.split(`${token}: oklch(`).length - 1, token).toBe(3);
      }
  });

  it("steps a heat cell by its share of the table's largest value", () => {
    expect(heatStep(0, 10)).toBeNull();
    expect(heatStep(3, 0)).toBeNull();
    expect(heatStep(2, 10)).toBe(0);
    expect(heatStep(3, 10)).toBe(1);
    expect(heatStep(6, 10)).toBe(2);
    expect(heatStep(10, 10)).toBe(3);
  });
});
