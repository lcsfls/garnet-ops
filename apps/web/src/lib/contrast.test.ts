import { readFileSync } from "node:fs";
import { SEVERITY_FILL_HEX } from "@garnetops/core/severity-colours";
import { describe, expect, it } from "vitest";
import { GATE_META, SEVERITY_LEVELS, TOKEN_TONES, type TokenTone } from "./severity-meta.ts";

/**
 * The colour tokens of app.css against WCAG 2.2 AA (AGENTS.md rule 6: every text pair is tested in CI). The test reads the
 * tokens of both themes from the stylesheet, turns each oklch() value into 8-bit sRGB as a browser shows it, and checks the
 * pairs the components use: 4.5:1 for text, 3:1 for the focus ring and the level bars of the severity pill. It also checks
 * that each value is exactly the hex colour in its comment, that the severities differ in lightness where the chart fills
 * and gate results carry them, and that the PDF report uses the same severity colours as the app.
 */

const css = readFileSync(new URL("../app.css", import.meta.url), "utf8");

type Theme = "light" | "dark";
interface Token {
  value: string;
  hex: string | null;
}

/** The custom properties of the first rule that starts with `selector {`, with the hex colour from their comment. */
function tokens(selector: string): Map<string, Token> {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`missing rule: ${selector}`);
  const body = css.slice(start, css.indexOf("}", start));
  const out = new Map<string, Token>();
  for (const m of body.matchAll(/--([a-z0-9-]+):\s*([^;]+);[ \t]*(?:\/\*\s*(#[0-9a-f]{6}))?/gi)) {
    out.set(m[1] ?? "", { value: (m[2] ?? "").trim(), hex: m[3]?.toLowerCase() ?? null });
  }
  return out;
}

const THEMES: Record<Theme, Map<string, Token>> = {
  light: tokens(":root"),
  dark: tokens(':root[data-theme="dark"]'),
};

/* ---------------------------------------------------------------------------------------------------------------- */
/* Colour maths: OKLCH to sRGB (Björn Ottosson's OKLab), WCAG relative luminance and contrast. No dependency.       */
/* ---------------------------------------------------------------------------------------------------------------- */

type Rgb = readonly [number, number, number];

function parseOklch(value: string): { l: number; c: number; h: number } {
  const m = /^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\)$/.exec(value);
  if (!m) throw new Error(`not an opaque oklch() colour: ${value}`);
  return { l: Number(m[1]), c: Number(m[2]), h: Number(m[3]) };
}

const toGamma = (c: number) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);
const toLinear = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);

/** 8-bit sRGB (0 to 255), clipped to the gamut, as a browser paints it. */
function oklchToRgb(value: string): Rgb {
  const { l: L, c: C, h: H } = parseOklch(value);
  const a = C * Math.cos((H * Math.PI) / 180);
  const b = C * Math.sin((H * Math.PI) / 180);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const linear = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  const [r = 0, g = 0, bl = 0] = linear.map((v) => Math.round(Math.min(1, Math.max(0, toGamma(v))) * 255));
  return [r, g, bl];
}

const hexOf = (rgb: Rgb) => `#${rgb.map((c) => c.toString(16).padStart(2, "0")).join("")}`;

function luminance(rgb: Rgb): number {
  const [r = 0, g = 0, b = 0] = rgb.map((c) => toLinear(c / 255));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** The value of a token after following var() references within its theme. */
function resolve(theme: Theme, name: string, seen: string[] = []): string {
  const token = THEMES[theme].get(name);
  if (!token) throw new Error(`--${name} is not defined in the ${theme} theme`);
  const ref = /^var\(--([a-z0-9-]+)\)$/.exec(token.value);
  if (!ref) return token.value;
  if (seen.includes(name)) throw new Error(`circular token: --${name}`);
  return resolve(theme, ref[1] ?? "", [...seen, name]);
}

const rgb = (theme: Theme, name: string) => oklchToRgb(resolve(theme, name));
const lightness = (theme: Theme, name: string) => parseOklch(resolve(theme, name)).l;

/* ---------------------------------------------------------------------------------------------------------------- */
/* The pairs the components use.                                                                                    */
/* ---------------------------------------------------------------------------------------------------------------- */

/** Every surface text sits on. */
const SURFACES = [
  "bg",
  "sidebar",
  "surface",
  "surface-2",
  "nav-active-bg",
  "row-selected-bg",
  "hover-bg",
  "neutral-bg",
];
/** Surfaces a state's text sits on as plain text: a table row (also hovered or selected), a card, the page. */
const ROW_SURFACES = ["bg", "surface", "surface-2", "row-selected-bg", "hover-bg"];

interface Pair {
  fg: string;
  bg: string;
  min: number;
  why: string;
}

function pairs(): Pair[] {
  const out: Pair[] = [];
  const add = (fg: string, bg: string, min: number, why: string) => out.push({ fg, bg, min, why });
  for (const bg of SURFACES) {
    add("text", bg, 4.5, "text and links");
    add("text-muted", bg, 4.5, "muted text");
  }
  add("primary-fg", "primary", 4.5, "primary button");
  add("primary-fg", "primary-hover", 4.5, "primary button, hovered");
  for (const tone of TOKEN_TONES) {
    add(`${tone}-fg`, `${tone}-bg`, 4.5, `${tone} badge, pill and callout icon`);
    add("text", `${tone}-bg`, 4.5, `${tone} callout title`);
    add("text-muted", `${tone}-bg`, 4.5, `${tone} callout text`);
    for (const bg of ROW_SURFACES) add(`${tone}-fg`, bg, 4.5, `${tone} text on a neutral surface`);
  }
  for (const s of SEVERITY_LEVELS) {
    for (const step of [`${s}-bg`, `${s}-heat-1`, `${s}-heat-2`, `${s}-heat-3`])
      add("text", step, 4.5, "heat-table cell");
    // The pill's level: filled bars in the fg colour against the empty, neutral ones and against the pill.
    add(`${s}-fg`, "input-border", 3, `${s} pill, filled against empty level bars`);
  }
  for (const bg of SURFACES) add("ring", bg, 3, "focus ring");
  return out;
}

describe.each(["light", "dark"] as const)("%s theme", (theme) => {
  it("writes every colour token as the exact OKLCH form of the hex colour in its comment", () => {
    const wrong: string[] = [];
    for (const [name, token] of THEMES[theme]) {
      if (!token.value.startsWith("oklch(") || token.value.includes("/")) continue;
      if (!token.hex) wrong.push(`--${name}: no hex comment`);
      else if (hexOf(oklchToRgb(token.value)) !== token.hex)
        wrong.push(`--${name}: ${token.value} is ${hexOf(oklchToRgb(token.value))}, not ${token.hex}`);
    }
    expect(wrong).toEqual([]);
  });

  it("meets WCAG AA for every text pair, the focus ring and the level bars", () => {
    const failing = pairs()
      .map((p) => ({ ...p, ratio: contrast(rgb(theme, p.fg), rgb(theme, p.bg)) }))
      .filter((p) => p.ratio < p.min)
      .map((p) => `${p.fg} on ${p.bg}: ${p.ratio.toFixed(2)} < ${p.min} (${p.why})`);
    expect(failing).toEqual([]);
  });

  it("tells the four severities apart by lightness in charts, not only by hue", () => {
    const fills = SEVERITY_LEVELS.map((s) => ({ s, l: lightness(theme, `${s}-fill`) }));
    for (const a of fills)
      for (const b of fills)
        if (a.s < b.s) expect(Math.abs(a.l - b.l), `${a.s} and ${b.s} fill`).toBeGreaterThanOrEqual(0.08);
  });

  it("tells the gate results and found against resolved apart by lightness", () => {
    const groups: TokenTone[][] = [
      Object.values(GATE_META).map((g) => g.tone as TokenTone),
      ["info", "success"],
    ];
    for (const tones of groups)
      for (const a of tones)
        for (const b of tones)
          if (a < b)
            expect(
              Math.abs(lightness(theme, `${a}-fill`) - lightness(theme, `${b}-fill`)),
              `${a} and ${b} fill`,
            ).toBeGreaterThanOrEqual(0.08);
  });

  it("makes each heat-table step stronger than the one before", () => {
    for (const s of SEVERITY_LEVELS) {
      const steps = [`${s}-bg`, `${s}-heat-1`, `${s}-heat-2`, `${s}-heat-3`].map((n) => lightness(theme, n));
      const away = steps.map((l) => Math.abs(l - lightness(theme, "surface")));
      for (let i = 1; i < away.length; i++)
        expect(away[i], `${s} step ${i}`).toBeGreaterThan(away[i - 1] ?? 0);
    }
  });

  /*
   * The text colours of the severities from the 0.1.1 mockup are close in lightness (light: low 0.442, medium 0.454,
   * critical 0.500, high 0.539; dark: low 0.823, high 0.837, critical 0.839, medium 0.884), so this cannot hold yet. The
   * pill shows the level as bars and the word, so severity never depends on the text colour; whether to change the
   * mockup's values is the maintainer's call.
   */
  it.todo("tells the four severities apart by the lightness of their text colour as well");
});

describe("the PDF report", () => {
  it("draws its severity squares in the light theme's fill colours", () => {
    for (const s of SEVERITY_LEVELS) {
      expect(SEVERITY_FILL_HEX[s], s).toBe(THEMES.light.get(`${s}-fill`)?.hex);
      expect(hexOf(rgb("light", `${s}-fill`)), s).toBe(SEVERITY_FILL_HEX[s]);
    }
  });
});

describe("contrast maths", () => {
  it("matches the WCAG reference values", () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([118, 118, 118], [255, 255, 255])).toBeCloseTo(4.54, 2);
    expect(hexOf(oklchToRgb("oklch(1 0 0)"))).toBe("#ffffff");
    expect(hexOf(oklchToRgb("oklch(0 0 0)"))).toBe("#000000");
  });
});
