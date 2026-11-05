#!/usr/bin/env node
/**
 * Fails when a web component brings its own colour instead of a design token (AGENTS.md rule 6: colours come from
 * semantic tokens with fixed values per theme, no alpha overlays of semantic colours, no hard-coded colours in
 * components). Part of `pnpm lint`, so CI runs it.
 *
 * It scans apps/web/src for .svelte and .ts files (not app.css, where the tokens live, and not tests) and reports:
 *   - colour literals: hex values, rgb(), hsl(), hwb(), lab(), lch(), oklab(), oklch(), color-mix()
 *   - Tailwind palette colours (bg-red-500, text-white, border-black, ...)
 *   - opacity modifiers on colour utilities (bg-muted/40, text-critical/80, ...): a lighter or darker step is a token
 *   - colour names retired with the 0.1.1 tokens (text-destructive-text, bg-sidebar-accent, fill-chart-high, ...)
 *
 *   node scripts/check-colours.mjs
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const SOURCE = join(ROOT, "apps/web/src");

/**
 * The only places that may keep a literal colour, each with its reason. Keep this list tiny: anything that is a state,
 * a severity or a surface takes a token from app.css.
 */
const ALLOW = [
  {
    file: "apps/web/src/lib/components/QrCode.svelte",
    match: /^(#000|bg-white)$/,
    reason: "A QR code is black on white in both themes, or phone cameras cannot read it.",
  },
];

const PALETTE =
  "red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone";
const COLOUR_UTILITY =
  "bg|text|border|border-[xytrblse]|ring|ring-offset|outline|fill|stroke|divide|decoration|caret|accent|shadow|placeholder|from|via|to";

const RULES = [
  { name: "hex colour", re: /(?<![\w&{/-])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b/g },
  { name: "colour function", re: /\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(/g },
  { name: "color-mix()", re: /\bcolor-mix\(/g },
  {
    name: "Tailwind palette colour",
    re: new RegExp(`\\b(?:${COLOUR_UTILITY})-(?:(?:${PALETTE})-\\d{2,3}|white|black)\\b`, "g"),
  },
  {
    // Retired with the 0.1.1 tokens: Tailwind would silently drop them, so the element would lose its colour.
    name: "retired colour token",
    re: new RegExp(
      `\\b(?:${COLOUR_UTILITY})-(?:destructive|warning|primary-text|sidebar-accent|sidebar-hover|chart-[a-z]+|(?:high|info|success)-text)\\b`,
      "g",
    ),
  },
  {
    name: "opacity modifier on a colour",
    // text-sm/6 and the like set a line height, not an opacity.
    re: new RegExp(
      `\\b(?:${COLOUR_UTILITY})-(?!(?:xs|sm|base|lg|\\d?xl)\\/)[a-z][a-z0-9-]*\\/(?:\\d+|\\[[^\\]]+\\])`,
      "g",
    ),
  },
];

function* files(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* files(path);
    else if (/\.(svelte|ts)$/.test(entry.name) && !/\.test\.ts$/.test(entry.name)) yield path;
  }
}

const problems = [];
for (const path of files(SOURCE)) {
  const file = relative(ROOT, path).split(sep).join("/");
  const lines = readFileSync(path, "utf8").split("\n");
  lines.forEach((line, i) => {
    for (const rule of RULES) {
      for (const m of line.matchAll(rule.re)) {
        const allowed = ALLOW.some((a) => a.file === file && a.match.test(m[0]));
        if (!allowed) problems.push(`${file}:${i + 1}:${m.index + 1}  ${rule.name}: ${m[0]}`);
      }
    }
  });
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  console.error(
    `\n${problems.length} hard-coded colour(s). Use a token from apps/web/src/app.css (AGENTS.md rule 6); ` +
      "a missing step or state gets its own token there, tested in lib/contrast.test.ts.",
  );
  process.exit(1);
}
console.log("check-colours: no hard-coded colours in apps/web/src.");
