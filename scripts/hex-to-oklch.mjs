#!/usr/bin/env node
/**
 * Converts sRGB hex colours to CSS oklch() values for the design tokens in apps/web/src/app.css (AGENTS.md rule 6:
 * tokens in OKLCH). The values are rounded only as far as the round trip still gives the same 8-bit sRGB colour, which
 * the script checks for every colour, so a token written from its output is exactly the hex value next to it.
 *
 *   node scripts/hex-to-oklch.mjs "#7a1f33" "#e8798d"
 */

const toLinear = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const toGamma = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);

/** OKLab from linear sRGB (Björn Ottosson's matrices). */
function linearToOklab([r, g, b]) {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ];
}

function oklabToLinear([L, a, b]) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
}

function parseHex(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex);
  if (!m) throw new Error(`not a six-digit hex colour: ${hex}`);
  return [0, 2, 4].map((i) => Number.parseInt(m[1].slice(i, i + 2), 16));
}

function oklchToHex(L, C, H) {
  const h = (H * Math.PI) / 180;
  const rgb = oklabToLinear([L, C * Math.cos(h), C * Math.sin(h)]).map((c) =>
    Math.round(Math.min(1, Math.max(0, toGamma(c))) * 255),
  );
  return `#${rgb.map((c) => c.toString(16).padStart(2, "0")).join("")}`;
}

/** The shortest oklch() (4 decimals for L and C, 2 for the hue at most) whose round trip gives the same hex colour. */
export function hexToOklch(hex) {
  const target = `#${parseHex(hex)
    .map((c) => c.toString(16).padStart(2, "0"))
    .join("")}`;
  const [L, a, b] = linearToOklab(parseHex(hex).map((c) => toLinear(c / 255)));
  const C = Math.hypot(a, b);
  const H = C < 1e-4 ? 0 : ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360;
  for (const digits of [3, 4, 5]) {
    const l = Number(L.toFixed(digits));
    const c = C < 1e-4 ? 0 : Number(C.toFixed(digits));
    const hue = c === 0 ? 0 : Number(H.toFixed(Math.max(1, digits - 2)));
    if (oklchToHex(l, c, hue) === target) return { css: `oklch(${l} ${c} ${hue})`, l, c, h: hue };
  }
  throw new Error(`no round trip for ${hex}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const colours = process.argv.slice(2);
  if (colours.length === 0) {
    console.error('usage: node scripts/hex-to-oklch.mjs "#rrggbb" ...');
    process.exit(2);
  }
  for (const hex of colours) console.log(`${hex.toLowerCase()}  ${hexToOklch(hex).css}`);
}
