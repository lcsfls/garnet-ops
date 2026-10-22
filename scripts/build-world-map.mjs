/**
 * Builds apps/web/src/assets/world-map.ts, the country shapes of the Attacks page, from the
 * Natural Earth 1:110m admin-0 data (public domain) as packaged in world-atlas 2.0.2 (ISC).
 *
 * The map is plain SVG paths in the repository: no tiles, no map library and no request to any
 * server at run time (AGENTS.md rule 3). Run this script only to regenerate the file:
 *
 *   node scripts/build-world-map.mjs
 *
 * Input: the vendored TopoJSON and the vendored d3 and topojson-client builds of the mockup
 * (design/mockup/vendor/js, ISC). They are used here, at build time, and never shipped.
 * Antarctica is left out (no one attacks from there and it wastes a third of the height);
 * countries that Natural Earth does not give an ISO code (N. Cyprus, Somaliland) are left out,
 * Kosovo gets the code the GeoIP data uses (XK). Countries too small for the 110m data (Singapore,
 * Malta, ...) have no shape; the page lists every country in a table as well.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";

const vendor = new URL("../design/mockup/vendor/js/", import.meta.url);
const sandbox = { window: {}, self: {} };
sandbox.self = sandbox;
createContext(sandbox);
for (const file of ["d3.min.js", "topojson-client.min.js", "countries-110m.js"]) {
  runInContext(readFileSync(new URL(file, vendor), "utf8"), sandbox);
}
const { d3, topojson } = sandbox;
const atlas = sandbox.window.WORLD_ATLAS;

/** ISO 3166-1 numeric (as world-atlas uses) to alpha-2. Checked against Intl.DisplayNames below. */
const ALPHA2 = {
  "004": "AF",
  "008": "AL",
  "010": "AQ",
  "012": "DZ",
  "024": "AO",
  "031": "AZ",
  "032": "AR",
  "036": "AU",
  "040": "AT",
  "044": "BS",
  "050": "BD",
  "051": "AM",
  "056": "BE",
  "064": "BT",
  "068": "BO",
  "070": "BA",
  "072": "BW",
  "076": "BR",
  "084": "BZ",
  "090": "SB",
  "096": "BN",
  100: "BG",
  104: "MM",
  108: "BI",
  112: "BY",
  116: "KH",
  120: "CM",
  124: "CA",
  140: "CF",
  144: "LK",
  148: "TD",
  152: "CL",
  156: "CN",
  158: "TW",
  170: "CO",
  178: "CG",
  180: "CD",
  188: "CR",
  191: "HR",
  192: "CU",
  196: "CY",
  203: "CZ",
  204: "BJ",
  208: "DK",
  214: "DO",
  218: "EC",
  222: "SV",
  226: "GQ",
  231: "ET",
  232: "ER",
  233: "EE",
  238: "FK",
  242: "FJ",
  246: "FI",
  250: "FR",
  260: "TF",
  262: "DJ",
  266: "GA",
  268: "GE",
  270: "GM",
  275: "PS",
  276: "DE",
  288: "GH",
  300: "GR",
  304: "GL",
  320: "GT",
  324: "GN",
  328: "GY",
  332: "HT",
  340: "HN",
  348: "HU",
  352: "IS",
  356: "IN",
  360: "ID",
  364: "IR",
  368: "IQ",
  372: "IE",
  376: "IL",
  380: "IT",
  384: "CI",
  388: "JM",
  392: "JP",
  398: "KZ",
  400: "JO",
  404: "KE",
  408: "KP",
  410: "KR",
  414: "KW",
  417: "KG",
  418: "LA",
  422: "LB",
  426: "LS",
  428: "LV",
  430: "LR",
  434: "LY",
  440: "LT",
  442: "LU",
  450: "MG",
  454: "MW",
  458: "MY",
  466: "ML",
  478: "MR",
  484: "MX",
  496: "MN",
  498: "MD",
  499: "ME",
  504: "MA",
  508: "MZ",
  512: "OM",
  516: "NA",
  524: "NP",
  528: "NL",
  540: "NC",
  554: "NZ",
  558: "NI",
  562: "NE",
  566: "NG",
  578: "NO",
  586: "PK",
  591: "PA",
  598: "PG",
  600: "PY",
  604: "PE",
  608: "PH",
  616: "PL",
  620: "PT",
  624: "GW",
  626: "TL",
  630: "PR",
  634: "QA",
  642: "RO",
  643: "RU",
  646: "RW",
  682: "SA",
  686: "SN",
  688: "RS",
  694: "SL",
  703: "SK",
  704: "VN",
  705: "SI",
  706: "SO",
  710: "ZA",
  716: "ZW",
  724: "ES",
  728: "SS",
  729: "SD",
  732: "EH",
  740: "SR",
  748: "SZ",
  752: "SE",
  756: "CH",
  760: "SY",
  762: "TJ",
  764: "TH",
  768: "TG",
  780: "TT",
  784: "AE",
  788: "TN",
  792: "TR",
  795: "TM",
  800: "UG",
  804: "UA",
  807: "MK",
  818: "EG",
  826: "GB",
  834: "TZ",
  840: "US",
  854: "BF",
  858: "UY",
  860: "UZ",
  862: "VE",
  887: "YE",
  894: "ZM",
  548: "VU",
};

const features = topojson.feature(atlas, atlas.objects.countries).features;
const names = new Intl.DisplayNames(["en"], { type: "region" });
const kept = [];
for (const f of features) {
  const name = f.properties.name;
  const code = name === "Kosovo" ? "XK" : ALPHA2[f.id];
  if (!code) {
    if (name !== "N. Cyprus" && name !== "Somaliland") throw new Error(`no ISO code for ${name} (${f.id})`);
    continue;
  }
  if (code === "AQ") continue;
  if (code !== "XK") {
    // A wrong code would paint the wrong country: compare with the platform's own names.
    const expected = names.of(code);
    const a = name.toLowerCase().replace(/[^a-z]/g, "");
    const b = String(expected)
      .toLowerCase()
      .replace(/[^a-z]/g, "");
    const loose = a.slice(0, 4) === b.slice(0, 4) || b.includes(a.slice(0, 5)) || a.includes(b.slice(0, 5));
    if (!loose) console.warn(`check ${code}: atlas says "${name}", platform says "${expected}"`);
  }
  kept.push({ code, name, feature: f });
}

const collection = { type: "FeatureCollection", features: kept.map((k) => k.feature) };
const WIDTH = 960;
const projection = d3.geoNaturalEarth1().fitWidth(WIDTH, collection);
const path = d3.geoPath(projection).digits(1);
const [[, y0], [, y1]] = path.bounds(collection);
const height = Math.ceil(y1 + Math.max(0, y0));
const countries = kept
  .map((k) => ({ code: k.code, name: k.name, d: path(k.feature) }))
  .filter((c) => c.d)
  .sort((a, b) => a.code.localeCompare(b.code));
const unique = new Set(countries.map((c) => c.code));
if (unique.size !== countries.length) throw new Error("duplicate country code");

const out = `/**
 * Generated by scripts/build-world-map.mjs. Do not edit.
 *
 * Country shapes: Natural Earth 1:110m admin-0 (public domain, naturalearthdata.com), packaged by
 * world-atlas 2.0.2 (ISC), Natural Earth projection, one SVG path per country. See NOTICE.md.
 */
export const WORLD_WIDTH = ${WIDTH};
export const WORLD_HEIGHT = ${height};

export interface WorldCountry {
  /** ISO 3166-1 alpha-2, as the GeoIP data uses it (XK for Kosovo). */
  code: string;
  /** English name from Natural Earth; the page shows names in the user's language instead. */
  name: string;
  /** SVG path data. */
  d: string;
}

export const WORLD_COUNTRIES: readonly WorldCountry[] = [
${countries.map((c) => `  ${JSON.stringify(c)},`).join("\n")}
];
`;
writeFileSync(new URL("../apps/web/src/assets/world-map.ts", import.meta.url), out);
console.log(`${countries.length} countries, ${(out.length / 1024).toFixed(0)} KiB, ${WIDTH}x${height}`);
