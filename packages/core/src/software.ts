/**
 * Software a website names about itself (ADR 0038): the `Server` and `X-Powered-By` headers and the `<meta name="generator">` tag of
 * the home page the stage 1 check reads anyway. Each version is judged against the committed end-of-life snapshot
 * (`eol-data.ts`): a release line that no longer gets fixes, or a version behind the latest of its line. Nothing extra is requested,
 * and a site that does not name its software is simply not judged.
 */
import { EOL_DATA, type EolCycle } from "./eol-data.ts";

export type SoftwareProduct =
  | "php"
  | "wordpress"
  | "nginx"
  | "apache-http-server"
  | "drupal"
  | "joomla"
  | "typo3"
  | "mediawiki"
  | "astro";

/** The names the page shows; technical names, the same in every language. */
export const SOFTWARE_NAMES: Record<SoftwareProduct, string> = {
  php: "PHP",
  wordpress: "WordPress",
  nginx: "nginx",
  "apache-http-server": "Apache HTTP Server",
  drupal: "Drupal",
  joomla: "Joomla",
  typo3: "TYPO3",
  mediawiki: "MediaWiki",
  astro: "Astro",
};

export interface DetectedSoftware {
  product: SoftwareProduct;
  version: string;
  source: "server" | "x-powered-by" | "generator";
  /**
   * A header that says the build comes from a distribution ("Apache/2.4.57 (Debian)", "PHP/8.1.2-1ubuntu2.14"). Distributions fix
   * security problems without changing the version, so such a version is shown but not judged.
   */
  distribution?: boolean;
}

/** A distribution named in a header, or its mark right after the version. */
const DISTRIBUTION_NAME =
  /\((?:Debian|Ubuntu|Raspbian|Red Hat|CentOS|Rocky|AlmaLinux|Oracle|Fedora|SUSE|openSUSE|Amazon|Alpine)/i;
const DISTRIBUTION_SUFFIX = /^[-~+.]\S*?(?:deb|ubuntu|el\d|fc\d|suse|amzn)/i;

const VERSION = String.raw`(\d+(?:\.\d+){0,3})`;
const PATTERNS: { source: DetectedSoftware["source"]; product: SoftwareProduct; re: RegExp }[] = [
  { source: "server", product: "nginx", re: new RegExp(String.raw`\bnginx/${VERSION}`, "i") },
  { source: "server", product: "apache-http-server", re: new RegExp(String.raw`\bApache/${VERSION}`) },
  { source: "x-powered-by", product: "php", re: new RegExp(String.raw`\bPHP/${VERSION}`, "i") },
  { source: "server", product: "php", re: new RegExp(String.raw`\bPHP/${VERSION}`, "i") },
  { source: "generator", product: "wordpress", re: new RegExp(`^WordPress ${VERSION}`, "i") },
  { source: "generator", product: "drupal", re: new RegExp(`^Drupal ${VERSION}`, "i") },
  { source: "generator", product: "joomla", re: new RegExp(`^Joomla!?.*?Version ${VERSION}`, "i") },
  { source: "generator", product: "typo3", re: new RegExp(`^TYPO3 ${VERSION}`, "i") },
  { source: "generator", product: "mediawiki", re: new RegExp(`^MediaWiki ${VERSION}`, "i") },
  { source: "generator", product: "astro", re: new RegExp(`^Astro v?${VERSION}`, "i") },
];

/**
 * The `content` of every `<meta name="generator">` in a page, cleaned and cut, at most three. The page is hostile input: only this one
 * attribute is taken, as text.
 */
export function metaGenerators(html: string): string[] {
  const out: string[] = [];
  for (const tag of html.slice(0, 64 * 1024).match(/<meta\b[^>]{0,500}>/gi) ?? []) {
    if (!/\bname\s*=\s*["']?generator["'\s/>]/i.test(tag)) continue;
    const content = /\bcontent\s*=\s*(?:"([^"]{0,300})"|'([^']{0,300})')/i.exec(tag);
    const value = (content?.[1] ?? content?.[2] ?? "")
      .replace(/[\p{Cc}\p{Cf}]/gu, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 120);
    if (value) out.push(value);
    if (out.length === 3) break;
  }
  return out;
}

/** What the headers and generator tags name, one entry per product (the first source wins). */
export function detectSoftware(input: {
  headers?: Record<string, string>;
  generators?: string[];
}): DetectedSoftware[] {
  // Stored snapshots of older versions may lack fields: whatever is missing is simply not looked at.
  const headers = input.headers ?? {};
  const asText = (v: unknown) => (typeof v === "string" && v ? [v] : []);
  const texts: Record<DetectedSoftware["source"], string[]> = {
    server: asText(headers.server),
    "x-powered-by": asText(headers["x-powered-by"]),
    generator: Array.isArray(input.generators) ? input.generators.filter((g) => typeof g === "string") : [],
  };
  const found = new Map<SoftwareProduct, DetectedSoftware>();
  for (const { source, product, re } of PATTERNS) {
    if (found.has(product)) continue;
    for (const text of texts[source]) {
      const m = re.exec(text);
      if (m?.[1]) {
        const after = text.slice((m.index ?? 0) + m[0].length);
        const distribution =
          source !== "generator" && (DISTRIBUTION_NAME.test(text) || DISTRIBUTION_SUFFIX.test(after));
        found.set(product, { product, version: m[1], source, ...(distribution ? { distribution } : {}) });
        break;
      }
    }
  }
  return [...found.values()];
}

/** Compares dotted numeric versions; missing parts count as 0. */
export function compareVersions(a: string, b: string): number {
  const x = a.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const y = b.split(".").map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export interface SoftwareJudgement extends DetectedSoftware {
  /**
   * - `endOfLife`: the release line no longer gets fixes, security fixes included.
   * - `outdated`: a newer version of the same line exists (it may carry security fixes).
   * - `current`: the latest of a supported line.
   * - `unknown`: no end-of-life data for the product, or the version names no line of it.
   * - `distribution`: a distribution's build; its number says nothing about the fixes it carries.
   */
  status: "endOfLife" | "outdated" | "current" | "unknown" | "distribution";
  cycle: string | null;
  /** The end of the line, when it has a date. */
  eol: string | null;
  latest: string | null;
}

/** The release line a version belongs to: the longest cycle that is the version or a prefix of it at a dot. */
function cycleOf(cycles: EolCycle[], version: string): EolCycle | null {
  let best: EolCycle | null = null;
  for (const c of cycles) {
    if (
      (version === c.cycle || version.startsWith(`${c.cycle}.`)) &&
      (!best || c.cycle.length > best.cycle.length)
    )
      best = c;
  }
  return best;
}

/**
 * How serious a judgement is: a CMS names itself exactly, so its version counts fully; a server header can come from a build that
 * was patched without a new number, so it counts one step lower.
 */
export function softwareSeverity(j: SoftwareJudgement): "high" | "medium" | "low" | null {
  const exact = j.source === "generator";
  if (j.status === "endOfLife") return exact ? "high" : "medium";
  if (j.status === "outdated") return exact ? "medium" : "low";
  return null;
}

export function judgeSoftware(found: DetectedSoftware, now: Date, data = EOL_DATA): SoftwareJudgement {
  if (found.distribution) return { ...found, status: "distribution", cycle: null, eol: null, latest: null };
  const cycles = data[found.product];
  const cycle = cycles ? cycleOf(cycles, found.version) : null;
  if (!cycle) return { ...found, status: "unknown", cycle: null, eol: null, latest: null };
  const eolDate = typeof cycle.eol === "string" ? cycle.eol : null;
  const ended =
    cycle.eol === true || (eolDate !== null && Date.parse(`${eolDate}T00:00:00Z`) <= now.getTime());
  const behind =
    cycle.latest !== null &&
    found.version.split(".").length >= cycle.latest.split(".").length &&
    compareVersions(found.version, cycle.latest) < 0;
  return {
    ...found,
    status: ended ? "endOfLife" : behind ? "outdated" : "current",
    cycle: cycle.cycle,
    eol: eolDate,
    latest: cycle.latest,
  };
}
