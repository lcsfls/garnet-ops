/**
 * WordPress plugins and themes as a site shows them from the outside (ADR 0042): the asset addresses of the home page that GarnetOps
 * already reads once a day (`/wp-content/plugins/<slug>/…`, `/wp-content/themes/<slug>/…`). Nothing else is requested. A version
 * comes from the asset's `ver` query parameter, which most plugins set to their own version; WordPress puts its own version there
 * when a plugin names none, so a value equal to the WordPress version is not taken. The page is hostile input: only slugs and
 * version numbers of a fixed shape are kept.
 */
import { compareVersions } from "./software.ts";

export interface WordPressComponent {
  slug: string;
  /** As the asset addresses say it; null when they name none, or only the WordPress version. */
  version: string | null;
  /** Only from the GarnetOps plugin (part 4): whether it is switched on. */
  active?: boolean;
}

export interface WordPressAssets {
  plugins: WordPressComponent[];
  themes: WordPressComponent[];
  /** Where the list comes from: the home page's asset addresses (absent before part 4), or the GarnetOps plugin's exact list. */
  source?: "assets" | "plugin";
}

/** At most this many of each are kept. */
export const WORDPRESS_LIMITS = { plugins: 60, themes: 5 } as const;

const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const VERSION = /^\d{1,6}(?:\.\d{1,6}){0,3}(?:[-.]?[a-z0-9]{1,10})?$/i;

/** The plugins and themes the asset addresses of a page name, by slug, with the version most of their addresses carry. */
export function wordpressAssets(html: string, wordpressVersion?: string | null): WordPressAssets | null {
  const seen = {
    plugins: new Map<string, Map<string, number>>(),
    themes: new Map<string, Map<string, number>>(),
  };
  const re = /\/wp-content\/(plugins|themes)\/([^/"'\s?#<>]{1,80})\/[^"'\s<>]{0,300}/gi;
  for (const m of html.slice(0, 256 * 1024).matchAll(re)) {
    const kind = (m[1] as string).toLowerCase() as "plugins" | "themes";
    const slug = (m[2] as string).toLowerCase();
    if (!SLUG.test(slug)) continue;
    const list = seen[kind];
    if (!list.has(slug)) {
      if (list.size >= WORDPRESS_LIMITS[kind]) continue;
      list.set(slug, new Map());
    }
    const query = /[?&](?:amp;)?ver=([^&"'\s<>#]{1,30})/i.exec(m[0]);
    const version = query?.[1] ? decodeURIComponentSafe(query[1]) : null;
    if (version && VERSION.test(version) && version !== wordpressVersion) {
      const counts = list.get(slug) as Map<string, number>;
      counts.set(version, (counts.get(version) ?? 0) + 1);
    }
  }
  const pick = (list: Map<string, Map<string, number>>): WordPressComponent[] =>
    [...list.entries()]
      .map(([slug, counts]) => ({
        slug,
        version:
          [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ?? null,
      }))
      .sort((a, b) => a.slug.localeCompare(b.slug));
  const plugins = pick(seen.plugins);
  const themes = pick(seen.themes);
  return plugins.length || themes.length ? { plugins, themes } : null;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/* -------------------------------------------------------------------------- */
/* Latest versions from wordpress.org (ADR 0042, part 2, opt-in)               */
/* -------------------------------------------------------------------------- */

export type WordPressKind = "plugin" | "theme";

/** The wordpress.org directory, the only host asked, and what it is asked: one slug per request, no other data. */
export const WORDPRESS_ORG = {
  host: "api.wordpress.org",
  timeoutMs: 15_000,
  maxBytes: 256 * 1024,
  /** A slug is asked again after this long. */
  refreshHours: 24,
  /** Requests per run, one at a time with a pause in between. */
  perRun: 200,
  gapMs: 1_000,
} as const;

const NOT_NEEDED = [
  "sections",
  "description",
  "short_description",
  "reviews",
  "banners",
  "icons",
  "screenshots",
  "versions",
  "contributors",
  "ratings",
  "tags",
  "compatibility",
  "donate_link",
  "downloadlink",
];

/** The path of the information request for one plugin or theme; everything but the version is switched off. */
export function wordpressOrgPath(kind: WordPressKind, slug: string): string {
  if (!SLUG.test(slug)) throw new Error("invalid slug");
  const fields = NOT_NEEDED.map((f) => `request[fields][${f}]=0`).join("&");
  return kind === "plugin"
    ? `/plugins/info/1.2/?action=plugin_information&request[slug]=${slug}&${fields}`
    : `/themes/info/1.2/?action=theme_information&request[slug]=${slug}&${fields}`;
}

/** The latest version in a directory answer, or null when the answer names none of a valid shape. */
export function parseWordPressOrgVersion(body: string): string | null {
  try {
    const value = (JSON.parse(body) as { version?: unknown })?.version;
    return typeof value === "string" && VERSION.test(value) ? value : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Advisories from the Wordfence Intelligence feed (ADR 0042, part 3)          */
/* -------------------------------------------------------------------------- */

/** The feed, asked once a day with the organisation's own API key. */
export const WORDFENCE = {
  host: "www.wordfence.com",
  path: "/api/intelligence/v3/vulnerabilities/production",
  timeoutMs: 300_000,
  /** The production feed is large; a larger answer is refused, not read. */
  maxBytes: 400 * 1024 * 1024,
  refreshHours: 24,
  /** Keys as Wordfence issues them: printable, no spaces. */
  keyPattern: /^[A-Za-z0-9._~+/=-]{20,200}$/,
} as const;

export type AdvisoryKind = WordPressKind | "core";
export type AdvisorySeverity = "critical" | "high" | "medium" | "low";

export interface VersionRange {
  /** "*" for no lower bound. */
  from: string;
  fromInclusive: boolean;
  to: string;
  toInclusive: boolean;
}

export interface WordPressAdvisory {
  id: string;
  kind: AdvisoryKind;
  slug: string;
  title: string;
  cve: string | null;
  cvssScore: number | null;
  severity: AdvisorySeverity;
  affected: VersionRange[];
  patched: string[];
  published: string | null;
}

const clean = (value: unknown, max: number) =>
  typeof value === "string"
    ? value
        .replace(/[\p{Cc}\p{Cf}]/gu, "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, max)
    : "";
const version = (value: unknown) => {
  const v = clean(value, 30);
  return v === "*" || VERSION.test(v) ? v : null;
};

function severityOf(rating: unknown, score: number | null): AdvisorySeverity {
  const r = typeof rating === "string" ? rating.toLowerCase() : "";
  if (r === "critical" || r === "high" || r === "medium" || r === "low") return r;
  if (score === null) return "medium";
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

/**
 * The advisories of a feed answer (an object of records by id) for the wanted `kind:slug` keys. The feed is outside data: every
 * field is checked for its shape and cut; a record that does not fit is skipped, never stored as it came.
 */
export function parseWordfenceFeed(feed: unknown, wanted: ReadonlySet<string>): WordPressAdvisory[] {
  if (!feed || typeof feed !== "object") return [];
  const out: WordPressAdvisory[] = [];
  for (const record of Object.values(feed as Record<string, unknown>)) {
    if (!record || typeof record !== "object") continue;
    const r = record as Record<string, unknown>;
    if (r.informational === true) continue;
    const id = clean(r.id, 64);
    if (!/^[A-Za-z0-9-]{8,64}$/.test(id) || !Array.isArray(r.software)) continue;
    const cvss = (r.cvss ?? {}) as Record<string, unknown>;
    const score = typeof cvss.score === "number" && cvss.score >= 0 && cvss.score <= 10 ? cvss.score : null;
    const cve = clean(r.cve, 30);
    for (const s of r.software as Record<string, unknown>[]) {
      const kind = s?.type;
      const slug = clean(s?.slug, 64).toLowerCase();
      if ((kind !== "plugin" && kind !== "theme" && kind !== "core") || !SLUG.test(slug)) continue;
      if (!wanted.has(`${kind}:${slug}`)) continue;
      const affected: VersionRange[] = [];
      for (const range of Object.values(
        (s.affected_versions ?? {}) as Record<string, Record<string, unknown>>,
      )) {
        const from = version(range?.from_version);
        const to = version(range?.to_version);
        if (!from || !to) continue;
        affected.push({
          from,
          fromInclusive: range.from_inclusive !== false,
          to,
          toInclusive: range.to_inclusive !== false,
        });
      }
      if (affected.length === 0) continue;
      out.push({
        id,
        kind,
        slug,
        title: clean(r.title, 300),
        cve: /^CVE-\d{4}-\d{4,7}$/.test(cve) ? cve : null,
        cvssScore: score,
        severity: severityOf(cvss.rating, score),
        affected: affected.slice(0, 20),
        patched: (Array.isArray(s.patched_versions) ? s.patched_versions : [])
          .map(version)
          .filter((v): v is string => v !== null && v !== "*")
          .slice(0, 10),
        published: /^\d{4}-\d{2}-\d{2}/.test(clean(r.published, 30)) ? clean(r.published, 10) : null,
      });
    }
  }
  return out;
}

/** Whether a version lies in one of an advisory's ranges. */
export function affectsVersion(advisory: Pick<WordPressAdvisory, "affected">, v: string): boolean {
  return advisory.affected.some((r) => {
    const above =
      r.from === "*" || (r.fromInclusive ? compareVersions(v, r.from) >= 0 : compareVersions(v, r.from) > 0);
    const below =
      r.to === "*" || (r.toInclusive ? compareVersions(v, r.to) <= 0 : compareVersions(v, r.to) < 0);
    return above && below;
  });
}

/* -------------------------------------------------------------------------- */
/* The GarnetOps WordPress plugin (ADR 0042, part 4)                           */
/* -------------------------------------------------------------------------- */

/** Where GarnetOps reads the plugin's inventory; works with and without pretty permalinks. */
export const WORDPRESS_PLUGIN = {
  path: "/?rest_route=/garnetops/v1/inventory",
  maxBytes: 512 * 1024,
  /** The plugin's answer format GarnetOps knows. */
  schema: 1,
  limits: { plugins: 500, themes: 50 },
} as const;

export interface WordPressInventory {
  pluginVersion: string;
  wordpress: string | null;
  php: string | null;
  assets: WordPressAssets;
}

/**
 * The plugin's answer, checked field by field: the site is outside data, so only slugs and versions of a fixed shape are kept, and
 * an answer in another format or with too much in it is refused (null).
 */
export function parseWordPressInventory(body: string): WordPressInventory | null {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(body) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (
    !data ||
    typeof data !== "object" ||
    data.schema !== WORDPRESS_PLUGIN.schema ||
    data.plugin !== "garnetops"
  )
    return null;
  const v = (value: unknown) => (typeof value === "string" && VERSION.test(value) ? value : null);
  const list = (value: unknown, max: number): WordPressComponent[] | null => {
    if (!Array.isArray(value) || value.length > max) return null;
    const out: WordPressComponent[] = [];
    for (const item of value as Record<string, unknown>[]) {
      const slug = typeof item?.slug === "string" ? item.slug.toLowerCase() : "";
      if (!SLUG.test(slug)) continue;
      out.push({ slug, version: v(item.version), active: item.active === true });
    }
    return out.sort((a, b) => a.slug.localeCompare(b.slug));
  };
  const plugins = list(data.plugins, WORDPRESS_PLUGIN.limits.plugins);
  const themes = list(data.themes, WORDPRESS_PLUGIN.limits.themes);
  if (!plugins || !themes) return null;
  return {
    pluginVersion: v(data.pluginVersion) ?? "unknown",
    wordpress: v(data.wordpress),
    php: v(data.php),
    assets: { plugins, themes, source: "plugin" },
  };
}
