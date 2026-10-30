/**
 * WordPress plugins and themes as a site shows them from the outside (ADR 0042): the asset addresses of the home page that GarnetOps
 * already reads once a day (`/wp-content/plugins/<slug>/…`, `/wp-content/themes/<slug>/…`). Nothing else is requested. A version
 * comes from the asset's `ver` query parameter, which most plugins set to their own version; WordPress puts its own version there
 * when a plugin names none, so a value equal to the WordPress version is not taken. The page is hostile input: only slugs and
 * version numbers of a fixed shape are kept.
 */

export interface WordPressComponent {
  slug: string;
  /** As the asset addresses say it; null when they name none, or only the WordPress version. */
  version: string | null;
}

export interface WordPressAssets {
  plugins: WordPressComponent[];
  themes: WordPressComponent[];
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
