/**
 * Latest versions of WordPress plugins and themes from wordpress.org (ADR 0042, part 2). Only for organisations that switched the
 * lookup on: their websites' slugs (from the home page's asset addresses) are asked one at a time, at most once a day each, with
 * every other field of the answer switched off. Nothing else is sent: no website name, no version, no organisation. The answers
 * are public data and kept for the whole installation; the daily look of a website judges its plugins and themes against them.
 */
import type { PassiveSnapshot } from "@garnetops/core/exposure";
import {
  parseWordPressOrgVersion,
  WORDPRESS_ORG,
  type WordPressKind,
  wordpressOrgPath,
} from "@garnetops/core/wordpress";
import { schema } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { httpsGet, type Lookup, OutboundError, readCapped } from "./outbound.ts";

export const WORDPRESS_ORG_QUEUE = "websites.wordpress-org";

export type WordPressOrgAnswer = { listed: true; latest: string | null } | { listed: false };
export type WordPressOrgFetch = (kind: WordPressKind, slug: string) => Promise<WordPressOrgAnswer>;

/** The real request. `test` points it at a local server (tests only). */
export function wordpressOrgFetch(test?: { lookup?: Lookup; ca?: string; port?: number }): WordPressOrgFetch {
  return async (kind, slug) => {
    try {
      const response = await httpsGet({
        host: WORDPRESS_ORG.host,
        path: wordpressOrgPath(kind, slug),
        timeoutMs: WORDPRESS_ORG.timeoutMs,
        headers: { accept: "application/json", "user-agent": "GarnetOps-WordPress-Versions/1" },
        ...(test ? { test } : {}),
      });
      const body = await readCapped(response, WORDPRESS_ORG.maxBytes);
      return { listed: true, latest: parseWordPressOrgVersion(body.toString("utf8")) };
    } catch (error) {
      // The directory answers 404 for a slug it does not list (premium and custom plugins).
      if (error instanceof OutboundError && error.code === "httpStatus" && error.status === 404)
        return { listed: false };
      throw error;
    }
  };
}

/** The `kind:slug` keys a snapshot's home page names. */
export function wordpressKeys(passive: unknown): string[] {
  const wp = (passive as PassiveSnapshot | null)?.http?.wordpress;
  if (!wp) return [];
  return [...wp.plugins.map((c) => `plugin:${c.slug}`), ...wp.themes.map((c) => `theme:${c.slug}`)];
}

/** The latest versions known for these keys (only listed ones with a version). */
export async function latestVersions(keys: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (keys.length === 0) return out;
  const w = schema.wordpressComponent;
  const slugs = [...new Set(keys.map((k) => k.slice(k.indexOf(":") + 1)))];
  const rows = await db.select().from(w).where(inArray(w.slug, slugs));
  for (const r of rows) if (r.listed && r.latest) out.set(`${r.kind}:${r.slug}`, r.latest);
  return out;
}

/**
 * One run: the slugs of opted-in organisations' websites whose answer is missing or older than a day, asked one at a time. Returns
 * how many were asked.
 */
export async function refreshWordPressVersions(
  deps: { fetch?: WordPressOrgFetch; now?: () => Date; gapMs?: number } = {},
): Promise<number> {
  const now = deps.now ? deps.now() : new Date();
  const fetch = deps.fetch ?? wordpressOrgFetch();
  const a = schema.exposureAsset;
  const s = schema.exposureSettings;
  const assets = await db
    .select({ passive: a.passive })
    .from(a)
    .innerJoin(
      s,
      and(eq(s.organizationId, a.organizationId), eq(s.enabled, true), eq(s.wordpressOrgEnabled, true)),
    );
  const wanted = new Set(assets.flatMap((x) => wordpressKeys(x.passive)));
  if (wanted.size === 0) return 0;
  const w = schema.wordpressComponent;
  const known = await db.select({ kind: w.kind, slug: w.slug, checkedAt: w.checkedAt }).from(w);
  const fresh = new Set(
    known
      .filter((k) => k.checkedAt.getTime() > now.getTime() - WORDPRESS_ORG.refreshHours * 3600_000)
      .map((k) => `${k.kind}:${k.slug}`),
  );
  const due = [...wanted].filter((k) => !fresh.has(k)).slice(0, WORDPRESS_ORG.perRun);
  const gap = deps.gapMs ?? WORDPRESS_ORG.gapMs;
  for (const [i, key] of due.entries()) {
    if (i > 0 && gap > 0) await new Promise((resolve) => setTimeout(resolve, gap));
    const kind = key.slice(0, key.indexOf(":")) as WordPressKind;
    const slug = key.slice(key.indexOf(":") + 1);
    const checkedAt = deps.now ? deps.now() : new Date();
    try {
      const answer = await fetch(kind, slug);
      const values = {
        listed: answer.listed,
        latest: answer.listed ? answer.latest : null,
        checkedAt,
        error: null,
      };
      await db
        .insert(w)
        .values({ kind, slug, ...values })
        .onConflictDoUpdate({ target: [w.kind, w.slug], set: values });
    } catch (error) {
      const code = error instanceof OutboundError ? error.code : "unreachable";
      // The previous answer stays; the slug is asked again after the usual pause.
      await db
        .insert(w)
        .values({ kind, slug, listed: false, checkedAt, error: code })
        .onConflictDoUpdate({ target: [w.kind, w.slug], set: { checkedAt, error: code } });
    }
  }
  return due.length;
}

export async function startWordPressOrg(boss: PgBoss): Promise<void> {
  await boss.createQueue(WORDPRESS_ORG_QUEUE);
  await boss.schedule(WORDPRESS_ORG_QUEUE, "41 * * * *", null, { tz: "UTC" });
  await boss.work(WORDPRESS_ORG_QUEUE, { batchSize: 1 }, async () => {
    await refreshWordPressVersions().catch((error: Error) => console.error("wordpress.org:", error.name));
  });
}
