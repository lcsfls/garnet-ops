/**
 * Advisories from the Wordfence Intelligence feed (ADR 0042, part 3), with each organisation's own API key. Once a day, and right
 * after a key is set, the worker downloads the feed, keeps only the advisories for the plugins, themes and WordPress versions the
 * organisation's websites show, and replaces that organisation's stored advisories with them. The key is opened only here and sent
 * only to the feed's host; the request carries nothing else of the organisation. The daily look of a website judges its versions
 * against the stored advisories.
 */
import type { PassiveSnapshot } from "@garnetops/core/exposure";
import { detectSoftware } from "@garnetops/core/software";
import { parseWordfenceFeed, WORDFENCE, type WordPressAdvisory } from "@garnetops/core/wordpress";
import { schema } from "@garnetops/db";
import { and, eq, isNotNull, isNull, lt, or } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { httpsGet, type Lookup, OutboundError, readCapped } from "./outbound.ts";
import { openSecretText } from "./vault-secrets.ts";
import { wordpressKeys } from "./wordpress-org.ts";

export const WORDFENCE_QUEUE = "websites.wordfence";

/** Why a download failed, as stored and shown. */
export type WordfenceError =
  | "unauthorized"
  | "rateLimited"
  | "unreachable"
  | "timeout"
  | "tooLarge"
  | "invalid"
  | "noKey";

export type WordfenceFetch = (key: string) => Promise<unknown>;

/** The real download. `test` points it at a local server (tests only). */
export function wordfenceFetch(test?: { lookup?: Lookup; ca?: string; port?: number }): WordfenceFetch {
  return async (key) => {
    const response = await httpsGet({
      host: WORDFENCE.host,
      path: WORDFENCE.path,
      timeoutMs: WORDFENCE.timeoutMs,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${key}`,
        "user-agent": "GarnetOps-Wordfence-Feed/1",
      },
      ...(test ? { test } : {}),
    });
    const body = await readCapped(response, WORDFENCE.maxBytes);
    return JSON.parse(body.toString("utf8"));
  };
}

function errorCode(error: unknown): WordfenceError {
  if (error instanceof SyntaxError) return "invalid";
  if (error instanceof OutboundError) {
    if (error.code === "httpStatus" && (error.status === 401 || error.status === 403)) return "unauthorized";
    if (error.code === "httpStatus" && error.status === 429) return "rateLimited";
    if (error.code === "timeout") return "timeout";
    if (error.code === "tooLarge") return "tooLarge";
  }
  return "unreachable";
}

/** The `kind:slug` keys an organisation's websites show: their plugins and themes, and WordPress itself where it names itself. */
async function wantedKeys(organizationId: string): Promise<Set<string>> {
  const a = schema.exposureAsset;
  const rows = await db.select({ passive: a.passive }).from(a).where(eq(a.organizationId, organizationId));
  const keys = new Set<string>();
  for (const { passive } of rows) {
    for (const k of wordpressKeys(passive)) keys.add(k);
    const http = (passive as PassiveSnapshot | null)?.http;
    if (http && detectSoftware(http).some((d) => d.product === "wordpress")) keys.add("core:wordpress");
  }
  return keys;
}

/** One download for one organisation. Never throws; the outcome is stored on its settings. */
export async function syncWordfence(
  organizationId: string,
  deps: { fetch?: WordfenceFetch; now?: () => Date } = {},
): Promise<{ advisories: number } | { error: WordfenceError }> {
  const s = schema.exposureSettings;
  const now = deps.now ? deps.now() : new Date();
  const [settings] = await db.select().from(s).where(eq(s.organizationId, organizationId)).limit(1);
  if (!settings?.enabled || !settings.wordfenceSecretId) return { error: "noKey" };
  const key = await openSecretText(settings.wordfenceSecretId, organizationId, "wordfence-api-key");
  const fail = async (code: WordfenceError) => {
    await db
      .update(s)
      .set({ wordfenceSyncedAt: now, wordfenceError: code })
      .where(eq(s.organizationId, organizationId));
    return { error: code };
  };
  if (!key) return fail("noKey");
  let feed: unknown;
  try {
    feed = await (deps.fetch ?? wordfenceFetch())(key);
  } catch (error) {
    console.error(`wordfence: ${(error as Error)?.name ?? "error"}`);
    return fail(errorCode(error));
  }
  if (!feed || typeof feed !== "object" || Array.isArray(feed)) return fail("invalid");
  const advisories = parseWordfenceFeed(feed, await wantedKeys(organizationId));
  const w = schema.wordpressAdvisory;
  await db.transaction(async (tx) => {
    await tx.delete(w).where(eq(w.organizationId, organizationId));
    for (let i = 0; i < advisories.length; i += 500) {
      await tx
        .insert(w)
        .values(advisories.slice(i, i + 500).map((a) => ({ organizationId, ...a })))
        .onConflictDoNothing();
    }
    await tx
      .update(s)
      .set({ wordfenceSyncedAt: now, wordfenceError: null, wordfenceAdvisories: advisories.length })
      .where(eq(s.organizationId, organizationId));
  });
  return { advisories: advisories.length };
}

/** The stored advisories of an organisation by `kind:slug`. */
export async function wordfenceAdvisories(organizationId: string): Promise<Map<string, WordPressAdvisory[]>> {
  const w = schema.wordpressAdvisory;
  const rows = await db.select().from(w).where(eq(w.organizationId, organizationId));
  const out = new Map<string, WordPressAdvisory[]>();
  for (const { organizationId: _, ...a } of rows) {
    const key = `${a.kind}:${a.slug}`;
    out.set(key, [...(out.get(key) ?? []), a]);
  }
  return out;
}

/** The organisations whose download is due: a key is set, the module is on, and the last one is a day old or missing. */
export async function dueWordfence(now = new Date()): Promise<string[]> {
  const s = schema.exposureSettings;
  const rows = await db
    .select({ organizationId: s.organizationId })
    .from(s)
    .where(
      and(
        eq(s.enabled, true),
        isNotNull(s.wordfenceSecretId),
        or(
          isNull(s.wordfenceSyncedAt),
          lt(s.wordfenceSyncedAt, new Date(now.getTime() - WORDFENCE.refreshHours * 3600_000)),
        ),
      ),
    );
  return rows.map((r) => r.organizationId);
}

export async function startWordfence(boss: PgBoss): Promise<void> {
  await boss.createQueue(WORDFENCE_QUEUE);
  // Every hour the due organisations; the API also sends a job with the organisation right after a key is set.
  await boss.schedule(WORDFENCE_QUEUE, "53 * * * *", null, { tz: "UTC" });
  await boss.work<{ organizationId?: string } | null>(WORDFENCE_QUEUE, { batchSize: 1 }, async ([job]) => {
    const organizations = job?.data?.organizationId ? [job.data.organizationId] : await dueWordfence();
    for (const organizationId of organizations) await syncWordfence(organizationId);
  });
}
