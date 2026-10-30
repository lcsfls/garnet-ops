/**
 * Availability of websites (ADR 0040): every minute the worker picks the assets whose check is due (their own interval, 1 to 60
 * minutes), sends one HTTPS GET for `/` to a checked public address (the same request stage 1 makes, without reading the page),
 * stores the result and tells people when an asset goes down or comes back. Assets whose availability is off, or whose
 * organisation switched website monitoring off, are never asked.
 */
import { newId } from "@garnetops/core";
import {
  answeredUp,
  nextUptimeState,
  UPTIME_RETENTION_DAYS,
  UPTIME_TIMEOUT_MS,
  type UptimeError,
} from "@garnetops/core/uptime";
import { schema } from "@garnetops/db";
import { and, asc, eq, isNull, lt, or, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { httpGet, type NetEnv, resolveAssetAddresses } from "./exposure-net.ts";
import { publicDnsOf, resolverFor } from "./public-dns.ts";
import { tellUsers } from "./user-notify.ts";

export const UPTIME_QUEUE = "websites.uptime";
/** Checks per tick, and how many run at the same time. */
const PER_TICK = 200;
const PARALLEL = 8;

type Asset = typeof schema.exposureAsset.$inferSelect;

export interface UptimeDeps {
  /** Tests only: the network (fake resolver, local server ports). */
  net?: NetEnv;
  now?: () => Date;
}

/** One check: resolve under the address policy, then one GET of `/` without reading the body. */
export async function checkAvailability(
  env: NetEnv,
  asset: Pick<Asset, "kind" | "value">,
): Promise<{ up: boolean; status: number | null; responseMs: number | null; error: UptimeError | null }> {
  const resolved = await resolveAssetAddresses(env, asset.value);
  if (resolved.addresses.length === 0) {
    return {
      up: false,
      status: null,
      responseMs: null,
      error: resolved.nonPublic.length > 0 ? "address" : "dns",
    };
  }
  const isName = asset.kind !== "ip";
  const started = performance.now();
  const result = await httpGet({
    scheme: "https",
    address: resolved.addresses[0] as string,
    port: env.httpsPort ?? 443,
    host: isName ? asset.value : null,
    path: "/",
    verify: true,
    ca: env.ca,
    timeoutMs: UPTIME_TIMEOUT_MS,
    maxBody: 0,
  });
  const responseMs = Math.round(performance.now() - started);
  if (!result.ok) return { up: false, status: null, responseMs: null, error: result.error };
  const up = answeredUp(result.status);
  return { up, status: result.status, responseMs, error: up ? null : "status" };
}

async function checkOne(asset: Asset, deps: UptimeDeps): Promise<void> {
  const now = deps.now ? deps.now() : new Date();
  const env = deps.net ?? { dns: resolverFor(await publicDnsOf(asset.organizationId)) };
  const result = await checkAvailability(env, asset);
  const next = nextUptimeState({ state: asset.uptimeState, failures: asset.uptimeFailures }, result.up);
  await db.transaction(async (tx) => {
    await tx.insert(schema.exposureUptimeCheck).values({
      id: newId("upt"),
      organizationId: asset.organizationId,
      assetId: asset.id,
      checkedAt: now,
      ...result,
    });
    await tx
      .update(schema.exposureAsset)
      .set({
        uptimeState: next.state,
        uptimeFailures: next.failures,
        uptimeCheckedAt: now,
        ...(next.state !== asset.uptimeState ? { uptimeSince: now } : {}),
      })
      .where(eq(schema.exposureAsset.id, asset.id));
  });
  if (next.changed) {
    await tellUsers({
      organizationId: asset.organizationId,
      titleKey: next.changed === "down" ? "exposureDown" : "exposureUp",
      params: {
        asset: asset.value,
        reason: result.error === "status" ? `HTTP ${result.status}` : (result.error ?? ""),
      },
      link: `/websites/${asset.id}?tab=availability`,
    });
  }
}

/** One tick: the due assets of organisations with website monitoring on, and checks older than the retention removed. */
export async function uptimeTick(deps: UptimeDeps = {}): Promise<number> {
  const now = deps.now ? deps.now() : new Date();
  const a = schema.exposureAsset;
  const due = await db
    .select({ asset: a })
    .from(a)
    .innerJoin(
      schema.exposureSettings,
      and(
        eq(schema.exposureSettings.organizationId, a.organizationId),
        eq(schema.exposureSettings.enabled, true),
      ),
    )
    .where(
      and(
        eq(a.uptimeEnabled, true),
        or(
          isNull(a.uptimeCheckedAt),
          sql`${a.uptimeCheckedAt} + make_interval(mins => ${a.uptimeIntervalMinutes}) <= ${now}`,
        ),
      ),
    )
    .orderBy(asc(a.uptimeCheckedAt))
    .limit(PER_TICK);
  const queue = due.map((d) => d.asset);
  await Promise.all(
    Array.from({ length: Math.min(PARALLEL, queue.length) }, async () => {
      for (let asset = queue.shift(); asset; asset = queue.shift()) {
        await checkOne(asset, deps).catch((error: Error) => console.error(`uptime: ${error.name}`));
      }
    }),
  );
  await db
    .delete(schema.exposureUptimeCheck)
    .where(
      lt(
        schema.exposureUptimeCheck.checkedAt,
        new Date(now.getTime() - UPTIME_RETENTION_DAYS * 24 * 3600_000),
      ),
    );
  return due.length;
}

export async function startUptime(boss: PgBoss): Promise<void> {
  await boss.createQueue(UPTIME_QUEUE);
  await boss.schedule(UPTIME_QUEUE, "* * * * *", null, { tz: "UTC" });
  await boss.work(UPTIME_QUEUE, { batchSize: 1 }, async () => {
    await uptimeTick().catch((error: Error) => console.error("uptime tick:", error.name));
  });
}
