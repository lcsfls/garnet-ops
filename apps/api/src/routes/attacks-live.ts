/**
 * The live attack feed for browsers (ADR 0021): the latest events and a stream of new ones.
 *
 * The worker polls the Wazuh indexer, stores the alerts and announces them with NOTIFY on a channel of the
 * organisation; this file only reads what is stored. Everyone in the organisation reads (the same people who read the
 * Attacks page); every query names the signed-in person's organisation, and a stream listens to the channel of that
 * organisation only. There is no inbound endpoint for Wazuh and nothing here contacts the outside.
 */
import { LIVE_VISIBLE, liveChannel } from "@garnetops/core/attack-live";
import { schema } from "@garnetops/db";
import { and, desc, eq, gt, sql } from "drizzle-orm";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { db } from "../db.ts";
import { liveInfo, viewEvents } from "../lib/attack-live.ts";
import type { AppEnv } from "../lib/context.ts";
import { listenBus } from "../lib/listen-bus.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";

const e = schema.wazuhAttackEvent;

/** Open live streams of one person in this process (several tabs; the same limit as the notification stream). */
export const MAX_LIVE_STREAMS_PER_USER = 4;
const HEARTBEAT_MS = 15_000;
/** A stream ends after this long; the browser reconnects with the last id, which checks the session again. */
const MAX_STREAM_MS = 10 * 60_000;
/** More missed events than this on a reconnect are not replayed one by one: the client reloads the list. */
const MAX_BACKLOG = LIVE_VISIBLE;
const openStreams = new Map<string, number>();

const afterParam = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);

export const attackLiveRoutes = new Hono<AppEnv>()
  /* ------------------------------ the latest events ------------------------------ */
  .get("/events", async (c) => {
    const actor = c.get("actor");
    await rateLimit(`attacks-events:${actor.userId}`, 120);
    const { limit } = z
      .object({ limit: z.coerce.number().int().min(1).max(LIVE_VISIBLE).default(LIVE_VISIBLE) })
      .parse(c.req.query());
    const rows = await db
      .select()
      .from(e)
      .where(eq(e.organizationId, actor.organizationId))
      .orderBy(desc(e.seq))
      .limit(limit);
    return c.json(
      {
        items: await viewEvents(actor.organizationId, rows),
        // The newest sequence number of the organisation: where a stream that opens now starts.
        latestSeq: rows[0]?.seq ?? 0,
        live: await liveInfo(actor.organizationId),
      },
      200,
      { "cache-control": "no-store" },
    );
  })

  /* --------------------------------- the stream --------------------------------- */
  /**
   * Server-sent events with the organisation's new attack events. `ready` comes first (the newest sequence number and
   * the status of the feed), then one `event` per new alert with its sequence number as the event id: a browser that
   * reconnects sends it back as Last-Event-ID (or `?after=`) and gets what it missed, or `resync` when that is too
   * much. `status` follows the heartbeat when the status of the feed changed. The list route stays the source of
   * truth; the stream only saves polling.
   */
  .get("/live", async (c) => {
    const actor = c.get("actor");
    if ((openStreams.get(actor.userId) ?? 0) >= MAX_LIVE_STREAMS_PER_USER) {
      throw new ProblemError(429, "too-many-streams", "Too many open streams");
    }
    const after = afterParam
      .optional()
      .safeParse(c.req.header("last-event-id") || c.req.query("after") || undefined);
    openStreams.set(actor.userId, (openStreams.get(actor.userId) ?? 0) + 1);
    const channel = liveChannel(actor.organizationId);

    const response = streamSSE(
      c,
      async (stream) => {
        let finished = false;
        let finish!: () => void;
        const ended = new Promise<void>((resolve) => {
          finish = resolve;
        });
        let chain: Promise<void> = Promise.resolve();
        const later = (fn: () => Promise<void>) => {
          chain = chain.then(fn).catch(() => {});
        };
        const send = (event: string, data: unknown, id?: number) =>
          stream.writeSSE({ event, data: JSON.stringify(data), ...(id ? { id: String(id) } : {}) });

        let lastSent = after.success && after.data ? after.data : 0;
        /** Notices that arrive before the starting point is known wait for it (the catch-up after `ready` covers them). */
        let started = false;
        let lastStatus = "";

        /** Sends everything newer than the last sequence number sent; too much at once is left to a reload. */
        const catchUp = async () => {
          if (finished || !started) return;
          const rows = await db
            .select()
            .from(e)
            .where(and(eq(e.organizationId, actor.organizationId), gt(e.seq, lastSent)))
            .orderBy(e.seq)
            .limit(MAX_BACKLOG + 1);
          if (rows.length > MAX_BACKLOG) {
            const [latest] = await db
              .select({ seq: sql<number>`max(${e.seq})::bigint` })
              .from(e)
              .where(eq(e.organizationId, actor.organizationId));
            lastSent = Number(latest?.seq ?? lastSent);
            await send("resync", {});
            return;
          }
          const views = await viewEvents(actor.organizationId, rows);
          for (const view of views) {
            lastSent = view.seq;
            await send("event", view, view.seq);
          }
          if (views.length > 0) {
            const live = await liveInfo(actor.organizationId);
            lastStatus = JSON.stringify(live);
            await send("status", live);
          }
        };

        const heartbeat = setInterval(() => {
          stream.write(": keep-alive\n\n").catch(() => {});
          later(async () => {
            const live = await liveInfo(actor.organizationId);
            const text = JSON.stringify(live);
            if (text !== lastStatus) {
              lastStatus = text;
              await send("status", live);
            }
          });
        }, HEARTBEAT_MS);
        const lifetime = setTimeout(() => {
          finished = true;
          finish();
        }, MAX_STREAM_MS);
        stream.onAbort(() => {
          finished = true;
          finish();
        });
        let unsubscribe: (() => void) | null = null;
        try {
          // Listen first, then read the stored state: whatever is written in between is not lost.
          unsubscribe = await listenBus.subscribe(
            channel,
            () => later(catchUp),
            () => later(async () => void (await send("resync", {}))),
          );
          const [latest] = await db
            .select({ seq: sql<number>`coalesce(max(${e.seq}), 0)::bigint` })
            .from(e)
            .where(eq(e.organizationId, actor.organizationId));
          const newest = Number(latest?.seq ?? 0);
          if (!(after.success && after.data)) lastSent = newest;
          if (finished) return;
          const live = await liveInfo(actor.organizationId);
          lastStatus = JSON.stringify(live);
          await send("ready", { latestSeq: newest, live });
          started = true;
          later(catchUp);
          await ended;
          await chain;
        } finally {
          clearInterval(heartbeat);
          clearTimeout(lifetime);
          unsubscribe?.();
          const left = (openStreams.get(actor.userId) ?? 1) - 1;
          if (left <= 0) openStreams.delete(actor.userId);
          else openStreams.set(actor.userId, left);
        }
      },
      async (error) => {
        // Not the message: keep the log free of content.
        console.error("attack stream:", (error as Error)?.name ?? "error");
      },
    );
    response.headers.set("cache-control", "no-store, no-transform");
    response.headers.set("x-accel-buffering", "no");
    return response;
  });
