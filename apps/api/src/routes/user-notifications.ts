import {
  EVENT_CATALOG,
  EVENT_GROUPS,
  type Preference,
  preferenceEvents,
  resolvePreference,
  SCOPES,
  USER_EVENTS,
  type UserEvent,
} from "@garnetops/core/user-notifications";
import { mailChannelAvailable, schema } from "@garnetops/db";
import { and, desc, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { db } from "../db.ts";
import { type AppEnv, isAdmin } from "../lib/context.ts";
import { modulesOf } from "../lib/modules.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { userNotificationBus } from "../lib/user-notification-bus.ts";

const n = schema.userNotification;

/** Open notification streams of one person in this process (several tabs; ADR 0019). */
export const MAX_NOTIFICATION_STREAMS_PER_USER = 4;
const HEARTBEAT_MS = 15_000;
/** A stream ends after this long; the browser reconnects with the last id, which checks the session again. */
const MAX_STREAM_MS = 10 * 60_000;
/** More missed notifications than this on a reconnect are not replayed one by one: the client reloads the list. */
const MAX_BACKLOG = 50;
const PAGE_SIZE = 30;
const UNREAD_CAP = 1000;
const openStreams = new Map<string, number>();

/** What the list and the stream show of a notification: the key and the facts, no free text. */
const view = (row: typeof n.$inferSelect) => ({
  id: row.id,
  event: row.event,
  titleKey: row.titleKey,
  params: row.params,
  link: row.link,
  createdAt: row.createdAt.toISOString(),
  readAt: row.readAt?.toISOString() ?? null,
});

const idParam = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);

async function unreadCount(userId: string, organizationId: string): Promise<number> {
  const [row] = await db
    .execute<{ count: number }>(sql`
    select count(*)::int as count from (
      select 1 from user_notification
      where user_id = ${userId} and organization_id = ${organizationId} and in_app and read_at is null
      limit ${UNREAD_CAP}
    ) unread`)
    .then((r) => r.rows);
  return row?.count ?? 0;
}

const mine = (userId: string, organizationId: string) =>
  and(eq(n.userId, userId), eq(n.organizationId, organizationId), eq(n.inApp, true));

const preferencesBody = z.object({
  preferences: z
    .array(
      z.object({
        event: z.enum(USER_EVENTS),
        inApp: z.boolean(),
        email: z.boolean(),
        scope: z.enum(SCOPES),
      }),
    )
    .min(1)
    .max(USER_EVENTS.length),
});

/**
 * A person's own notifications (ADR 0019): the list, marking as read, the live stream and the
 * matrix of what they receive. Every query names the signed-in person and their organisation;
 * there is no way to ask for anyone else's.
 */
export const userNotificationRoutes = new Hono<AppEnv>()
  .get("/notifications", async (c) => {
    const actor = c.get("actor");
    const query = z
      .object({
        before: idParam.optional(),
        limit: z.coerce.number().int().min(1).max(100).default(PAGE_SIZE),
        unread: z.enum(["1"]).optional(),
      })
      .parse(c.req.query());
    const rows = await db
      .select()
      .from(n)
      .where(
        and(
          mine(actor.userId, actor.organizationId),
          query.before ? lt(n.id, query.before) : undefined,
          query.unread ? isNull(n.readAt) : undefined,
        ),
      )
      .orderBy(desc(n.id))
      .limit(query.limit + 1);
    const items = rows.slice(0, query.limit);
    return c.json(
      {
        items: items.map(view),
        unread: await unreadCount(actor.userId, actor.organizationId),
        next: rows.length > query.limit ? (items.at(-1)?.id ?? null) : null,
      },
      200,
      { "cache-control": "no-store" },
    );
  })

  .post("/notifications/read-all", async (c) => {
    const actor = c.get("actor");
    await rateLimit(`notifications:${actor.userId}`, 60);
    const body = z.object({ upTo: idParam.optional() }).parse(await c.req.json().catch(() => ({})));
    const updated = await db
      .update(n)
      .set({ readAt: sql`now()` })
      .where(
        and(
          mine(actor.userId, actor.organizationId),
          isNull(n.readAt),
          // The newest id the person has seen, so a notification that arrived since stays unread.
          body.upTo ? sql`${n.id} <= ${body.upTo}` : undefined,
        ),
      )
      .returning({ id: n.id });
    return c.json({ updated: updated.length });
  })

  .post("/notifications/:id/read", async (c) => {
    const actor = c.get("actor");
    await rateLimit(`notifications:${actor.userId}`, 60);
    const parsed = idParam.safeParse(c.req.param("id"));
    if (!parsed.success) throw notFound("Notification");
    const [row] = await db
      .update(n)
      .set({ readAt: sql`coalesce(${n.readAt}, now())` })
      .where(and(eq(n.id, parsed.data), mine(actor.userId, actor.organizationId)))
      .returning({ id: n.id });
    if (!row) throw notFound("Notification");
    return c.body(null, 204);
  })

  /* --------------------------------- stream --------------------------------- */
  /**
   * Server-sent events with the signed-in person's new notifications. `ready` comes first (the
   * unread count and the newest id), then one `notification` event per new row, with the row's id
   * as the event id: a browser that reconnects sends it back as Last-Event-ID (or `?after=`) and
   * gets what it missed, or `resync` when that is too much. Heartbeats keep proxies from closing
   * an idle stream. The list route stays the source of truth; the stream only saves a poll.
   */
  .get("/notifications/stream", async (c) => {
    const actor = c.get("actor");
    if ((openStreams.get(actor.userId) ?? 0) >= MAX_NOTIFICATION_STREAMS_PER_USER) {
      throw new ProblemError(429, "too-many-streams", "Too many open streams");
    }
    const after = idParam
      .optional()
      .safeParse(c.req.header("last-event-id") || c.req.query("after") || undefined);
    openStreams.set(actor.userId, (openStreams.get(actor.userId) ?? 0) + 1);

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

        let newest = 0;
        let lastSent = after.success && after.data ? after.data : 0;
        /** Notices that arrive before the starting point is known wait for it (the catch-up after `ready` covers them). */
        let started = false;

        /** Sends everything newer than the last id sent; too much at once is left to a reload. */
        const catchUp = async () => {
          if (finished || !started) return;
          const rows = await db
            .select()
            .from(n)
            .where(and(mine(actor.userId, actor.organizationId), gt(n.id, lastSent)))
            .orderBy(n.id)
            .limit(MAX_BACKLOG + 1);
          if (rows.length > MAX_BACKLOG) {
            const [latest] = await db
              .select({ id: sql<number>`max(${n.id})::int` })
              .from(n)
              .where(mine(actor.userId, actor.organizationId));
            lastSent = latest?.id ?? lastSent;
            await send("resync", {});
            return;
          }
          for (const row of rows) {
            lastSent = row.id;
            await send("notification", view(row), row.id);
          }
        };

        const heartbeat = setInterval(() => {
          stream.write(": keep-alive\n\n").catch(() => {});
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
          unsubscribe = await userNotificationBus.subscribe(
            actor.userId,
            () => later(catchUp),
            () => later(async () => void (await send("resync", {}))),
          );
          const [latest] = await db
            .select({ id: sql<number>`coalesce(max(${n.id}), 0)::int` })
            .from(n)
            .where(mine(actor.userId, actor.organizationId));
          newest = latest?.id ?? 0;
          if (!(after.success && after.data)) lastSent = newest;
          if (finished) return;
          await send("ready", {
            unread: await unreadCount(actor.userId, actor.organizationId),
            latestId: newest,
          });
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
        console.error("notification stream:", (error as Error)?.name ?? "error");
      },
    );
    response.headers.set("cache-control", "no-store, no-transform");
    response.headers.set("x-accel-buffering", "no");
    return response;
  })

  /* ------------------------------- preferences ------------------------------ */
  .get("/notification-preferences", async (c) => {
    const actor = c.get("actor");
    return c.json(
      await preferencesView(actor.userId, actor.organizationId, actor.role, actor.email, isAdmin(actor)),
    );
  })

  .put("/notification-preferences", async (c) => {
    const actor = c.get("actor");
    await rateLimit(`notification-preferences:${actor.userId}`, 30);
    const input = preferencesBody.parse(await c.req.json());
    const allowed = new Set<UserEvent>(preferenceEvents(actor.role));
    const seen = new Set<string>();
    const mailAvailable = await mailChannelAvailable(db, actor.organizationId);
    const errors: { path: string; message: string }[] = [];
    input.preferences.forEach((p, i) => {
      if (!allowed.has(p.event) || seen.has(p.event)) {
        errors.push({ path: `preferences.${i}.event`, message: "This event is not available to you" });
      }
      seen.add(p.event);
      if (p.email && !mailAvailable) {
        errors.push({ path: `preferences.${i}.email`, message: "Your organisation has no mail channel" });
      }
    });
    if (errors.length > 0) {
      throw new ProblemError(422, "validation", "The request is not valid", undefined, { errors });
    }
    await db.transaction(async (tx) => {
      for (const p of input.preferences) {
        // A scope only exists for events that can be limited; the others are always "all".
        const scope = EVENT_CATALOG[p.event].scoped ? p.scope : "all";
        await tx
          .insert(schema.notificationPreference)
          .values({
            organizationId: actor.organizationId,
            userId: actor.userId,
            event: p.event,
            inApp: p.inApp,
            email: p.email,
            scope,
          })
          .onConflictDoUpdate({
            target: [
              schema.notificationPreference.organizationId,
              schema.notificationPreference.userId,
              schema.notificationPreference.event,
            ],
            set: { inApp: p.inApp, email: p.email, scope, updatedAt: sql`now()` },
          });
      }
    });
    // Preference changes are not audited: they are personal, change nothing for anyone else, and
    // mail only ever goes to the person's own sign-in address (ADR 0019).
    return c.body(null, 204);
  });

async function preferencesView(
  userId: string,
  organizationId: string,
  role: Parameters<typeof preferenceEvents>[0],
  email: string,
  canManageChannels: boolean,
) {
  const mailAvailable = await mailChannelAvailable(db, organizationId);
  const stored = await db
    .select()
    .from(schema.notificationPreference)
    .where(
      and(
        eq(schema.notificationPreference.organizationId, organizationId),
        eq(schema.notificationPreference.userId, userId),
      ),
    );
  const byEvent = new Map<string, Partial<Preference>>(
    stored.map((p) => [p.event, { inApp: p.inApp, email: p.email, scope: p.scope }]),
  );
  // Events of a module that is switched off are not listed (ADR 0033).
  const modules = await modulesOf(organizationId);
  const events = preferenceEvents(role)
    .filter((event) => {
      const module = EVENT_CATALOG[event].module;
      return !module || modules[module];
    })
    .sort(
      (a, b) =>
        EVENT_GROUPS.indexOf(EVENT_CATALOG[a].group) - EVENT_GROUPS.indexOf(EVENT_CATALOG[b].group) ||
        USER_EVENTS.indexOf(a) - USER_EVENTS.indexOf(b),
    )
    .map((event) => {
      const preference = resolvePreference(event, byEvent.get(event));
      return {
        event,
        group: EVENT_CATALOG[event].group,
        scoped: EVENT_CATALOG[event].scoped,
        scopeKind: event.startsWith("fix_pr.") ? ("requests" as const) : ("repositories" as const),
        // What the person gets now: without a mail channel nothing is sent, whatever was stored.
        preference: { ...preference, email: preference.email && mailAvailable },
      };
    });
  return { email, mailAvailable, canManageChannels, events };
}
