import { safeAppLink } from "@garnetops/core/user-notifications";
import { renderNotificationItem, resolveLanguage } from "@garnetops/i18n";
import { createInfiniteQuery, type InfiniteData, useQueryClient } from "@tanstack/svelte-query";
import { untrack } from "svelte";
import { language, t } from "./i18n.svelte.ts";
import {
  loadNotifications,
  type NotificationPage,
  newestId,
  notificationsKey,
  type UserNotification,
} from "./notifications.ts";
import { toast } from "./toast.svelte.ts";

export type NotificationCache = InfiniteData<NotificationPage, number | undefined>;

const STREAM_URL = "/api/v1/me/notifications/stream";
/** Polling is the fallback while the stream is down; with the stream up it is only a safety net. */
const POLL_FALLBACK_MS = 30_000;
const POLL_SAFETY_MS = 5 * 60_000;
/** Individual toasts for new notifications; more than this at once become one. */
const MAX_TOASTS_AT_ONCE = 2;

/**
 * The signed-in person's notifications: the list (newest first, older pages on demand), kept
 * current by the event stream (ADR 0019). If the stream cannot be opened or breaks, the list is
 * polled every 30 seconds and the stream is retried with a growing pause. New notifications
 * that arrive while the app is open also show a short toast.
 *
 * Call it while a component initialises (it creates a query and effects owned by that component).
 */
export function createNotificationFeed() {
  const queryClient = useQueryClient();
  let live = $state(false);

  const query = createInfiniteQuery(() => ({
    queryKey: notificationsKey,
    queryFn: ({ pageParam }: { pageParam: number | undefined }) => loadNotifications(pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last: NotificationPage) => last.next ?? undefined,
    refetchInterval: live ? POLL_SAFETY_MS : POLL_FALLBACK_MS,
  }));

  $effect(() => {
    if (typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let stopped = false;
    const reload = () => queryClient.invalidateQueries({ queryKey: notificationsKey });

    const open = () => {
      source = new EventSource(STREAM_URL);
      source.addEventListener("ready", (event) => {
        failures = 0;
        live = true;
        const data = parse<{ unread?: number; latestId?: number }>(event);
        const cached = queryClient.getQueryData<NotificationCache>(notificationsKey);
        // Whatever arrived between the list and the stream, or while the stream was down.
        if (
          !cached ||
          (data?.latestId ?? 0) > newestId(cached.pages) ||
          data?.unread !== cached.pages[0]?.unread
        ) {
          void reload();
        }
      });
      source.addEventListener("notification", (event) => {
        const item = parse<UserNotification>(event);
        if (!item || typeof item.id !== "number") return;
        const cached = queryClient.getQueryData<NotificationCache>(notificationsKey);
        if (!cached?.pages[0]) return void reload();
        if (cached.pages.some((p) => p.items.some((i) => i.id === item.id))) return;
        const [first, ...rest] = cached.pages;
        if (!first) return;
        queryClient.setQueryData<NotificationCache>(notificationsKey, {
          ...cached,
          pages: [
            { ...first, items: [item, ...first.items], unread: first.unread + (item.readAt ? 0 : 1) },
            ...rest,
          ],
        });
      });
      source.addEventListener("resync", () => void reload());
      source.onerror = () => {
        live = false;
        // CONNECTING: the browser reconnects by itself (and sends the last id). CLOSED: the server
        // refused (signed out, too many streams); try again later, polling meanwhile.
        if (source?.readyState !== EventSource.CLOSED || stopped) return;
        source.close();
        failures++;
        timer = setTimeout(open, Math.min(60_000, 5_000 * 2 ** (failures - 1)));
      };
    };
    untrack(open);
    return () => {
      stopped = true;
      clearTimeout(timer);
      source?.close();
      live = false;
    };
  });

  // A toast for what arrived since the last look; the first load only sets the starting point.
  let seen: number | null = null;
  $effect(() => {
    const first = query.data?.pages[0];
    if (!first) return;
    // Showing a toast reads and writes the toast store; that must not make this effect depend on it.
    untrack(() => announce(first));
  });

  function announce(first: NotificationPage) {
    const newest = newestId([first]);
    if (seen === null) {
      seen = newest;
      return;
    }
    const since = seen;
    const fresh = first.items.filter((i) => i.id > since && !i.readAt).sort((a, b) => a.id - b.id);
    seen = Math.max(seen, newest);
    if (fresh.length === 0) return;
    if (fresh.length > MAX_TOASTS_AT_ONCE) {
      toast.info(t("inapp.newMany", { count: fresh.length }));
      return;
    }
    const lang = resolveLanguage(language());
    for (const item of fresh) {
      const link = safeAppLink(item.link);
      toast.info(renderNotificationItem(lang, item.titleKey, item.params).title, {
        ...(link ? { action: { label: t("inapp.view"), href: link } } : {}),
      });
    }
  }

  return {
    query,
    /** Whether the event stream is open (else the list is polled). */
    get live() {
      return live;
    },
  };
}

function parse<T>(event: Event): T | null {
  try {
    return JSON.parse((event as MessageEvent<string>).data) as T;
  } catch {
    return null;
  }
}
