import { safeAppLink } from "@garnetops/core/user-notifications";
import { renderNotificationItem, resolveLanguage } from "@garnetops/i18n";
import { type InfiniteData, useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  loadNotifications,
  type NotificationPage,
  newestId,
  notificationsKey,
  type UserNotification,
} from "./notifications.ts";
import { toast } from "./toast.ts";

type Cache = InfiniteData<NotificationPage, number | undefined>;

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
 */
export function useNotificationFeed() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [live, setLive] = useState(false);

  const query = useInfiniteQuery({
    queryKey: notificationsKey,
    queryFn: ({ pageParam }) => loadNotifications(pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next ?? undefined,
    refetchInterval: live ? POLL_SAFETY_MS : POLL_FALLBACK_MS,
  });

  useEffect(() => {
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
        setLive(true);
        const data = parse<{ unread?: number; latestId?: number }>(event);
        const cached = queryClient.getQueryData<Cache>(notificationsKey);
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
        const cached = queryClient.getQueryData<Cache>(notificationsKey);
        if (!cached?.pages[0]) return void reload();
        if (cached.pages.some((p) => p.items.some((i) => i.id === item.id))) return;
        const [first, ...rest] = cached.pages;
        if (!first) return;
        queryClient.setQueryData<Cache>(notificationsKey, {
          ...cached,
          pages: [
            { ...first, items: [item, ...first.items], unread: first.unread + (item.readAt ? 0 : 1) },
            ...rest,
          ],
        });
      });
      source.addEventListener("resync", () => void reload());
      source.onerror = () => {
        setLive(false);
        // CONNECTING: the browser reconnects by itself (and sends the last id). CLOSED: the server
        // refused (signed out, too many streams); try again later, polling meanwhile.
        if (source?.readyState !== EventSource.CLOSED || stopped) return;
        source.close();
        failures++;
        timer = setTimeout(open, Math.min(60_000, 5_000 * 2 ** (failures - 1)));
      };
    };
    open();
    return () => {
      stopped = true;
      clearTimeout(timer);
      source?.close();
      setLive(false);
    };
  }, [queryClient]);

  // A toast for what arrived since the last look; the first load only sets the starting point.
  const seen = useRef<number | null>(null);
  const first = query.data?.pages[0];
  useEffect(() => {
    if (!first) return;
    const newest = newestId([first]);
    if (seen.current === null) {
      seen.current = newest;
      return;
    }
    const fresh = first.items
      .filter((i) => i.id > (seen.current ?? 0) && !i.readAt)
      .sort((a, b) => a.id - b.id);
    seen.current = Math.max(seen.current, newest);
    if (fresh.length === 0) return;
    if (fresh.length > MAX_TOASTS_AT_ONCE) {
      toast.info(t("inapp.newMany", { count: fresh.length }));
      return;
    }
    const language = resolveLanguage(i18n.language);
    for (const item of fresh) {
      const link = safeAppLink(item.link);
      toast.info(renderNotificationItem(language, item.titleKey, item.params).title, {
        ...(link ? { action: { label: t("inapp.view"), href: link } } : {}),
      });
    }
  }, [first, t, i18n.language]);

  return { query, live };
}

function parse<T>(event: Event): T | null {
  try {
    return JSON.parse((event as MessageEvent<string>).data) as T;
  } catch {
    return null;
  }
}
