import { safeAppLink } from "@garnetops/core/user-notifications";
import { renderNotificationItem, resolveLanguage } from "@garnetops/i18n";
import { type InfiniteData, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useRouter } from "@tanstack/react-router";
import { Bell, Check, CheckCheck } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatDate, formatDateTime, formatRelative } from "../lib/format.ts";
import {
  groupByDay,
  type NotificationPage,
  newestId,
  notificationsKey,
  type UserNotification,
  unreadBadge,
} from "../lib/notifications.ts";
import { displayTimeZone } from "../lib/time-zone.ts";
import { toast } from "../lib/toast.ts";
import { useNotificationFeed } from "../lib/use-notification-feed.ts";
import { BADGE_TONE } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

type Cache = InfiniteData<NotificationPage, number | undefined>;

/** Applies a change to every notification in the cached pages (marking as read, locally and at once). */
function mapItems(
  cache: Cache | undefined,
  change: (item: UserNotification) => UserNotification,
): Cache | undefined {
  if (!cache) return cache;
  return {
    ...cache,
    pages: cache.pages.map((page) => ({ ...page, items: page.items.map(change) })),
  };
}

/**
 * The bell in the top bar (ADR 0019): the number of unread notifications and, on click, a panel
 * with the latest ones grouped by day. A disclosure, not a menu or dialog: Escape and a click
 * outside close it, and focus is never moved for you.
 */
export function NotificationBell() {
  const { t, i18n } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { query, live } = useNotificationFeed();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const pages = query.data?.pages ?? [];
  const items = pages.flatMap((p) => p.items);
  const unread = pages[0]?.unread ?? 0;
  const language = resolveLanguage(i18n.language);
  const zone = displayTimeZone();
  const groups = useMemo(() => groupByDay(items, new Date(), zone), [items, zone]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const reload = () => queryClient.invalidateQueries({ queryKey: notificationsKey });

  const markRead = useMutation({
    mutationFn: (id: number) => api(`/me/notifications/${id}/read`, { method: "POST" }),
    onMutate: (id) => {
      queryClient.setQueryData<Cache>(notificationsKey, (cache) => {
        const wasUnread = cache?.pages.some((p) => p.items.some((i) => i.id === id && !i.readAt));
        const next = mapItems(cache, (i) =>
          i.id === id && !i.readAt ? { ...i, readAt: new Date().toISOString() } : i,
        );
        if (!next || !wasUnread) return next;
        const [first, ...rest] = next.pages;
        return first
          ? { ...next, pages: [{ ...first, unread: Math.max(0, first.unread - 1) }, ...rest] }
          : next;
      });
    },
    onError: () => {
      toast.error(t("errors.actionFailed"));
      void reload();
    },
  });

  const markAll = useMutation({
    mutationFn: () => api("/me/notifications/read-all", { method: "POST", body: { upTo: newestId(pages) } }),
    onMutate: () => {
      const now = new Date().toISOString();
      queryClient.setQueryData<Cache>(notificationsKey, (cache) => {
        const next = mapItems(cache, (i) => (i.readAt ? i : { ...i, readAt: now }));
        if (!next) return next;
        const [first, ...rest] = next.pages;
        return first ? { ...next, pages: [{ ...first, unread: 0 }, ...rest] } : next;
      });
    },
    onSuccess: () => toast.success(t("inapp.markedAllRead")),
    onError: () => {
      toast.error(t("errors.actionFailed"));
      void reload();
    },
  });

  function follow(item: UserNotification, href: string, event: React.MouseEvent) {
    if (!item.readAt) markRead.mutate(item.id);
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    setOpen(false);
    router.history.push(href);
  }

  return (
    <div ref={root} className="relative">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={unread > 0 ? t("inapp.bellUnread", { count: unread }) : t("inapp.bell")}
        title={t("inapp.bell")}
        onClick={() => setOpen((v) => !v)}
        className="relative grid size-9 place-items-center rounded-md hover:bg-accent"
      >
        <Bell aria-hidden="true" className="size-4" />
        {unread > 0 ? (
          <span
            aria-hidden="true"
            data-testid="bell-count"
            className={cn(
              "absolute -top-1 -right-1 grid h-[18px] min-w-[18px] place-items-center rounded-full border border-background px-1 text-[11px] leading-none font-semibold tabular-nums",
              BADGE_TONE.info,
            )}
          >
            {unreadBadge(unread)}
          </span>
        ) : null}
      </button>
      {open ? (
        <section
          id={panelId}
          aria-label={t("inapp.panelLabel")}
          className="absolute top-full right-0 z-30 mt-2 grid w-[26rem] max-w-[calc(100vw-2rem)] rounded-lg border bg-card text-card-foreground shadow-xs"
        >
          <div className="flex items-center gap-2 border-b px-4 py-2.5">
            <h2 className="mr-auto text-base font-semibold">{t("inapp.panelTitle")}</h2>
            <Button
              variant="ghost"
              className="h-8 px-2 text-sm"
              disabled={unread === 0 || markAll.isPending}
              onClick={() => markAll.mutate()}
            >
              <CheckCheck aria-hidden="true" className="size-4" />
              {t("inapp.markAllRead")}
            </Button>
          </div>
          <div className="max-h-[min(28rem,calc(100dvh-10rem))] overflow-y-auto">
            {query.isError && items.length === 0 ? (
              <p role="alert" className="px-4 py-6 text-sm text-destructive-text">
                {t("inapp.loadFailed")}
              </p>
            ) : items.length === 0 ? (
              <p className="px-4 py-6 text-sm text-muted-foreground">
                {query.isPending ? t("common.loading") : t("inapp.empty")}
              </p>
            ) : (
              groups.map((group) => (
                <div key={group.day}>
                  <h3 className="sticky top-0 bg-card px-4 pt-3 pb-1 text-[13px] font-medium text-muted-foreground">
                    {group.key === "today"
                      ? t("inapp.today")
                      : group.key === "yesterday"
                        ? t("inapp.yesterday")
                        : formatDate(group.items[0]?.createdAt ?? group.day)}
                  </h3>
                  <ul>
                    {group.items.map((item) => {
                      const { title, text } = renderNotificationItem(language, item.titleKey, item.params);
                      const href = safeAppLink(item.link);
                      const body = (
                        <>
                          <span className={cn("block break-words", !item.readAt && "font-semibold")}>
                            {!item.readAt ? (
                              <span className="sr-only">{t("inapp.unreadMarker")}: </span>
                            ) : null}
                            {title}
                          </span>
                          <span className="block text-sm break-words text-muted-foreground">{text}</span>
                          <time
                            dateTime={item.createdAt}
                            title={formatDateTime(item.createdAt)}
                            className="block text-[13px] text-muted-foreground"
                          >
                            {formatRelative(item.createdAt)}
                          </time>
                        </>
                      );
                      return (
                        <li
                          key={item.id}
                          data-notification={item.titleKey}
                          data-unread={item.readAt ? undefined : ""}
                          className="flex items-start gap-1 px-2"
                        >
                          {/* Not colour alone: an unread one is bold, has a bar and says so for screen readers. */}
                          <span
                            aria-hidden="true"
                            className={cn(
                              "mt-2 h-8 w-1 flex-none rounded-full",
                              item.readAt ? "bg-transparent" : "bg-info",
                            )}
                          />
                          {href ? (
                            <a
                              href={href}
                              onClick={(event) => follow(item, href, event)}
                              className="min-w-0 flex-1 rounded-md px-2 py-2 hover:bg-accent"
                            >
                              {body}
                            </a>
                          ) : (
                            <div className="min-w-0 flex-1 px-2 py-2">{body}</div>
                          )}
                          {!item.readAt ? (
                            <button
                              type="button"
                              aria-label={t("inapp.markRead")}
                              title={t("inapp.markRead")}
                              onClick={() => markRead.mutate(item.id)}
                              className="mt-1.5 grid size-8 flex-none place-items-center rounded-md hover:bg-accent"
                            >
                              <Check aria-hidden="true" className="size-4" />
                            </button>
                          ) : (
                            <span className="size-8 flex-none" />
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))
            )}
            {query.hasNextPage ? (
              <div className="px-4 py-2">
                <Button
                  variant="outline"
                  className="h-8 w-full text-sm"
                  disabled={query.isFetchingNextPage}
                  onClick={() => void query.fetchNextPage()}
                >
                  {query.isFetchingNextPage ? t("common.loading") : t("inapp.showOlder")}
                </Button>
              </div>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t px-4 py-2.5 text-sm">
            <Link
              to="/account"
              search={{ section: "notifications" }}
              onClick={() => setOpen(false)}
              className="font-medium text-primary-text underline underline-offset-4"
            >
              {t("inapp.settingsLink")}
            </Link>
            <span className="ml-auto text-[13px] text-muted-foreground">
              {live ? t("inapp.live") : t("inapp.polling")}
            </span>
          </div>
        </section>
      ) : null}
    </div>
  );
}
