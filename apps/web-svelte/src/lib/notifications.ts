import { queryOptions } from "@tanstack/svelte-query";
import { api } from "./api.ts";
import { dayKeyIn } from "./dates.ts";

/** A notification as the API sends it: a title key and short facts, never free text (ADR 0019). */
export interface UserNotification {
  id: number;
  event: string;
  titleKey: string;
  params: Record<string, string | number>;
  /** A path inside the app; the web app checks it again before following it. */
  link: string;
  createdAt: string;
  readAt: string | null;
}

export interface NotificationPage {
  items: UserNotification[];
  /** Unread notifications (counted up to 1000). */
  unread: number;
  /** Pass as `before` to get the next older page; null at the end. */
  next: number | null;
}

export const notificationsKey = ["notifications"] as const;

export const loadNotifications = (before?: number) =>
  api<NotificationPage>(`/me/notifications${before ? `?before=${before}` : ""}`);

/** The badge: the number, or "99+" from a hundred on. */
export function unreadBadge(count: number): string {
  return count > 99 ? "99+" : String(count);
}

export interface DayGroup<T> {
  /** "today", "yesterday" or the calendar day "YYYY-MM-DD" in the user's zone. */
  key: string;
  day: string;
  items: T[];
}

/**
 * Groups newest-first items by the calendar day they happened on in the user's zone (ADR 0005).
 * `key` is "today" and "yesterday" for those two days, so the view can name them in its language.
 */
export function groupByDay<T extends { createdAt: string }>(
  items: T[],
  now: Date,
  zone: string,
): DayGroup<T>[] {
  const today = dayKeyIn(now, zone);
  // Calendar arithmetic on the day number, never "24 hours ago" (a day can have 23 or 25 hours).
  const yesterday = new Date(Date.parse(`${today}T00:00:00Z`) - 86_400_000).toISOString().slice(0, 10);
  const groups: DayGroup<T>[] = [];
  for (const item of items) {
    const day = dayKeyIn(new Date(item.createdAt), zone);
    const last = groups.at(-1);
    if (last && last.day === day) last.items.push(item);
    else
      groups.push({
        key: day === today ? "today" : day === yesterday ? "yesterday" : day,
        day,
        items: [item],
      });
  }
  return groups;
}

/** The newest id in a list of pages, or 0. */
export function newestId(pages: NotificationPage[] | undefined): number {
  let max = 0;
  for (const page of pages ?? []) for (const item of page.items) max = Math.max(max, item.id);
  return max;
}

export const preferencesQuery = queryOptions({
  queryKey: ["notification-preferences"],
  queryFn: () => api<NotificationPreferences>("/me/notification-preferences"),
});

export interface PreferenceRow {
  event: string;
  group: "code" | "account" | "system";
  scoped: boolean;
  scopeKind: "repositories" | "requests";
  preference: { inApp: boolean; email: boolean; scope: "all" | "mine" };
}

export interface NotificationPreferences {
  email: string;
  mailAvailable: boolean;
  canManageChannels: boolean;
  events: PreferenceRow[];
}

/** Message keys cannot contain dots: "fix_pr.merged" is "fixPrMerged". */
export const eventMessageKey = (event: string) =>
  event.replace(/[._]([a-z])/g, (_, letter: string) => letter.toUpperCase());
