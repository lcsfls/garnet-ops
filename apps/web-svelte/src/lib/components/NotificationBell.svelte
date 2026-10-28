<script lang="ts">
  import { safeAppLink } from "@garnetops/core/user-notifications";
  import { renderNotificationItem, resolveLanguage } from "@garnetops/i18n";
  import { Bell, Check, CheckCheck } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { api } from "../api.ts";
  import { cn } from "../cn.ts";
  import { formatDate, formatDateTime, formatRelative } from "../format.ts";
  import { language, t } from "../i18n.svelte.ts";
  import { createNotificationFeed, type NotificationCache } from "../notification-feed.svelte.ts";
  import { groupByDay, newestId, notificationsKey, type UserNotification, unreadBadge } from "../notifications.ts";
  import { displayTimeZone } from "../time-zone.svelte.ts";
  import { toast } from "../toast.svelte.ts";
  import { href as appHref } from "../url.ts";
  import Button from "./ui/Button.svelte";
  import { BADGE_TONE } from "./ui/tones.ts";

  /** Applies a change to every notification in the cached pages (marking as read, locally and at once). */
  function mapItems(
    cache: NotificationCache | undefined,
    change: (item: UserNotification) => UserNotification,
  ): NotificationCache | undefined {
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
  const queryClient = useQueryClient();
  const feed = createNotificationFeed();
  const query = feed.query;
  let open = $state(false);
  const panelId = $props.id();
  let root: HTMLDivElement | undefined = $state();
  let button: HTMLButtonElement | undefined = $state();

  const pages = $derived(query.data?.pages ?? []);
  const items = $derived(pages.flatMap((p) => p.items));
  const unread = $derived(pages[0]?.unread ?? 0);
  const lang = $derived(resolveLanguage(language()));
  const groups = $derived(groupByDay(items, new Date(), displayTimeZone()));

  $effect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root?.contains(event.target as Node)) open = false;
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      open = false;
      button?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  });

  const reload = () => queryClient.invalidateQueries({ queryKey: notificationsKey });

  const markRead = createMutation(() => ({
    mutationFn: (id: number) => api(`/me/notifications/${id}/read`, { method: "POST" }),
    onMutate: (id: number) => {
      queryClient.setQueryData<NotificationCache>(notificationsKey, (cache) => {
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
  }));

  const markAll = createMutation(() => ({
    mutationFn: () => api("/me/notifications/read-all", { method: "POST", body: { upTo: newestId(pages) } }),
    onMutate: () => {
      const now = new Date().toISOString();
      queryClient.setQueryData<NotificationCache>(notificationsKey, (cache) => {
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
  }));

  function follow(item: UserNotification, href: string, event: MouseEvent) {
    if (!item.readAt) markRead.mutate(item.id);
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    open = false;
    void goto(href);
  }
</script>

{#snippet body(item: UserNotification, title: string, text: string)}
  <span class={cn("block break-words", !item.readAt && "font-semibold")}>
    {#if !item.readAt}<span class="sr-only">{`${t("inapp.unreadMarker")}: `}</span>{/if}{title}
  </span>
  <span class="block text-sm break-words text-muted-foreground">{text}</span>
  <time datetime={item.createdAt} title={formatDateTime(item.createdAt)} class="block text-[13px] text-muted-foreground">
    {formatRelative(item.createdAt)}
  </time>
{/snippet}

<div bind:this={root} class="relative">
  <button
    bind:this={button}
    type="button"
    aria-expanded={open}
    aria-controls={panelId}
    aria-label={unread > 0 ? t("inapp.bellUnread", { count: unread }) : t("inapp.bell")}
    title={t("inapp.bell")}
    onclick={() => (open = !open)}
    class="relative grid size-9 place-items-center rounded-md hover:bg-accent"
  >
    <Bell aria-hidden="true" class="size-4" />
    {#if unread > 0}
      <span
        aria-hidden="true"
        data-testid="bell-count"
        class={cn(
          "absolute -top-1 -right-1 grid h-[18px] min-w-[18px] place-items-center rounded-full border border-background px-1 text-[11px] leading-none font-semibold tabular-nums",
          BADGE_TONE.info,
        )}
      >
        {unreadBadge(unread)}
      </span>
    {/if}
  </button>
  {#if open}
    <section
      id={panelId}
      aria-label={t("inapp.panelLabel")}
      class="absolute top-full right-0 z-30 mt-2 grid w-[26rem] max-w-[calc(100vw-2rem)] rounded-lg border bg-card text-card-foreground shadow-xs"
    >
      <div class="flex items-center gap-2 border-b px-4 py-2.5">
        <h2 class="mr-auto text-base font-semibold">{t("inapp.panelTitle")}</h2>
        <Button
          variant="ghost"
          class="h-8 px-2 text-sm"
          disabled={unread === 0 || markAll.isPending}
          onclick={() => markAll.mutate()}
        >
          <CheckCheck aria-hidden="true" class="size-4" />
          {t("inapp.markAllRead")}
        </Button>
      </div>
      <div class="max-h-[min(28rem,calc(100dvh-10rem))] overflow-y-auto">
        {#if query.isError && items.length === 0}
          <p role="alert" class="px-4 py-6 text-sm text-destructive-text">
            {t("inapp.loadFailed")}
          </p>
        {:else if items.length === 0}
          <p class="px-4 py-6 text-sm text-muted-foreground">
            {query.isPending ? t("common.loading") : t("inapp.empty")}
          </p>
        {:else}
          {#each groups as group (group.day)}
            <div>
              <h3 class="sticky top-0 bg-card px-4 pt-3 pb-1 text-[13px] font-medium text-muted-foreground">
                {group.key === "today"
                  ? t("inapp.today")
                  : group.key === "yesterday"
                    ? t("inapp.yesterday")
                    : formatDate(group.items[0]?.createdAt ?? group.day)}
              </h3>
              <ul>
                {#each group.items as item (item.id)}
                  {@const rendered = renderNotificationItem(lang, item.titleKey, item.params)}
                  {@const link = safeAppLink(item.link)}
                  <li
                    data-notification={item.titleKey}
                    data-unread={item.readAt ? undefined : ""}
                    class="flex items-start gap-1 px-2"
                  >
                    <!-- Not colour alone: an unread one is bold, has a bar and says so for screen readers. -->
                    <span
                      aria-hidden="true"
                      class={cn("mt-2 h-8 w-1 flex-none rounded-full", item.readAt ? "bg-transparent" : "bg-info")}
                    ></span>
                    {#if link}
                      <a
                        href={link}
                        onclick={(event) => follow(item, link, event)}
                        class="min-w-0 flex-1 rounded-md px-2 py-2 hover:bg-accent"
                      >
                        {@render body(item, rendered.title, rendered.text)}
                      </a>
                    {:else}
                      <div class="min-w-0 flex-1 px-2 py-2">{@render body(item, rendered.title, rendered.text)}</div>
                    {/if}
                    {#if !item.readAt}
                      <button
                        type="button"
                        aria-label={t("inapp.markRead")}
                        title={t("inapp.markRead")}
                        onclick={() => markRead.mutate(item.id)}
                        class="mt-1.5 grid size-8 flex-none place-items-center rounded-md hover:bg-accent"
                      >
                        <Check aria-hidden="true" class="size-4" />
                      </button>
                    {:else}
                      <span class="size-8 flex-none"></span>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/each}
        {/if}
        {#if query.hasNextPage}
          <div class="px-4 py-2">
            <Button
              variant="outline"
              class="h-8 w-full text-sm"
              disabled={query.isFetchingNextPage}
              onclick={() => void query.fetchNextPage()}
            >
              {query.isFetchingNextPage ? t("common.loading") : t("inapp.showOlder")}
            </Button>
          </div>
        {/if}
      </div>
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1 border-t px-4 py-2.5 text-sm">
        <a
          href={appHref("/account", { section: "notifications" })}
          onclick={() => (open = false)}
          class="font-medium text-primary-text underline underline-offset-4"
        >
          {t("inapp.settingsLink")}
        </a>
        <span class="ml-auto text-[13px] text-muted-foreground">
          {feed.live ? t("inapp.live") : t("inapp.polling")}
        </span>
      </div>
    </section>
  {/if}
</div>
