<script lang="ts">
  import { ChevronRight, Lock, Moon, PanelLeft, Plus, Sun } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import type { Snippet } from "svelte";
  import { page } from "$app/state";
  import { api } from "../api.ts";
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";
  import { isAdmin, moduleOn, type NavItem, navFor, navTrail } from "../nav.ts";
  import type { Me } from "../session.ts";
  import { findingCountsQuery, systemQuery } from "../shell.ts";
  import { resolvedTheme, setTheme } from "../theme.svelte.ts";
  import { displayVersion } from "../version.ts";
  import CommandSearch from "./CommandSearch.svelte";
  import MaintenanceBanner from "./MaintenanceBanner.svelte";
  import Mark from "./Mark.svelte";
  import NotificationBell from "./NotificationBell.svelte";
  import ToastRegion from "./ToastRegion.svelte";
  import UserMenu from "./UserMenu.svelte";
  import Badge from "./ui/Badge.svelte";
  import { BADGE_TONE, type BadgeTone } from "./ui/tones.ts";
  import Wordmark from "./Wordmark.svelte";

  let { me, children }: { me: Me; children: Snippet } = $props();

  const SIDEBAR_KEY = "garnetops.sidebar";
  function storedCollapsed(): boolean {
    try {
      return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
    } catch {
      return false;
    }
  }

  let collapsed = $state(storedCollapsed());
  const counts = createQuery(() => ({ ...findingCountsQuery(), refetchInterval: 60_000 }));
  const system = createQuery(() => systemQuery);
  const criticalOpen = $derived(counts.data?.open.critical ?? 0);
  // What needs a look under Infrastructure: the same "attention" the pages filter by.
  type Attention = { count: number; worst: "critical" | "high" | null };
  const hostsAttention = createQuery(() => ({
    queryKey: ["hosts", "attention"],
    queryFn: () => api<Attention>("/hosts/attention"),
    enabled: moduleOn(me, "hosts"),
    refetchInterval: 60_000,
  }));
  const websitesAttention = createQuery(() => ({
    queryKey: ["websites", "attention"],
    queryFn: () => api<Attention>("/exposure/attention"),
    enabled: moduleOn(me, "websites"),
    refetchInterval: 60_000,
  }));
  function badgeOf(item: NavItem): { count: number; tone: BadgeTone; label: string } | null {
    if (item.to === "/findings")
      return criticalOpen > 0
        ? {
            count: criticalOpen,
            tone: "critical",
            label: t("shell.criticalOpenBadge", { count: criticalOpen }),
          }
        : null;
    const attention =
      item.to === "/hosts"
        ? hostsAttention.data
        : item.to === "/websites"
          ? websitesAttention.data
          : undefined;
    if (!attention || attention.count === 0 || !item.module || !moduleOn(me, item.module)) return null;
    return {
      count: attention.count,
      tone: attention.worst ?? "neutral",
      label: t("shell.attentionBadge", { count: attention.count }),
    };
  }
  const trail = $derived(navTrail(page.url.pathname));
  const versionText = $derived(
    system.data ? t("shell.version", { version: displayVersion(system.data.version, t("shell.alpha")) }) : "",
  );
  const dark = $derived(resolvedTheme() === "dark");

  function isActive(to: string): boolean {
    const path = page.url.pathname;
    return to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`);
  }

  function toggleSidebar() {
    collapsed = !collapsed;
    try {
      localStorage.setItem(SIDEBAR_KEY, collapsed ? "collapsed" : "expanded");
    } catch {
      // Not persisted; the sidebar still toggles for this page view.
    }
  }
</script>

<div
  class={cn(
    "grid h-dvh",
    collapsed
      ? "grid-cols-[var(--sidebar-width-collapsed)_minmax(0,1fr)]"
      : "grid-cols-[var(--sidebar-width)_minmax(0,1fr)]",
  )}
>
  <aside class="flex flex-col overflow-x-hidden overflow-y-auto border-r bg-sidebar px-2">
    <div class={cn("flex h-14 flex-none items-center", collapsed ? "justify-center" : "px-2")}>
      {#if collapsed}
        <Mark class="size-6" />
        <span class="sr-only">GarnetOps</span>
      {:else}
        <Wordmark />
        <span title={t("shell.alphaHint")} class="ml-2"><Badge tone="info">{t("shell.alpha")}</Badge></span>
      {/if}
    </div>
    <nav aria-label={t("shell.mainNavigation")}>
      {#each navFor(me) as group (group.label)}
        <div class={cn("pb-1", collapsed ? "border-t pt-2 first:border-t-0" : "pt-3")}>
          {#if !collapsed}<div class="px-2 pb-1.5 text-sm text-muted-foreground">{t(group.label)}</div>{/if}
          <ul class="grid gap-0.5">
            {#each group.items as item (item.to)}
              {@const badge = badgeOf(item)}
              {@const active = isActive(item.to)}
              {@const add = !collapsed && item.add && isAdmin(me) && item.module && moduleOn(me, item.module) ? item.add : null}
              <li class="flex items-center gap-0.5">
                <a
                  href={item.to}
                  title={collapsed ? t(item.label) : undefined}
                  aria-label={badge !== null ? `${t(item.label)}, ${badge.label}` : collapsed ? t(item.label) : undefined}
                  aria-current={active ? "page" : undefined}
                  class={cn(
                    "flex h-9 min-w-0 flex-1 items-center gap-2.5 rounded-md hover:bg-sidebar-hover",
                    collapsed ? "relative justify-center" : "px-2",
                    active && "bg-sidebar-accent font-medium text-sidebar-accent-foreground hover:bg-sidebar-accent",
                  )}
                >
                  <item.icon aria-hidden="true" class="size-4 flex-none" />
                  {#if !collapsed}<span class="truncate">{t(item.label)}</span>{/if}
                  {#if badge !== null}
                    <span
                      aria-hidden="true"
                      data-testid="nav-badge-{item.to.slice(1)}"
                      class={cn(
                        "rounded-md px-1.5 text-xs leading-5 font-semibold",
                        BADGE_TONE[badge.tone],
                        collapsed ? "absolute -top-1 -right-1" : "ml-auto",
                      )}
                    >
                      {formatNumber(badge.count)}
                    </span>
                  {/if}
                </a>
                {#if add}
                  <a
                    href={add.to}
                    aria-label={t(add.label)}
                    title={t(add.label)}
                    class="grid size-9 flex-none place-items-center rounded-md text-muted-foreground hover:bg-sidebar-hover hover:text-foreground"
                  >
                    <Plus aria-hidden="true" class="size-4" />
                  </a>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/each}
    </nav>
    <!-- One line: the badge keeps its size and the version gives way (and shows in full on hover). -->
    <div
      class={cn(
        "mt-auto flex min-w-0 items-center gap-2 border-t py-3 text-sm whitespace-nowrap text-muted-foreground",
        collapsed ? "justify-center" : "justify-between px-2",
      )}
    >
      <span
        title={t("shell.localOnlyHint")}
        class={cn(
          "inline-flex flex-none items-center gap-1.5 rounded-md border px-2 leading-6",
          collapsed && "border-transparent px-0",
        )}
      >
        <Lock aria-hidden="true" class="size-3.5" />
        <span class={collapsed ? "sr-only" : undefined}>{t("shell.localOnly")}</span>
      </span>
      {#if !collapsed && system.data}
        <span class="min-w-0 truncate" title={versionText}>{versionText}</span>
      {/if}
    </div>
  </aside>

  <div class="flex min-w-0 flex-col overflow-hidden">
    <header class="flex h-14 flex-none items-center gap-3 border-b bg-background px-4">
      <button
        type="button"
        onclick={toggleSidebar}
        aria-label={collapsed ? t("shell.expandSidebar") : t("shell.collapseSidebar")}
        aria-expanded={!collapsed}
        class="grid size-9 flex-none place-items-center rounded-md hover:bg-accent"
      >
        <PanelLeft aria-hidden="true" class="size-4" />
      </button>
      {#if trail}
        <nav aria-label={t("shell.breadcrumbs")} class="min-w-0">
          <ol class="flex items-center gap-1.5 text-muted-foreground">
            <li class="truncate">{t(trail.group)}</li>
            <li aria-hidden="true"><ChevronRight class="size-4" /></li>
            <li aria-current="page" class="truncate font-medium text-foreground">{t(trail.item.label)}</li>
          </ol>
        </nav>
      {/if}
      <div class="ml-auto flex items-center gap-2">
        <CommandSearch {me} />
        <button
          type="button"
          onclick={() => setTheme(dark ? "light" : "dark")}
          aria-label={dark ? t("shell.useLightTheme") : t("shell.useDarkTheme")}
          title={dark ? t("shell.useLightTheme") : t("shell.useDarkTheme")}
          class="grid size-9 place-items-center rounded-md hover:bg-accent"
        >
          {#if dark}<Sun aria-hidden="true" class="size-4" />{:else}<Moon aria-hidden="true" class="size-4" />{/if}
        </button>
        <NotificationBell />
        <UserMenu {me} />
      </div>
    </header>
    <!-- The content area is the container every layout decision is made against (AGENTS.md rule 5). -->
    <main data-content class="@container flex-1 overflow-y-auto px-8 pt-6 pb-12">
      <MaintenanceBanner />
      {@render children()}
    </main>
  </div>
  <ToastRegion />
</div>
