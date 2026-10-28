import { useQuery } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronRight, Lock, Moon, PanelLeft, Sun } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatNumber } from "../lib/format.ts";
import type { Me } from "../lib/session.ts";
import { resolvedTheme, setTheme, useTheme } from "../lib/theme.ts";
import { displayVersion } from "../lib/version.ts";
import { Mark, Wordmark } from "./brand.tsx";
import { CommandSearch } from "./command-search.tsx";
import { MaintenanceBanner } from "./maintenance-banner.tsx";
import { navFor, navTrail } from "./nav.ts";
import { NotificationBell } from "./notification-bell.tsx";
import { ToastRegion } from "./toast-region.tsx";
import { Badge } from "./ui/badge.tsx";
import { UserMenu } from "./user-menu.tsx";

const SIDEBAR_KEY = "garnetops.sidebar";

function storedCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
  } catch {
    return false;
  }
}

export interface FindingCounts {
  states: { open: number; accepted: number; resolved: number };
  open: Partial<Record<string, number>>;
}

/** Shared with the findings page, which shows the same counts on its tabs. */
export const findingCountsQuery = (filters = "") => ({
  queryKey: ["finding-counts", filters],
  queryFn: () => api<FindingCounts>(`/findings/counts${filters}`),
});

export const systemQuery = {
  queryKey: ["system"],
  queryFn: () => api<{ version: string }>("/system"),
  staleTime: 5 * 60_000,
};

export function AppShell({ me, children }: { me: Me; children: ReactNode }) {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [collapsed, setCollapsed] = useState(storedCollapsed);
  const { resolved } = useTheme();
  const counts = useQuery({ ...findingCountsQuery(), refetchInterval: 60_000 });
  const system = useQuery(systemQuery);
  const criticalOpen = counts.data?.open.critical ?? 0;
  const trail = navTrail(pathname);
  const versionText = system.data
    ? t("shell.version", { version: displayVersion(system.data.version, t("shell.alpha")) })
    : "";

  function toggleSidebar() {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(SIDEBAR_KEY, next ? "collapsed" : "expanded");
    } catch {
      // Not persisted; the sidebar still toggles for this page view.
    }
  }

  return (
    <div
      className={cn(
        "grid h-dvh",
        collapsed
          ? "grid-cols-[var(--sidebar-width-collapsed)_minmax(0,1fr)]"
          : "grid-cols-[var(--sidebar-width)_minmax(0,1fr)]",
      )}
    >
      <aside className="flex flex-col overflow-x-hidden overflow-y-auto border-r bg-sidebar px-2">
        <div className={cn("flex h-14 flex-none items-center", collapsed ? "justify-center" : "px-2")}>
          {collapsed ? (
            <>
              <Mark className="size-6" />
              <span className="sr-only">GarnetOps</span>
            </>
          ) : (
            <>
              <Wordmark />
              <span title={t("shell.alphaHint")} className="ml-2">
                <Badge tone="info">{t("shell.alpha")}</Badge>
              </span>
            </>
          )}
        </div>
        <nav aria-label={t("shell.mainNavigation")}>
          {navFor(me).map((group) => (
            <div
              key={group.label}
              className={cn("pb-1", collapsed ? "border-t pt-2 first:border-t-0" : "pt-3")}
            >
              {collapsed ? null : (
                <div className="px-2 pb-1.5 text-sm text-muted-foreground">{t(group.label)}</div>
              )}
              <ul className="grid gap-0.5">
                {group.items.map(({ to, label, icon: Icon }) => {
                  const badge = to === "/findings" && criticalOpen > 0 ? criticalOpen : null;
                  return (
                    <li key={to}>
                      <Link
                        to={to}
                        activeOptions={{ exact: to === "/", includeSearch: false }}
                        title={collapsed ? t(label) : undefined}
                        aria-label={
                          badge !== null
                            ? `${t(label)}, ${t("shell.criticalOpenBadge", { count: badge })}`
                            : collapsed
                              ? t(label)
                              : undefined
                        }
                        className={cn(
                          "flex h-9 items-center gap-2.5 rounded-md hover:bg-sidebar-hover",
                          collapsed ? "relative justify-center" : "px-2",
                        )}
                        activeProps={{
                          className:
                            "bg-sidebar-accent font-medium text-sidebar-accent-foreground hover:bg-sidebar-accent",
                          "aria-current": "page",
                        }}
                      >
                        <Icon aria-hidden="true" className="size-4 flex-none" />
                        {collapsed ? null : <span className="truncate">{t(label)}</span>}
                        {badge !== null ? (
                          <span
                            aria-hidden="true"
                            className={cn(
                              "rounded-md bg-destructive/15 px-1.5 text-xs leading-5 font-semibold text-destructive-text",
                              collapsed ? "absolute -top-1 -right-1" : "ml-auto",
                            )}
                          >
                            {formatNumber(badge)}
                          </span>
                        ) : null}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
        {/* One line: the badge keeps its size and the version gives way (and shows in full on hover). */}
        <div
          className={cn(
            "mt-auto flex min-w-0 items-center gap-2 border-t py-3 text-sm whitespace-nowrap text-muted-foreground",
            collapsed ? "justify-center" : "justify-between px-2",
          )}
        >
          <span
            title={t("shell.localOnlyHint")}
            className={cn(
              "inline-flex flex-none items-center gap-1.5 rounded-md border px-2 leading-6",
              collapsed && "border-transparent px-0",
            )}
          >
            <Lock aria-hidden="true" className="size-3.5" />
            <span className={collapsed ? "sr-only" : undefined}>{t("shell.localOnly")}</span>
          </span>
          {collapsed || !system.data ? null : (
            <span className="min-w-0 truncate" title={versionText}>
              {versionText}
            </span>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-col overflow-hidden">
        <header className="flex h-14 flex-none items-center gap-3 border-b bg-background px-4">
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label={collapsed ? t("shell.expandSidebar") : t("shell.collapseSidebar")}
            aria-expanded={!collapsed}
            className="grid size-9 flex-none place-items-center rounded-md hover:bg-accent"
          >
            <PanelLeft aria-hidden="true" className="size-4" />
          </button>
          {trail ? (
            <nav aria-label={t("shell.breadcrumbs")} className="min-w-0">
              <ol className="flex items-center gap-1.5 text-muted-foreground">
                <li className="truncate">{t(trail.group)}</li>
                <li aria-hidden="true">
                  <ChevronRight className="size-4" />
                </li>
                <li aria-current="page" className="truncate font-medium text-foreground">
                  {t(trail.item.label)}
                </li>
              </ol>
            </nav>
          ) : null}
          <div className="ml-auto flex items-center gap-2">
            <CommandSearch me={me} />
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme() === "dark" ? "light" : "dark")}
              aria-label={resolved === "dark" ? t("shell.useLightTheme") : t("shell.useDarkTheme")}
              title={resolved === "dark" ? t("shell.useLightTheme") : t("shell.useDarkTheme")}
              className="grid size-9 place-items-center rounded-md hover:bg-accent"
            >
              {resolved === "dark" ? (
                <Sun aria-hidden="true" className="size-4" />
              ) : (
                <Moon aria-hidden="true" className="size-4" />
              )}
            </button>
            <NotificationBell />
            <UserMenu me={me} />
          </div>
        </header>
        {/* The content area is the container every layout decision is made against (AGENTS.md rule 5). */}
        <main data-content className="@container flex-1 overflow-y-auto px-8 pt-6 pb-12">
          <MaintenanceBanner />
          {children}
        </main>
      </div>
      <ToastRegion />
    </div>
  );
}
