import {
  Activity,
  Bug,
  ChartColumn,
  GitBranch,
  GitPullRequest,
  GitPullRequestArrow,
  LayoutGrid,
  type LucideIcon,
  Package,
  ScrollText,
  Settings,
  ShieldCheck,
  Siren,
  Users,
} from "@lucide/svelte";
import type { MessageKey } from "./i18n.svelte.ts";
import type { Me } from "./session.ts";

export type NavTo =
  | "/"
  | "/findings"
  | "/early-warnings"
  | "/statistics"
  | "/repositories"
  | "/gates"
  | "/pull-requests"
  | "/fixes"
  | "/packages"
  | "/settings"
  | "/team"
  | "/audit-log"
  | "/system";

export interface NavItem {
  to: NavTo;
  label: MessageKey;
  icon: LucideIcon;
  adminOnly?: boolean;
}

/** Only screens that exist are listed; nothing is shown as a teaser. */
export const NAV: { label: MessageKey; items: NavItem[] }[] = [
  {
    label: "shell.groupDaily",
    items: [
      { to: "/", label: "nav.overview", icon: LayoutGrid },
      { to: "/findings", label: "nav.findings", icon: Bug },
      { to: "/early-warnings", label: "nav.earlyWarnings", icon: Siren },
      { to: "/statistics", label: "nav.statistics", icon: ChartColumn },
    ],
  },
  {
    label: "shell.groupCode",
    items: [
      { to: "/repositories", label: "nav.repositories", icon: GitBranch },
      { to: "/gates", label: "nav.gates", icon: ShieldCheck },
      { to: "/pull-requests", label: "nav.pullRequests", icon: GitPullRequestArrow },
      { to: "/fixes", label: "nav.fixes", icon: GitPullRequest },
      { to: "/packages", label: "nav.packages", icon: Package },
    ],
  },
  {
    label: "shell.groupAdmin",
    items: [
      { to: "/settings", label: "nav.settings", icon: Settings },
      { to: "/team", label: "nav.team", icon: Users, adminOnly: true },
      { to: "/audit-log", label: "nav.auditLog", icon: ScrollText, adminOnly: true },
      { to: "/system", label: "nav.system", icon: Activity, adminOnly: true },
    ],
  },
];

export const isAdmin = (me: Me) => me.role === "owner" || me.role === "admin";

/** The navigation as this user sees it. */
export function navFor(me: Me) {
  return NAV.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || isAdmin(me)),
  })).filter((group) => group.items.length > 0);
}

/** Group and item of the page at `pathname`, for the breadcrumbs. */
export function navTrail(pathname: string): { group: MessageKey; item: NavItem } | null {
  for (const group of NAV) {
    for (const item of group.items) {
      const match =
        item.to === "/" ? pathname === "/" : pathname === item.to || pathname.startsWith(`${item.to}/`);
      if (match) return { group: group.label, item };
    }
  }
  return null;
}
