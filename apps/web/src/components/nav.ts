import {
  Bug,
  GitBranch,
  GitPullRequest,
  Globe,
  LayoutGrid,
  type LucideIcon,
  Package,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";

export type NavTo =
  | "/"
  | "/findings"
  | "/repositories"
  | "/gates"
  | "/fixes"
  | "/packages"
  | "/servers"
  | "/xdr"
  | "/attacks"
  | "/settings"
  | "/team"
  | "/audit-log";

/** Screens that only exist once something is connected. */
export type NavFeature = "xdr";
export type NavFeatures = Partial<Record<NavFeature, boolean>>;

export interface NavItem {
  to: NavTo;
  label: MessageKey;
  icon: LucideIcon;
  adminOnly?: boolean;
  /** Listed only while this feature is available (XDR: a Wazuh connection exists). */
  feature?: NavFeature;
}

/** Only screens that exist are listed; nothing is shown as a teaser. */
export const NAV: { label: MessageKey; items: NavItem[] }[] = [
  {
    label: "shell.groupDaily",
    items: [
      { to: "/", label: "nav.overview", icon: LayoutGrid },
      { to: "/findings", label: "nav.findings", icon: Bug },
    ],
  },
  {
    label: "shell.groupCode",
    items: [
      { to: "/repositories", label: "nav.repositories", icon: GitBranch },
      { to: "/gates", label: "nav.gates", icon: ShieldCheck },
      { to: "/fixes", label: "nav.fixes", icon: GitPullRequest },
      { to: "/packages", label: "nav.packages", icon: Package },
    ],
  },
  {
    label: "shell.groupInfrastructure",
    items: [
      { to: "/servers", label: "nav.servers", icon: Server },
      { to: "/xdr", label: "nav.xdr", icon: Radar, feature: "xdr" },
      // Built from Wazuh's alerts, so it is listed with the XDR page: only while a Wazuh connection exists.
      { to: "/attacks", label: "nav.attacks", icon: Globe, feature: "xdr" },
    ],
  },
  {
    label: "shell.groupAdmin",
    items: [
      { to: "/settings", label: "nav.settings", icon: Settings },
      { to: "/team", label: "nav.team", icon: Users, adminOnly: true },
      { to: "/audit-log", label: "nav.auditLog", icon: ScrollText, adminOnly: true },
    ],
  },
];

export const isAdmin = (me: Me) => me.role === "owner" || me.role === "admin";

/** The navigation as this user sees it, with the screens of the connected features. */
export function navFor(me: Me, features: NavFeatures = {}) {
  return NAV.map((group) => ({
    ...group,
    items: group.items.filter(
      (item) => (!item.adminOnly || isAdmin(me)) && (!item.feature || features[item.feature] === true),
    ),
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
