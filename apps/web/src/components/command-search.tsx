import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  Boxes,
  Bug,
  GitBranch,
  Globe,
  type LucideIcon,
  Network,
  Package,
  Radar,
  Search,
  Server,
  Sparkles,
  Telescope,
  UserRound,
} from "lucide-react";
import { type KeyboardEvent, useEffect, useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import type { Me } from "../lib/session.ts";
import { xdrStatusQuery } from "../lib/xdr.ts";
import { isAdmin, navFor } from "./nav.ts";
import { Dialog } from "./ui/dialog.tsx";

interface Option {
  id: string;
  label: string;
  /** What kind of hit it is, shown muted after the label. */
  hint?: string;
  icon: LucideIcon;
  go: () => void;
}

interface Hits {
  repositories: { id: string; name: string }[];
  servers: { id: string; name: string }[];
  guests: { id: string; name: string; vmid: number }[];
  assets: { id: string; value: string }[];
  vulnerabilities: { id: string }[];
  packages: { name: string; type: string }[];
}

/**
 * Search box in the top bar (Ctrl K or ⌘ K). From two characters on it shows a few
 * matching repositories, vulnerabilities and packages; below them it offers the
 * findings, packages or repositories list with the text as filter, and pages whose
 * name matches. Results stay in the URL, so they can be shared like any other filter.
 */
export function CommandSearch({ me }: { me: Me }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const optionId = (index: number) => `${listId}-${index}`;

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const close = () => {
    setOpen(false);
    setText("");
    setActive(0);
  };

  // Ask the API only after typing pauses.
  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(text.trim()), 200);
    return () => clearTimeout(timer);
  }, [text]);
  const xdr = useQuery(xdrStatusQuery);
  const hits = useQuery({
    queryKey: ["search", debounced],
    queryFn: () => api<Hits>(`/search?q=${encodeURIComponent(debounced)}`),
    enabled: open && debounced.length >= 2,
    placeholderData: keepPreviousData,
  });

  const options = useMemo<Option[]>(() => {
    const q = text.trim();
    const found: Option[] =
      q.length >= 2 && hits.data
        ? [
            ...hits.data.repositories.map((r) => ({
              id: `repo:${r.id}`,
              label: r.name,
              hint: t("shell.searchKindRepository"),
              icon: GitBranch,
              go: () => navigate({ to: "/repositories/$id", params: { id: r.id } }),
            })),
            ...hits.data.servers.map((s) => ({
              id: `server:${s.id}`,
              label: s.name,
              hint: t("shell.searchKindServer"),
              icon: Server,
              go: () => navigate({ to: "/servers/$id", params: { id: s.id } }),
            })),
            ...hits.data.assets.map((x) => ({
              id: `asset:${x.id}`,
              label: x.value,
              hint: t("shell.searchKindAsset"),
              icon: Telescope,
              go: () => navigate({ to: "/exposure/$id", params: { id: x.id }, search: {} }),
            })),
            ...hits.data.guests.map((g) => ({
              id: `guest:${g.id}`,
              label: g.name,
              hint: `${t("shell.searchKindGuest")} ${g.vmid}`,
              icon: Boxes,
              go: () => navigate({ to: "/servers", search: { view: "proxmox", guest: g.id } }),
            })),
            ...hits.data.vulnerabilities.map((v) => ({
              id: `vuln:${v.id}`,
              label: v.id,
              hint: t("shell.searchKindVulnerability"),
              icon: Bug,
              go: () => navigate({ to: "/findings", search: { q: v.id, state: "all" } }),
            })),
            ...hits.data.packages.map((p) => ({
              id: `pkg:${p.name}`,
              label: p.name,
              hint: t("shell.searchKindPackage", { type: p.type }),
              icon: Package,
              go: () => navigate({ to: "/packages", search: { q: p.name } }),
            })),
          ]
        : [];
    const pages: Option[] = navFor(me, {
      xdr: xdr.data?.connected === true,
      attacks: xdr.data?.attacks === true,
    })
      .flatMap((group) => group.items)
      .filter((item) => !q || t(item.label).toLowerCase().includes(q.toLowerCase()))
      .map((item) => ({
        id: `page:${item.to}`,
        label: t("shell.searchGoTo", { page: t(item.label) }),
        icon: item.icon,
        go: () => navigate({ to: item.to }),
      }));
    // Proxmox is a view of the Servers page, not a page of its own, so it is offered here by name.
    const proxmoxName = t("proxmox.viewProxmox");
    if (!q || proxmoxName.toLowerCase().includes(q.toLowerCase())) {
      pages.push({
        id: "page:proxmox",
        label: t("shell.searchGoTo", { page: proxmoxName }),
        icon: Boxes,
        go: () => navigate({ to: "/servers", search: { view: "proxmox" } }),
      });
    }
    // The UniFi network devices are a view of the Servers page too (ADR 0022).
    const unifiName = t("unifi.viewUnifi");
    if (!q || unifiName.toLowerCase().includes(q.toLowerCase())) {
      pages.push({
        id: "page:unifi",
        label: t("shell.searchGoTo", { page: unifiName }),
        icon: Network,
        go: () => navigate({ to: "/servers", search: { view: "unifi" } }),
      });
    }
    // Settings, AI is a section of the settings page, so it is offered here by name (owners and admins).
    const aiName = t("ai.settingsPageName");
    if (isAdmin(me) && (!q || aiName.toLowerCase().includes(q.toLowerCase()))) {
      pages.push({
        id: "page:settings-ai",
        label: t("shell.searchGoTo", { page: aiName }),
        icon: Sparkles,
        go: () => navigate({ to: "/settings", search: { section: "ai" } }),
      });
    }
    // Settings, XDR / Wazuh is a section of the settings page (owners and admins).
    const xdrName = t("xdr.settingsPageName");
    if (isAdmin(me) && (!q || xdrName.toLowerCase().includes(q.toLowerCase()))) {
      pages.push({
        id: "page:settings-xdr",
        label: t("shell.searchGoTo", { page: xdrName }),
        icon: Radar,
        go: () => navigate({ to: "/settings", search: { section: "xdr" } }),
      });
    }
    // Settings, Exposure is a section of the settings page (owners and admins).
    const exposureName = t("exposure.settingsPageName");
    if (isAdmin(me) && (!q || exposureName.toLowerCase().includes(q.toLowerCase()))) {
      pages.push({
        id: "page:settings-exposure",
        label: t("shell.searchGoTo", { page: exposureName }),
        icon: Telescope,
        go: () => navigate({ to: "/settings", search: { section: "exposure" } }),
      });
    }
    // Settings, Attack overview is a section of the settings page (owners and admins).
    const attacksName = t("attacks.settingsPageName");
    if (isAdmin(me) && (!q || attacksName.toLowerCase().includes(q.toLowerCase()))) {
      pages.push({
        id: "page:settings-attacks",
        label: t("shell.searchGoTo", { page: attacksName }),
        icon: Globe,
        go: () => navigate({ to: "/settings", search: { section: "attacks" } }),
      });
    }
    // The account page is opened from the avatar menu, so it is offered here too: the page and its sections.
    for (const [section, name] of [
      [undefined, t("account.title")],
      ["password", t("account.nav.password")],
      ["authenticator", t("account.nav.authenticator")],
      ["passkeys", t("account.nav.passkeys")],
      ["sessions", t("account.nav.sessions")],
      ["notifications", t("account.nav.notifications")],
    ] as const) {
      // Without a search text only the page itself is listed; its sections appear when typing.
      if (q ? !name.toLowerCase().includes(q.toLowerCase()) : section !== undefined) continue;
      pages.push({
        id: `page:account-${section ?? "profile"}`,
        label: t("shell.searchGoTo", { page: section ? `${t("account.title")}: ${name}` : name }),
        icon: UserRound,
        go: () => navigate({ to: "/account", search: section ? { section } : {} }),
      });
    }
    if (!q) return pages;
    return [
      ...found,
      {
        id: "findings",
        label: t("shell.searchFindings", { text: q }),
        icon: Bug,
        go: () => navigate({ to: "/findings", search: { q, state: "all" } }),
      },
      {
        id: "packages",
        label: t("shell.searchPackages", { text: q }),
        icon: Package,
        go: () => navigate({ to: "/packages", search: { q } }),
      },
      {
        id: "repositories",
        label: t("shell.searchRepositories", { text: q }),
        icon: GitBranch,
        go: () => navigate({ to: "/repositories", search: { q } }),
      },
      {
        id: "servers",
        label: t("shell.searchServers", { text: q }),
        icon: Server,
        go: () => navigate({ to: "/servers", search: { q } }),
      },
      {
        id: "proxmox",
        label: t("shell.searchProxmox", { text: q }),
        icon: Boxes,
        go: () => navigate({ to: "/servers", search: { view: "proxmox", pxQ: q } }),
      },
      ...pages,
    ];
  }, [text, hits.data, me, t, navigate, xdr.data?.connected, xdr.data?.attacks]);

  const choose = (option: Option | undefined) => {
    if (!option) return;
    close();
    option.go();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((i) => Math.min(i + 1, options.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(options[active]);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-keyshortcuts="Control+K Meta+K"
        className="flex h-9 w-[clamp(12rem,16vw,20rem)] items-center gap-2 overflow-hidden rounded-md border border-input bg-card px-2.5 text-sm whitespace-nowrap text-muted-foreground shadow-xs hover:bg-accent"
      >
        <Search aria-hidden="true" className="size-4 flex-none" />
        <span className="min-w-0 truncate">{t("shell.searchPlaceholder")}</span>
        <kbd className="ml-auto flex-none rounded border bg-muted px-1.5 font-mono text-xs">Ctrl K</kbd>
      </button>
      <Dialog open={open} onClose={close} title={t("shell.searchTitle")}>
        <div className="grid gap-3">
          <input
            type="search"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={options[active] ? optionId(active) : undefined}
            aria-label={t("shell.searchTitle")}
            placeholder={t("shell.searchPlaceholder")}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            className="h-10 w-full rounded-md border border-input bg-card px-3 text-base shadow-xs placeholder:text-muted-foreground"
          />
          <div id={listId} role="listbox" aria-label={t("shell.searchTitle")} className="grid gap-0.5">
            {options.map((option, index) => (
              // Keyboard selection happens in the combobox input (aria-activedescendant).
              <div
                key={option.id}
                id={optionId(index)}
                role="option"
                aria-selected={index === active}
                tabIndex={-1}
                onMouseMove={() => setActive(index)}
                onClick={() => choose(option)}
                onKeyDown={(e) => e.key === "Enter" && choose(option)}
                className={cn(
                  "flex h-10 cursor-pointer items-center gap-2.5 rounded-md px-2.5",
                  index === active && "bg-accent",
                )}
              >
                <option.icon aria-hidden="true" className="size-4 flex-none text-muted-foreground" />
                <span className="truncate">{option.label}</span>
                {option.hint ? (
                  <span className="ml-auto flex-none text-sm text-muted-foreground">{option.hint}</span>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      </Dialog>
    </>
  );
}
