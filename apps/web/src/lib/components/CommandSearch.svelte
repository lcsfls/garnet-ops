<script lang="ts">
  import {
    Bug,
    GitBranch,
    Globe,
    type LucideIcon,
    Package,
    Search,
    Sparkles,
    UserRound,
  } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { api } from "../api.ts";
  import { cn } from "../cn.ts";
  import { t } from "../i18n.svelte.ts";
  import { isAdmin, navFor } from "../nav.ts";
  import type { Me } from "../session.ts";
  import { href } from "../url.ts";
  import Dialog from "./ui/Dialog.svelte";

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
    vulnerabilities: { id: string }[];
    packages: { name: string; type: string }[];
    /** Monitored websites; only while the module is on (ADR 0033), and from older servers not at all. */
    websites?: { id: string; value: string }[];
  }

  /**
   * Search box in the top bar (Ctrl K or ⌘ K). From two characters on it shows a few
   * matching repositories, vulnerabilities and packages; below them it offers the
   * findings, packages or repositories list with the text as filter, and pages whose
   * name matches. Results stay in the URL, so they can be shared like any other filter.
   */
  let { me }: { me: Me } = $props();
  let open = $state(false);
  let text = $state("");
  let active = $state(0);
  const listId = $props.id();
  const optionId = (index: number) => `${listId}-${index}`;

  $effect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        open = true;
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const close = () => {
    open = false;
    text = "";
    active = 0;
  };

  // Ask the API only after typing pauses.
  let debounced = $state("");
  $effect(() => {
    const value = text.trim();
    const timer = setTimeout(() => (debounced = value), 200);
    return () => clearTimeout(timer);
  });
  const hits = createQuery(() => ({
    queryKey: ["search", debounced],
    queryFn: () => api<Hits>(`/search?q=${encodeURIComponent(debounced)}`),
    enabled: open && debounced.length >= 2,
    placeholderData: keepPreviousData,
  }));

  const options = $derived.by<Option[]>(() => {
    const q = text.trim();
    const data = hits.data;
    const found: Option[] =
      q.length >= 2 && data
        ? [
            ...data.repositories.map((r) => ({
              id: `repo:${r.id}`,
              label: r.name,
              hint: t("shell.searchKindRepository"),
              icon: GitBranch,
              go: () => void goto(`/repositories/${encodeURIComponent(r.id)}`),
            })),
            ...data.vulnerabilities.map((v) => ({
              id: `vuln:${v.id}`,
              label: v.id,
              hint: t("shell.searchKindVulnerability"),
              icon: Bug,
              go: () => void goto(href("/findings", { q: v.id, state: "all" })),
            })),
            ...data.packages.map((p) => ({
              id: `pkg:${p.name}`,
              label: p.name,
              hint: t("shell.searchKindPackage", { type: p.type }),
              icon: Package,
              go: () => void goto(href("/packages", { q: p.name })),
            })),
            ...(data.websites ?? []).map((w) => ({
              id: `site:${w.id}`,
              label: w.value,
              hint: t("shell.searchKindWebsite"),
              icon: Globe,
              go: () => void goto(`/websites/${encodeURIComponent(w.id)}`),
            })),
          ]
        : [];
    const pages: Option[] = navFor(me)
      .flatMap((group) => group.items)
      .filter((item) => !q || t(item.label).toLowerCase().includes(q.toLowerCase()))
      .map((item) => ({
        id: `page:${item.to}`,
        label: t("shell.searchGoTo", { page: t(item.label) }),
        icon: item.icon,
        go: () => void goto(item.to),
      }));
    // Settings, AI is a section of the settings page, so it is offered here by name (owners and admins).
    const aiName = t("ai.settingsPageName");
    if (isAdmin(me) && (!q || aiName.toLowerCase().includes(q.toLowerCase()))) {
      pages.push({
        id: "page:settings-ai",
        label: t("shell.searchGoTo", { page: aiName }),
        icon: Sparkles,
        go: () => void goto(href("/settings", { section: "ai" })),
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
        go: () => void goto(href("/account", { section })),
      });
    }
    if (!q) return pages;
    return [
      ...found,
      {
        id: "findings",
        label: t("shell.searchFindings", { text: q }),
        icon: Bug,
        go: () => void goto(href("/findings", { q, state: "all" })),
      },
      {
        id: "packages",
        label: t("shell.searchPackages", { text: q }),
        icon: Package,
        go: () => void goto(href("/packages", { q })),
      },
      {
        id: "repositories",
        label: t("shell.searchRepositories", { text: q }),
        icon: GitBranch,
        go: () => void goto(href("/repositories", { q })),
      },
      ...pages,
    ];
  });

  const choose = (option: Option | undefined) => {
    if (!option) return;
    close();
    option.go();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      active = Math.min(active + 1, options.length - 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      active = Math.max(active - 1, 0);
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(options[active]);
    }
  };
</script>

<button
  type="button"
  onclick={() => (open = true)}
  aria-keyshortcuts="Control+K Meta+K"
  class="flex h-9 w-[clamp(12rem,16vw,20rem)] items-center gap-2 overflow-hidden rounded-md border border-input bg-card px-2.5 text-sm whitespace-nowrap text-muted-foreground shadow-xs hover:bg-accent"
>
  <Search aria-hidden="true" class="size-4 flex-none" />
  <span class="min-w-0 truncate">{t("shell.searchPlaceholder")}</span>
  <kbd class="ml-auto flex-none rounded border bg-muted px-1.5 font-mono text-xs">Ctrl K</kbd>
</button>
<Dialog {open} onClose={close} title={t("shell.searchTitle")}>
  <div class="grid gap-3">
    <input
      type="search"
      role="combobox"
      aria-expanded="true"
      aria-controls={listId}
      aria-activedescendant={options[active] ? optionId(active) : undefined}
      aria-label={t("shell.searchTitle")}
      placeholder={t("shell.searchPlaceholder")}
      value={text}
      oninput={(e) => {
        text = e.currentTarget.value;
        active = 0;
      }}
      onkeydown={onKeyDown}
      class="h-10 w-full rounded-md border border-input bg-card px-3 text-base shadow-xs placeholder:text-muted-foreground"
    />
    <div id={listId} role="listbox" aria-label={t("shell.searchTitle")} class="grid gap-0.5">
      <!-- Not keyed by option id: two packages of different types can share a name. -->
      {#each options as option, index}
        <!-- Keyboard selection happens in the combobox input (aria-activedescendant). -->
        <div
          id={optionId(index)}
          role="option"
          aria-selected={index === active}
          tabindex={-1}
          onmousemove={() => (active = index)}
          onclick={() => choose(option)}
          onkeydown={(e) => e.key === "Enter" && choose(option)}
          class={cn("flex h-10 cursor-pointer items-center gap-2.5 rounded-md px-2.5", index === active && "bg-accent")}
        >
          <option.icon aria-hidden="true" class="size-4 flex-none text-muted-foreground" />
          <span class="truncate">{option.label}</span>
          {#if option.hint}
            <span class="ml-auto flex-none text-sm text-muted-foreground">{option.hint}</span>
          {/if}
        </div>
      {/each}
    </div>
  </div>
</Dialog>
