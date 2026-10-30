<script lang="ts" module>
  import type { FixSearch } from "../../search.ts";

  export type SetFixSearch = (patch: Partial<FixSearch>, replace?: boolean) => unknown;
</script>

<script lang="ts">
  import { SEVERITIES } from "@garnetops/core";
  import { TriangleAlert } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api } from "../../api.ts";
  import { cn } from "../../cn.ts";
  import { type CreateVia, isBusy } from "../../fixes.ts";
  import { t } from "../../i18n.svelte.ts";
  import { layoutStep } from "../../layout-step.svelte.ts";
  import { rowClick } from "../../row-link.ts";
  import { toQuery } from "../../search.ts";
  import type { Me } from "../../session.ts";
  import type { FixProposalPage, FixProposalRow, Page, RepositoryRow, Severity } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import Pagination from "../Pagination.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import SearchInput from "../SearchInput.svelte";
  import Segmented from "../Segmented.svelte";
  import SortHeader, { type SortDir } from "../SortHeader.svelte";
  import Badge from "../ui/Badge.svelte";
  import Drawer from "../ui/Drawer.svelte";
  import Select from "../ui/Select.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import CreatePrDialog from "./CreatePrDialog.svelte";
  import FixDetail from "./FixDetail.svelte";
  import FixStatus from "./FixStatus.svelte";

  const ACTIONS = ["all", "edit", "manual"] as const;
  const ACTION_LABELS = {
    all: "fixes.actionAll",
    edit: "fixes.actionEdit",
    manual: "fixes.actionManual",
  } as const;
  const PR_FILTERS = ["all", "none", "open", "merged", "closed", "failed"] as const;
  const ECOSYSTEMS = ["npm", "pypi", "go", "cargo", "composer", "other"] as const;
  const FILTER_SEVERITIES = SEVERITIES.filter((s) => s !== "negligible" && s !== "unknown") as Severity[];

  /** The list of fix proposals with its filters and the detail pane (or drawer) of the selected one. */
  let {
    search,
    setSearch,
    me,
  }: {
    search: FixSearch;
    setSearch: SetFixSearch;
    me: Me;
  } = $props();

  const role = $derived(me.role);
  const step = $derived(layoutStep());
  const apiQuery = $derived(toQuery(search, ["id", "view", "prState"]));
  const list = createQuery(() => ({
    queryKey: ["fixes", "proposals", apiQuery],
    queryFn: () => api<FixProposalPage>(`/fixes${apiQuery}`),
    placeholderData: keepPreviousData,
    // A pull request that is being created shows up by itself.
    refetchInterval: (q: { state: { data: FixProposalPage | undefined } }) =>
      q.state.data?.items.some((i) => isBusy(i.pr?.state)) ? 3000 : false,
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
  let creating = $state<{ proposal: FixProposalRow; via: CreateVia } | null>(null);

  const sortProps = $derived({
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as FixSearch["sort"], dir }),
  });
  const items = $derived(list.data?.items ?? []);
  // From the wide step there is room for list and detail side by side; below it the detail is a drawer.
  const sidePane = $derived(step !== "base");
  const shown = $derived(items.find((i) => i.key === search.id) ?? (step === "xwide" ? items[0] : undefined));
  const select = (key: string | undefined) => setSearch({ id: key, cursor: search.cursor }, true);

  const selectedSeverities = $derived(new Set((search.severity ?? "").split(",").filter(Boolean)));
  const toggleSeverity = (s: Severity) => {
    const next = new Set(selectedSeverities);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSearch({ severity: next.size ? [...next].join(",") : undefined });
  };
  const hasFilters = $derived(
    Boolean(search.action || search.severity || search.ecosystem || search.pr || search.repositoryId || search.q),
  );
  const navigate = (next: FixSearch) => void goto(href(page.url.pathname, next), { reset: false });
</script>

<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("fixes.actionLabel")}
    value={search.action ?? "all"}
    options={ACTIONS.map((a) => ({
      value: a,
      label: t(ACTION_LABELS[a]),
      count: list.data ? list.data.counts[a] : null,
    }))}
    onChange={(action) => setSearch({ action: action === "all" ? undefined : action })}
  />
  <fieldset class="flex flex-wrap gap-1.5">
    <legend class="sr-only">{t("fixes.severityFilter")}</legend>
    {#each FILTER_SEVERITIES as s (s)}
      <button
        type="button"
        aria-pressed={selectedSeverities.has(s)}
        onclick={() => toggleSeverity(s)}
        class={cn(
          "rounded-md border p-0.5",
          selectedSeverities.has(s) ? "border-ring" : "border-transparent opacity-70 hover:opacity-100",
        )}
      >
        <SeverityBadge severity={s} />
      </button>
    {/each}
  </fieldset>
  <Select
    aria-label={t("fixes.repository")}
    value={search.repositoryId ?? ""}
    onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined })}
    class="max-w-56"
  >
    <option value="">{t("fixes.allRepositories")}</option>
    {#each repositories.data?.items ?? [] as r (r.id)}
      <option value={r.id}>{r.name}</option>
    {/each}
  </Select>
  <Select
    aria-label={t("fixes.ecosystem")}
    value={search.ecosystem ?? ""}
    onchange={(e) => setSearch({ ecosystem: (e.currentTarget.value || undefined) as FixSearch["ecosystem"] })}
    class="max-w-44"
  >
    <option value="">{t("fixes.allEcosystems")}</option>
    {#each ECOSYSTEMS as e (e)}
      <option value={e}>{e === "other" ? t("fixes.ecosystemOther") : e}</option>
    {/each}
  </Select>
  <Select
    aria-label={t("fixes.prFilter")}
    value={search.pr ?? "all"}
    onchange={(e) =>
      setSearch({ pr: e.currentTarget.value === "all" ? undefined : (e.currentTarget.value as FixSearch["pr"]) })}
    class="max-w-56"
  >
    {#each PR_FILTERS as f (f)}
      <option value={f}>{f === "all" ? t("fixes.prAll") : f === "none" ? t("fixes.prNone") : t(`fixes.prState.${f}`)}</option>
    {/each}
  </Select>
  <SearchInput
    class="ml-auto"
    label={t("fixes.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
  <button
    type="button"
    onclick={() => navigate({})}
    disabled={!hasFilters}
    aria-hidden={!hasFilters}
    tabindex={hasFilters ? undefined : -1}
    class={cn("text-sm font-medium text-primary-text hover:underline", !hasFilters && "invisible")}
  >
    {t("fixes.clearFilters")}
  </button>
</div>

<div
  class={cn(
    "grid gap-4",
    sidePane && shown && "@wide:grid-cols-[minmax(0,1fr)_28rem] @xwide:grid-cols-[minmax(0,1fr)_32rem]",
  )}
>
  <Card class="@container/list self-start">
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <SortHeader column="package" label={t("fixes.columnPackage")} natural="asc" class="px-5" {...sortProps} />
          <SortHeader column="severity" label={t("fixes.columnSeverity")} natural="asc" class="px-3" {...sortProps} />
          <SortHeader
            column="repository"
            label={t("fixes.columnRepository")}
            natural="asc"
            class="hidden px-3 @2xl/list:table-cell"
            {...sortProps}
          />
          <th class="hidden px-3 py-2.5 font-medium @4xl/list:table-cell">
            {t("fixes.columnFile")}
          </th>
          <th class="hidden px-3 py-2.5 font-medium @5xl/list:table-cell">
            {t("fixes.columnDependency")}
          </th>
          <th class="hidden px-3 py-2.5 font-medium @7xl/list:table-cell">
            {t("fixes.columnSuggestion")}
          </th>
          <SortHeader column="status" label={t("fixes.columnStatus")} natural="asc" class="px-5" {...sortProps} />
        </tr>
      </thead>
      <tbody>
        {#each items as p (p.key)}
          <tr
            aria-selected={p.key === shown?.key}
            class="row-link border-b align-top last:border-0"
            onclick={rowClick(() => select(p.key))}
          >
            <td class="px-5 py-2.5">
              <button
                type="button"
                onclick={() => select(p.key)}
                aria-current={p.key === shown?.key ? "true" : undefined}
                class="text-left font-mono font-medium break-all hover:underline"
              >
                {p.packageName}
              </button>
              <div class="font-mono text-sm whitespace-nowrap text-muted-foreground">
                {p.targetVersion
                  ? t("fixes.versionChange", { from: p.installedVersion, to: p.targetVersion })
                  : `${p.installedVersion} · ${t("fixes.noVersion")}`}
              </div>
              <div class="mt-1 flex flex-wrap items-center gap-1.5">
                <span class="text-sm text-muted-foreground">{p.packageType}</span>
                {#if p.majorUpgrade}
                  <Badge tone="outline">
                    <TriangleAlert aria-hidden="true" />
                    {t("fixes.majorUpgrade")}
                  </Badge>
                {/if}
                {#if p.dev}<Badge tone="neutral">{t("fixes.dev")}</Badge>{/if}
              </div>
            </td>
            <td class="px-3 py-2.5">
              <div class="mb-1">
                <SeverityBadge severity={p.severity} />
              </div>
              <a
                href={href("/findings", { repositoryId: p.repositoryId, q: p.packageName })}
                class="text-sm whitespace-nowrap hover:underline"
              >
                {t("fixes.vulnerabilities", { count: p.vulnerabilityIds.length })}
              </a>
            </td>
            <td class="hidden px-3 py-2.5 @2xl/list:table-cell">
              <RepositoryLink id={p.repositoryId} name={p.repositoryName} />
            </td>
            <td class="hidden px-3 py-2.5 font-mono text-sm break-words @4xl/list:table-cell">
              {#if p.manifestPath !== null}{p.manifestPath}{:else}<span class="font-sans text-muted-foreground"
                  >–</span
                >{/if}
            </td>
            <td class="hidden px-3 py-2.5 text-sm @5xl/list:table-cell">
              {p.dependency === "direct"
                ? t("fixes.direct")
                : p.dependency === "transitive"
                  ? t("fixes.transitive")
                  : t("fixes.unknownDependency")}
            </td>
            <td class="hidden max-w-80 px-3 py-2.5 text-sm @7xl/list:table-cell">
              {#if p.aiSuggestion}
                <Badge tone="outline" class="mb-1">
                  {t("fixes.aiLabel")}
                </Badge>
                <p class="line-clamp-3">{p.aiSuggestion.summary}</p>
              {:else}
                <span class="text-muted-foreground">–</span>
              {/if}
            </td>
            <td class="px-5 py-2.5">
              <FixStatus
                row={p}
                canCreate={role !== "viewer"}
                admin={role === "owner" || role === "admin"}
                onCreate={(via) => (creating = { proposal: p, via })}
              />
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && list.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">
        {hasFilters ? t("fixes.emptyFiltered") : t("fixes.empty")}
      </p>
    {/if}
    {#if list.data}
      <Pagination
        page={list.data}
        onCursor={(cursor) => navigate({ ...search, cursor })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>

  {#if sidePane && shown}
    {#key shown.key}
      <FixDetail
        proposal={shown}
        canCreate={role !== "viewer"}
        onCreate={(via) => (creating = shown ? { proposal: shown, via } : null)}
        onClose={search.id ? () => select(undefined) : undefined}
      />
    {/key}
  {/if}
</div>
<Drawer open={!sidePane && Boolean(search.id && shown)} onClose={() => select(undefined)} title={t("fixes.detailTitle")}>
  {#if !sidePane && shown}
    <div class="p-4">
      {#key shown.key}
        <FixDetail proposal={shown} canCreate={role !== "viewer"} onCreate={(via) => (creating = shown ? { proposal: shown, via } : null)} />
      {/key}
    </div>
  {/if}
</Drawer>
{#if creating}
  <CreatePrDialog proposal={creating.proposal} via={creating.via} {me} onClose={() => (creating = null)} onCreated={() => (creating = null)} />
{/if}
