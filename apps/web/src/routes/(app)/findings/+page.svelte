<script lang="ts" module>
  import { SEVERITIES } from "@garnetops/core";
  import type { Severity } from "#lib/types.ts";

  const STATES = ["open", "accepted", "resolved", "all"] as const;
  const FILTER_SEVERITIES = SEVERITIES.filter((s) => s !== "negligible" && s !== "unknown") as Severity[];
</script>

<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { Bug, ScanSearch } from "@lucide/svelte";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import { cn } from "#lib/cn.ts";
  import AiPanel from "#lib/components/ai/AiPanel.svelte";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import FindingDetail from "#lib/components/findings/FindingDetail.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import SortHeader, { type SortDir } from "#lib/components/SortHeader.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import Drawer from "#lib/components/ui/Drawer.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { formatDate, formatDateTime, formatPercent, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { layoutStep } from "#lib/layout-step.svelte.ts";
  import { rowClick } from "#lib/row-link.ts";
  import { type FindingSearch, findingSearch, toQuery } from "#lib/search.ts";
  import { findingCountsQuery } from "#lib/shell.ts";
  import type { FindingRow, Page, RepositoryRow } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const search: FindingSearch = $derived(parseSearch(findingSearch, page.url));

  const list = createQuery(() => ({
    queryKey: ["findings", { ...search, id: undefined, ai: undefined }],
    queryFn: () => api<Page<FindingRow>>(`/findings${toQuery(search, ["id", "ai"])}`),
    placeholderData: keepPreviousData,
  }));
  // Counts per state for the tabs, under every other filter.
  const counts = createQuery(() => ({
    ...findingCountsQuery(toQuery(search, ["id", "ai", "cursor", "pageSize", "state"])),
    placeholderData: keepPreviousData,
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));

  const go = (next: Partial<FindingSearch>, replace = false) =>
    goto(href(page.url.pathname, next), { reset: false, replace });
  const setSearch = (patch: Partial<FindingSearch>, replace = false) =>
    go({ ...search, cursor: undefined, ...patch }, replace);

  // From the xwide step there is room for list and detail side by side (mockup), so the
  // first finding is shown until the user picks one. Below it the list stays full width.
  const step = $derived(layoutStep());
  const shownId = $derived(search.id ?? (step === "xwide" ? list.data?.items[0]?.id : undefined));
  // At xwide the AI conversation is a third pane (AGENTS.md rule 5); below it, a drawer behind a click.
  const aiPane = $derived(step === "xwide");

  const queryClient = useQueryClient();
  let queued = $state<number | null>(null);
  const scan = createMutation(() => ({
    mutationFn: async () => {
      if (search.repositoryId) {
        await api(`/repositories/${search.repositoryId}/scans`, { method: "POST" });
        return 1;
      }
      return (await api<{ queued: number }>("/repositories/scan-all", { method: "POST" })).queued;
    },
    onSuccess: async (n: number) => {
      queued = n;
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
    },
  }));

  const onSort = (sort: string | undefined, dir: SortDir | undefined) =>
    setSearch({ sort: sort as FindingSearch["sort"], dir });

  const selected = $derived(new Set((search.severity ?? "").split(",").filter(Boolean)));
  function toggleSeverity(s: Severity) {
    const next = new Set(selected);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSearch({ severity: next.size ? [...next].join(",") : undefined });
  }
  const hasFilters = $derived(
    Boolean(
      search.severity ||
        search.repositoryId ||
        search.scanId ||
        search.kev ||
        search.fixable ||
        search.q ||
        search.state,
    ),
  );
</script>

<!-- A value the vulnerability database does not have, announced as such to screen readers. -->
{#snippet missing()}
  <span class="font-sans text-muted-foreground" title={t("findings.notAvailable")}>
    <span aria-hidden="true">–</span>
    <span class="sr-only">{t("findings.notAvailable")}</span>
  </span>
{/snippet}

{#snippet filterCheckbox(label: string, checked: boolean, onChange: (on: boolean) => void)}
  <label class="flex items-center gap-2 text-sm whitespace-nowrap">
    <Checkbox {checked} onchange={(e) => onChange(e.currentTarget.checked)} />
    {label}
  </label>
{/snippet}

{#snippet epssLabel()}
  <abbr title={t("findings.epssHint")} class="no-underline">{t("findings.epss")}</abbr>
{/snippet}

{#snippet headerActions()}
  {#if scan.isError}
    <span role="alert" class="text-sm text-destructive-text">{t("errors.actionFailed")}</span>
  {:else if queued !== null}
    <span role="status" class="text-sm text-muted-foreground">{t("overview.scansQueued", { count: queued })}</span>
  {/if}
  <ExportMenu filters={{ ...search, id: undefined, ai: undefined, cursor: undefined, pageSize: undefined }} />
  {#if me.role !== "viewer"}
    <Button disabled={scan.isPending} onclick={() => scan.mutate()}>
      <ScanSearch aria-hidden="true" class="size-4" />
      {search.repositoryId ? t("findings.scanFiltered") : t("repositories.scanNow")}
    </Button>
  {/if}
{/snippet}

<PageHeader icon={Bug} title={t("findings.title")} description={t("findings.description")} actions={headerActions} />

<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("findings.stateFilter")}
    value={search.state ?? "open"}
    options={STATES.map((s) => ({
      value: s,
      label: t(`findingState.${s}`),
      count: counts.data
        ? s === "all"
          ? counts.data.states.open + counts.data.states.accepted + counts.data.states.resolved
          : counts.data.states[s]
        : null,
    }))}
    onChange={(state) => setSearch({ state: state === "open" ? undefined : state })}
  />
  <fieldset class="flex flex-wrap gap-1.5">
    <legend class="sr-only">{t("findings.severityFilter")}</legend>
    {#each FILTER_SEVERITIES as s (s)}
      <button
        type="button"
        aria-pressed={selected.has(s)}
        onclick={() => toggleSeverity(s)}
        class={cn(
          "rounded-md border p-0.5",
          selected.has(s) ? "border-ring" : "border-transparent opacity-70 hover:opacity-100",
        )}
      >
        <SeverityBadge severity={s} />
      </button>
    {/each}
  </fieldset>
  <Select
    aria-label={t("findings.repository")}
    value={search.repositoryId ?? ""}
    onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined })}
    class="max-w-56"
  >
    <option value="">{t("findings.allRepositories")}</option>
    {#each repositories.data?.items ?? [] as r (r.id)}
      <option value={r.id}>{r.name}</option>
    {/each}
  </Select>
  {@render filterCheckbox(t("findings.knownExploitedOnly"), search.kev === "1", (on) =>
    setSearch({ kev: on ? "1" : undefined }),
  )}
  {@render filterCheckbox(t("findings.fixableOnly"), search.fixable === "1", (on) =>
    setSearch({ fixable: on ? "1" : undefined }),
  )}
  <SearchInput
    class="ml-auto"
    label={t("findings.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
  <!-- Always rendered so the toolbar never shifts when a filter is set; hidden while nothing is filtered. -->
  <button
    type="button"
    onclick={() => go({})}
    disabled={!hasFilters}
    aria-hidden={!hasFilters}
    tabindex={hasFilters ? undefined : -1}
    class={cn("text-sm font-medium text-primary-text hover:underline", !hasFilters && "invisible")}
  >
    {t("findings.clearFilters")}
  </button>
</div>

<div
  class={cn(
    "grid gap-4",
    shownId && "@wide:grid-cols-[minmax(0,1fr)_28rem] @xwide:grid-cols-[minmax(0,1fr)_32rem_30rem]",
  )}
>
  <!-- The table answers to the width of its own card, which is narrower when panes sit beside it. -->
  <Card class="@container/list self-start">
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <SortHeader
            column="vulnerability"
            label={t("findings.columnFinding")}
            natural="asc"
            class="px-5"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="cvss"
            label={t("findings.columnCvss")}
            natural="desc"
            align="right"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="epss"
            label={epssLabel}
            natural="desc"
            align="right"
            class="hidden px-3 @6xl/list:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="published"
            label={t("findings.columnPublished")}
            natural="desc"
            class="hidden px-3 @3xl/list:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="package"
            label={t("findings.columnPackage")}
            natural="asc"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <th class="hidden px-3 py-2.5 font-medium @4xl/list:table-cell">{t("findings.columnFixedIn")}</th>
          <SortHeader
            column="repository"
            label={t("findings.columnRepository")}
            natural="asc"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="firstSeen"
            label={t("findings.columnFirstSeen")}
            natural="desc"
            class="hidden px-5 @5xl/list:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
        </tr>
      </thead>
      <tbody>
        {#each list.data?.items ?? [] as f (f.id)}
          <tr
            aria-selected={f.id === shownId}
            class="row-link border-b align-top last:border-0"
            onclick={rowClick(() => setSearch({ id: f.id, cursor: search.cursor }))}
          >
            <td class="px-5 py-2.5">
              <div class="mb-1"><SeverityBadge severity={f.severity} /></div>
              <button
                type="button"
                onclick={() => setSearch({ id: f.id, cursor: search.cursor })}
                aria-current={f.id === shownId ? "true" : undefined}
                class="text-left font-medium break-all hover:underline"
              >
                {f.vulnerabilityId}
              </button>
              {#if f.knownExploited}<div class="text-sm text-destructive-text">{t("findings.kev")}</div>{/if}
            </td>
            <td class="px-3 py-2.5 text-right font-mono text-sm tabular-nums">
              {#if f.cvssScore !== null}{f.cvssScore.toFixed(1)}{:else}{@render missing()}{/if}
            </td>
            <td class="hidden px-3 py-2.5 text-right font-mono text-sm tabular-nums @6xl/list:table-cell">
              {#if f.epss !== null}{formatPercent(f.epss)}{:else}{@render missing()}{/if}
            </td>
            <td class="hidden px-3 py-2.5 text-sm whitespace-nowrap @3xl/list:table-cell">
              {#if f.publishedAt}
                <time datetime={f.publishedAt} title={formatDateTime(f.publishedAt)}>{formatDate(f.publishedAt)}</time>
              {:else}
                {@render missing()}
              {/if}
            </td>
            <td class="px-3 py-2.5 font-mono text-sm break-all">
              {f.packageName}
              <div class="text-muted-foreground">{f.packageVersion}</div>
            </td>
            <td class="hidden px-3 py-2.5 font-mono text-sm break-all @4xl/list:table-cell">
              {#if f.fixedIn?.length}
                {f.fixedIn.join(", ")}
              {:else}
                <span class="font-sans text-muted-foreground">{t("findings.noFix")}</span>
              {/if}
            </td>
            <td class="px-3 py-2.5"><RepositoryLink id={f.repositoryId} name={f.repositoryName} /></td>
            <td class="hidden px-5 py-2.5 text-sm whitespace-nowrap @5xl/list:table-cell">
              <time datetime={f.firstSeenAt}>{formatDateTime(f.firstSeenAt)}</time>
              <div class="text-muted-foreground">{formatRelative(f.firstSeenAt)}</div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && list.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">{t("findings.empty")}</p>
    {/if}
    {#if list.data}
      <Pagination
        page={list.data}
        onCursor={(cursor) => go({ ...search, cursor })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>

  {#if shownId}
    {#key shownId}
      <FindingDetail
        id={shownId}
        canEdit={me.role !== "viewer"}
        onClose={search.id ? () => setSearch({ id: undefined, ai: undefined, cursor: search.cursor }, true) : undefined}
        onAskAi={aiPane ? undefined : () => setSearch({ ai: "1", cursor: search.cursor }, true)}
      />
    {/key}
  {/if}
  <!-- The pane is sized to start below the header and filters and still end inside the screen. -->
  {#if shownId && aiPane}
    <div class="sticky top-0 h-[calc(100dvh-15rem)] self-start">
      {#key shownId}<AiPanel findingId={shownId} {me} variant="pane" />{/key}
    </div>
  {/if}
</div>
<Drawer
  open={Boolean(shownId) && !aiPane && search.ai === "1"}
  onClose={() => setSearch({ ai: undefined, cursor: search.cursor }, true)}
  title={t("ai.panelTitle")}
>
  {#if shownId}
    {#key shownId}<AiPanel findingId={shownId} {me} variant="drawer" />{/key}
  {/if}
</Drawer>
