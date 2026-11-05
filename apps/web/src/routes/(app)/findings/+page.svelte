<script lang="ts" module>
  import { SEVERITIES } from "@garnetops/core";
  import type { Severity } from "#lib/types.ts";

  const STATES = ["open", "accepted", "resolved", "all"] as const;
  const FILTER_SEVERITIES = SEVERITIES.filter((s) => s !== "negligible" && s !== "unknown") as Severity[];
</script>

<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { Check, ScanSearch, ShieldAlert, X } from "@lucide/svelte";
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
  import Drawer from "#lib/components/ui/Drawer.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import {
    formatCalendarDate,
    formatDate,
    formatDateTime,
    formatDay,
    formatPercent,
    formatRelative,
  } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { layoutStep } from "#lib/layout-step.svelte.ts";
  import { rowClick } from "#lib/row-link.ts";
  import { type FindingSearch, findingSearch, toQuery } from "#lib/search.ts";
  import { findingCountsQuery } from "#lib/shell.ts";
  import type { FindingRow, Page, RepositoryRow } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import type { Snippet } from "svelte";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const search: FindingSearch = $derived(parseSearch(findingSearch, page.url));
  // Date filters are calendar days of the viewer's zone (as the statistics count them), so the API needs the zone.
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const dated = $derived(
    Boolean(search.firstSeenFrom || search.firstSeenTo || search.resolvedFrom || search.resolvedTo),
  );
  const apiSearch = $derived({ ...search, tz: dated ? timeZone : undefined });

  const list = createQuery(() => ({
    queryKey: ["findings", { ...apiSearch, id: undefined, ai: undefined }],
    queryFn: () => api<Page<FindingRow>>(`/findings${toQuery(apiSearch, ["id", "ai"])}`),
    placeholderData: keepPreviousData,
    // Scheduled scans open and resolve findings while the page is open.
    refetchInterval: 60_000,
  }));
  // Counts per state for the tabs, under every other filter.
  const counts = createQuery(() => ({
    ...findingCountsQuery(toQuery(apiSearch, ["id", "ai", "cursor", "pageSize", "state"])),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
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
  // The toggles' counts: per severity in the chosen state, under every filter but the severity one (API /findings/counts).
  const severityCounts = $derived.by(() => {
    const by = counts.data?.severities;
    if (!by) return null;
    const state = search.state ?? "open";
    const states = state === "all" ? (["open", "accepted", "resolved"] as const) : [state];
    const out: Partial<Record<string, number>> = {};
    for (const st of states) for (const [sev, n] of Object.entries(by[st] ?? {})) out[sev] = (out[sev] ?? 0) + (n ?? 0);
    return out;
  });

  // A column whose values are all empty on this page is left out (the export keeps it): "Published" is often unknown.
  const items = $derived(list.data?.items ?? []);
  const show = $derived({
    cvss: items.length === 0 || items.some((f) => f.cvssScore !== null),
    epss: items.length === 0 || items.some((f) => f.epss !== null),
    published: items.length === 0 || items.some((f) => f.publishedAt !== null),
  });

  const hasFilters = $derived(
    Boolean(
      search.severity ||
        search.repositoryId ||
        search.scanId ||
        search.kev ||
        search.fixable ||
        search.q ||
        search.state ||
        dated,
    ),
  );

  /** "12 Oct 2026" for one day, "5 Oct 2026 – 11 Oct 2026" for a range, "…" for an open end. */
  function dayRange(from: string | undefined, to: string | undefined): string {
    if (from && from === to) return formatCalendarDate(from);
    return `${from ? formatCalendarDate(from) : "…"} – ${to ? formatCalendarDate(to) : "…"}`;
  }
</script>

<!-- A value the vulnerability database does not have, announced as such to screen readers. -->
{#snippet missing()}
  <span class="font-sans text-muted-foreground" title={t("findings.notAvailable")}>
    <span aria-hidden="true">–</span>
    <span class="sr-only">{t("findings.notAvailable")}</span>
  </span>
{/snippet}

<!-- A filter that is on or off: a real toggle button, with a check mark when on and a dashed border when off. -->
{#snippet toggle(on: boolean, onToggle: () => void, content: Snippet, disabled: boolean, testid: string)}
  <button
    type="button"
    aria-pressed={on}
    {disabled}
    onclick={onToggle}
    data-testid={testid}
    class={cn(
      "inline-flex h-9 items-center gap-1.5 rounded-md border px-2 text-sm whitespace-nowrap",
      "disabled:pointer-events-none disabled:opacity-50",
      on ? "border-foreground bg-card font-medium" : "border-dashed border-control text-muted-foreground hover:bg-accent",
    )}
  >
    {#if on}<Check aria-hidden="true" class="size-3.5 flex-none" />{/if}
    {@render content()}
  </button>
{/snippet}

<!-- A date filter set from the statistics, shown as what it is and removable in one click. -->
{#snippet dateChip(filter: string, clear: Partial<FindingSearch>)}
  <button
    type="button"
    onclick={() => setSearch(clear)}
    aria-label={t("findings.removeFilter", { filter })}
    class="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-sm whitespace-nowrap hover:bg-accent"
  >
    {filter}<X aria-hidden="true" class="size-3.5" />
  </button>
{/snippet}

{#snippet epssLabel()}
  <abbr title={t("findings.epssHint")} class="no-underline">{t("findings.epss")}</abbr>
{/snippet}

{#snippet headerActions()}
  {#if scan.isError}
    <span role="alert" class="text-sm text-critical">{t("errors.actionFailed")}</span>
  {:else if queued !== null}
    <span role="status" class="text-sm text-muted-foreground">{t("overview.scansQueued", { count: queued })}</span>
  {/if}
  <ExportMenu filters={{ ...search, id: undefined, ai: undefined, cursor: undefined, pageSize: undefined }} />
  {#if me.role !== "viewer"}
    <Button variant="primary" disabled={scan.isPending} onclick={() => scan.mutate()}>
      <ScanSearch aria-hidden="true" class="size-4" />
      {search.repositoryId ? t("findings.scanFiltered") : t("repositories.scanNow")}
    </Button>
  {/if}
{/snippet}

<PageHeader title={t("findings.title")} description={t("findings.description")} actions={headerActions} />

<!-- Row 1: the state with counts, and the search; row 2: severity, repository, known exploited, fix available. -->
<div class="mb-4 grid gap-3">
  <div class="flex flex-wrap items-center gap-3">
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
    <SearchInput
      class="ml-auto"
      label={t("findings.search")}
      value={search.q ?? ""}
      onChange={(q) => setSearch({ q: q || undefined }, true)}
    />
  </div>
  <div class="flex flex-wrap items-center gap-2" data-testid="findings-filters">
    <fieldset class="flex flex-wrap gap-1.5">
      <legend class="sr-only">{t("findings.severityFilter")}</legend>
      {#each FILTER_SEVERITIES as s (s)}
        {@const count = severityCounts ? (severityCounts[s] ?? 0) : undefined}
        {#snippet badge()}<SeverityBadge severity={s} {count} />{/snippet}
        {@render toggle(selected.has(s), () => toggleSeverity(s), badge, count === 0 && !selected.has(s), `severity-${s}`)}
      {/each}
    </fieldset>
    <Select
      aria-label={t("findings.repository")}
      value={search.repositoryId ?? ""}
      onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined })}
      class="h-9 max-w-56"
    >
      <option value="">{t("findings.allRepositories")}</option>
      {#each repositories.data?.items ?? [] as r (r.id)}
        <option value={r.id}>{r.name}</option>
      {/each}
    </Select>
    {#snippet kevLabel()}<ShieldAlert aria-hidden="true" class="size-3.5" />{t("findings.toggleKnownExploited")}{/snippet}
    {@render toggle(search.kev === "1", () => setSearch({ kev: search.kev ? undefined : "1" }), kevLabel, false, "toggle-kev")}
    {#snippet fixLabel()}{t("findings.toggleFixable")}{/snippet}
    {@render toggle(
      search.fixable === "1",
      () => setSearch({ fixable: search.fixable ? undefined : "1" }),
      fixLabel,
      false,
      "toggle-fixable",
    )}
    {#if search.firstSeenFrom || search.firstSeenTo}
      {@render dateChip(t("findings.firstSeenRange", { range: dayRange(search.firstSeenFrom, search.firstSeenTo) }), {
        firstSeenFrom: undefined,
        firstSeenTo: undefined,
      })}
    {/if}
    {#if search.resolvedFrom || search.resolvedTo}
      {@render dateChip(t("findings.resolvedRange", { range: dayRange(search.resolvedFrom, search.resolvedTo) }), {
        resolvedFrom: undefined,
        resolvedTo: undefined,
      })}
    {/if}
    <!-- Always rendered so the toolbar never shifts when a filter is set; hidden while nothing is filtered. -->
    <button
      type="button"
      onclick={() => go({})}
      disabled={!hasFilters}
      aria-hidden={!hasFilters}
      tabindex={hasFilters ? undefined : -1}
      class={cn("link ml-auto text-sm font-medium", !hasFilters && "invisible")}
    >
      {t("findings.clearFilters")}
    </button>
  </div>
</div>

<div
  class={cn(
    "grid gap-4",
    shownId && "@wide:grid-cols-[minmax(0,1fr)_28rem] @xwide:grid-cols-[minmax(0,1fr)_32rem_30rem]",
  )}
>
  <!-- The table answers to the width of its own card, which is narrower when panes sit beside it. -->
  <Card class="@container/list self-start">
    <table class="w-full text-left" data-testid="findings-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="py-2.5 pr-2 pl-5 font-medium">{t("findings.columnSeverity")}</th>
          <SortHeader
            column="vulnerability"
            label={t("findings.columnFinding")}
            natural="asc"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="repository"
            label={t("findings.columnRepository")}
            natural="asc"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          {#if show.cvss}
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
          {/if}
          {#if show.epss}
            <SortHeader
              column="epss"
              label={epssLabel}
              natural="desc"
              align="right"
              class="hidden px-3 @5xl/list:table-cell"
              current={search.sort}
              dir={search.dir}
              {onSort}
            />
          {/if}
          {#if show.published}
            <SortHeader
              column="published"
              label={t("findings.columnPublished")}
              natural="desc"
              class="hidden px-3 @4xl/list:table-cell"
              current={search.sort}
              dir={search.dir}
              {onSort}
            />
          {/if}
          <SortHeader
            column="firstSeen"
            label={t("findings.columnDetected")}
            natural="desc"
            class="hidden pr-5 pl-3 @3xl/list:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
        </tr>
      </thead>
      <tbody>
        {#each items as f (f.id)}
          <tr
            aria-selected={f.id === shownId}
            class="row-link border-b last:border-0"
            onclick={rowClick(() => setSearch({ id: f.id, cursor: search.cursor }))}
          >
            <td class="py-1.5 pr-2 pl-5 align-middle whitespace-nowrap"><SeverityBadge severity={f.severity} /></td>
            <td class="px-3 py-1.5">
              <div class="flex items-center gap-1.5 leading-5">
                <button
                  type="button"
                  onclick={() => setSearch({ id: f.id, cursor: search.cursor })}
                  aria-current={f.id === shownId ? "true" : undefined}
                  class="text-left font-medium break-all hover:underline"
                >
                  {f.vulnerabilityId}
                </button>
                {#if f.knownExploited}
                  <span class="inline-flex items-center gap-1 text-sm whitespace-nowrap text-critical">
                    <ShieldAlert aria-hidden="true" class="size-3.5" />{t("findings.kev")}
                  </span>
                {/if}
              </div>
              <div class="font-mono text-sm leading-5 break-all text-muted-foreground">
                {f.packageName}
                {f.packageVersion}
                {#if f.fixedIn?.length}
                  <span aria-label={t("findings.fixedInLabel", { versions: f.fixedIn.join(", ") })}
                    >→ {f.fixedIn.join(", ")}</span
                  >
                {:else}
                  <span class="font-sans">· {t("findings.noFix")}</span>
                {/if}
              </div>
            </td>
            <td class="px-3 py-1.5"><RepositoryLink id={f.repositoryId} name={f.repositoryName} /></td>
            {#if show.cvss}
              <td class="px-3 py-1.5 text-right font-mono text-sm tabular-nums">
                {#if f.cvssScore !== null}{f.cvssScore.toFixed(1)}{:else}{@render missing()}{/if}
              </td>
            {/if}
            {#if show.epss}
              <td class="hidden px-3 py-1.5 text-right font-mono text-sm tabular-nums @5xl/list:table-cell">
                {#if f.epss !== null}{formatPercent(f.epss)}{:else}{@render missing()}{/if}
              </td>
            {/if}
            {#if show.published}
              <td class="hidden px-3 py-1.5 text-sm whitespace-nowrap @4xl/list:table-cell">
                {#if f.publishedAt}
                  <time datetime={f.publishedAt} title={formatDateTime(f.publishedAt)}>{formatDate(f.publishedAt)}</time>
                {:else}
                  {@render missing()}
                {/if}
              </td>
            {/if}
            <td class="hidden py-1.5 pr-5 pl-3 text-sm whitespace-nowrap @3xl/list:table-cell">
              <time datetime={f.firstSeenAt} title={formatDateTime(f.firstSeenAt)}>
                {formatDay(f.firstSeenAt)} · {formatRelative(f.firstSeenAt)}
              </time>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && items.length === 0}
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
  <!-- The pane is sized to start below the header and the two filter rows and still end inside the screen. -->
  {#if shownId && aiPane}
    <div class="sticky top-0 h-[calc(100dvh-17rem)] self-start">
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
