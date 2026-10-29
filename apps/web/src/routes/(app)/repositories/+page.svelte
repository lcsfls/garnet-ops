<script lang="ts">
  import { Clock, GitBranch, ListChecks, Plus } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import AddRepositoryDialog from "#lib/components/repositories/AddRepositoryDialog.svelte";
  import GradeFilter from "#lib/components/repositories/GradeFilter.svelte";
  import GradeHelp from "#lib/components/repositories/GradeHelp.svelte";
  import RepositoryRowView, { SEVERITY_COLUMNS } from "#lib/components/repositories/RepositoryRow.svelte";
  import ShareRequestsCard from "#lib/components/repositories/ShareRequestsCard.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import SortHeader, { type SortDir } from "#lib/components/SortHeader.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { formatWallClock } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { type RepositorySearch, repositorySearch, toQuery } from "#lib/search.ts";
  import type { GateResult, Grade, Page, RepositoryRow } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  const STATUSES = ["all", "blocked", "attention", "clean"] as const;
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const search = $derived(parseSearch(repositorySearch, page.url));
  const canEdit = $derived(me.role !== "viewer");
  const canDelete = $derived(me.role === "owner" || me.role === "admin");

  const query = createQuery(() => ({
    queryKey: ["repositories", search],
    queryFn: () => api<Page<RepositoryRow>>(`/repositories${toQuery({ ...search, tz: timeZone }, ["add"])}`),
    placeholderData: keepPreviousData,
    // Follow running scans until they finish.
    refetchInterval: (q: { state: { data?: Page<RepositoryRow> } }) =>
      q.state.data?.items.some((r) => r.lastScan && ["queued", "running"].includes(r.lastScan.state))
        ? 4000
        : false,
  }));

  // The latest gate result of each repository's own branch (pull request checks excluded).
  const gates = createQuery(() => ({
    queryKey: ["gate-latest"],
    queryFn: () => api<{ repositoryId: string; result: GateResult }[]>("/gates/latest"),
  }));
  const gateOf = $derived(new Map((gates.data ?? []).map((g) => [g.repositoryId, g.result])));

  const counts = createQuery(() => ({
    queryKey: ["repository-counts", search.q ?? ""],
    queryFn: () =>
      api<Record<(typeof STATUSES)[number], number>>(`/repositories/counts${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
  }));

  const grades = createQuery(() => ({
    queryKey: ["repository-grades", search.q ?? ""],
    queryFn: () => api<Record<Grade | "none", number>>(`/repositories/grades${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
  }));

  function setSearch(patch: Partial<RepositorySearch>, replace = false) {
    void goto(href(page.url.pathname, { ...search, cursor: undefined, ...patch }), { replace, reset: false });
  }
  const onSort = (sort: string | undefined, dir: SortDir | undefined) =>
    setSearch({ sort: sort as RepositorySearch["sort"], dir });
</script>

<PageHeader icon={GitBranch} title={t("repositories.title")} description={t("repositories.description")}>
  {#snippet actions()}
    {#if canEdit}
      <a
        href={href("/settings", { section: "accounts" })}
        class="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-input bg-card px-4 font-medium whitespace-nowrap shadow-xs transition-colors hover:bg-accent"
      >
        <ListChecks aria-hidden="true" class="size-4" />
        {t("connections.fromAccount")}
      </a>
      <Button onclick={() => setSearch({ add: "1" })}>
        <Plus aria-hidden="true" class="size-4" />
        {t("repositories.add")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>

<p class="-mt-2 mb-4 flex items-center gap-1.5 text-sm text-muted-foreground">
  <Clock aria-hidden="true" class="size-4" />
  {me.organization.scanSchedule.enabled
    ? t("repositories.nightly", {
        time: formatWallClock(me.organization.scanSchedule.localTime),
        zone: me.organization.scanSchedule.timeZone,
      })
    : t("repositories.nightlyOff")}
</p>

<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("repositories.statusFilter")}
    value={search.status ?? "all"}
    options={STATUSES.map((s) => ({
      value: s,
      label: t(`repositories.status.${s}`),
      count: counts.data ? counts.data[s] : null,
    }))}
    onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
  />
  <GradeFilter value={search.grade} counts={grades.data} onChange={(grade) => setSearch({ grade })} />
  <SearchInput
    class="ml-auto"
    label={t("repositories.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>

<GradeHelp />

{#if canDelete}<ShareRequestsCard />{/if}

<Card>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <SortHeader
          column="name"
          label={t("repositories.columnName")}
          natural="asc"
          class="px-5"
          current={search.sort}
          dir={search.dir}
          {onSort}
        />
        <SortHeader
          column="grade"
          label={t("grades.column")}
          natural="desc"
          class="px-2"
          current={search.sort}
          dir={search.dir}
          {onSort}
        />
        <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("repositories.columnSource")}</th>
        <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("repositories.columnBranch")}</th>
        {#each SEVERITY_COLUMNS as severity (severity)}
          <SortHeader
            column={severity}
            label={t(`severity.${severity}`)}
            natural="desc"
            align="right"
            class="px-3"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
        {/each}
        <!-- Same order as the cells of RepositoryRow (the React version had Gate after Trend here). -->
        <th class="hidden px-3 py-2.5 font-medium @5xl:table-cell">{t("gates.columnGate")}</th>
        <th class="hidden px-3 py-2.5 font-medium @xwide:table-cell">{t("repositories.columnScanners")}</th>
        <th class="hidden px-3 py-2.5 font-medium @xwide:table-cell">{t("repositories.columnTrend")}</th>
        <SortHeader
          column="lastScan"
          label={t("repositories.columnLastScan")}
          natural="desc"
          class="px-3"
          current={search.sort}
          dir={search.dir}
          {onSort}
        />
        <th class="w-14 px-3 py-2.5 text-right font-medium @wide:px-5">
          <span class="sr-only">{t("repositories.columnActions")}</span>
        </th>
      </tr>
    </thead>
    <tbody>
      {#each query.data?.items ?? [] as repo (repo.id)}
        <!-- A member may remove their own private repository (ADR 0030). -->
        <RepositoryRowView
          {repo}
          gate={gateOf.get(repo.id) ?? null}
          {canEdit}
          canDelete={canDelete || (canEdit && repo.mine && repo.visibility === "private")}
        />
      {/each}
    </tbody>
  </table>
  <QueryStatus {query} />
  {#if query.data && query.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("repositories.empty")}</p>
  {/if}
  {#if query.data}
    <Pagination
      page={query.data}
      onCursor={(cursor) =>
        void goto(href(page.url.pathname, { ...search, cursor }), { reset: false })}
      onPageSize={(pageSize) => setSearch({ pageSize })}
    />
  {/if}
</Card>

<AddRepositoryDialog open={search.add === "1"} onClose={() => setSearch({ add: undefined }, true)} />
