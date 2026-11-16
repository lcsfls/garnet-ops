<script lang="ts">
  import { SEVERITIES, SEVERITY_RANK, type Severity } from "@garnetops/core";
  import { ChevronDown, SlidersHorizontal } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import GradeFilter from "#lib/components/repositories/GradeFilter.svelte";
  import GradeLetter from "#lib/components/repositories/GradeLetter.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import SortHeader, { type SortDir } from "#lib/components/SortHeader.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { type PackageSearch, packageSearch, toQuery } from "#lib/search.ts";
  import type { Grade, Page, RepositoryRow } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  type Deprecation = { state: "deprecated" | "yanked"; message: string | null } | null;
  /** One row of the inventory: a package in one repository. */
  interface PackageRow {
    id: string;
    name: string;
    version: string;
    type: string;
    purl: string | null;
    licenses: string[] | null;
    repositoryId: string;
    repositoryName: string;
    openFindings: number;
    worstSeverityRank: number | null;
    /** The grade the package gives by the repository grade rules (ADR 0018). */
    grade: Grade | null;
    /** What the registry said, when deprecated or yanked and the module is on (ADR 0051). */
    deprecation: Deprecation;
  }
  /** One row of the affected view (0.1.9): a package with open findings, over every repository that has it. */
  interface AffectedRow {
    name: string;
    version: string;
    type: string;
    repositories: number;
    repositoryList: { id: string; name: string }[];
    openFindings: number;
    worstSeverityRank: number;
    grade: Grade | null;
    fix: { version: string; majorUpgrade: boolean; unresolved: number } | null;
    deprecation: Deprecation;
  }
  type StatusCounts = Record<(typeof STATUSES)[number], number>;

  const STATUSES = ["all", "blocked", "attention", "clean"] as const;
  const AFFECTED_SORTS = ["severity", "findings", "repositories", "name"] as const;
  const severityOfRank = (rank: number): Severity =>
    SEVERITIES.find((s) => SEVERITY_RANK[s] === rank) ?? "unknown";

  const search: PackageSearch = $derived(parseSearch(packageSearch, new URL(page.url.href)));
  const inventory = $derived(search.view === "inventory");
  /** Deprecated and yanked packages (ADR 0051) show only while the module is on. */
  const deprecatedOn = $derived(page.data.me?.organization.modules?.deprecated === true);
  /** The filters as the API takes them, without the list's position or view. */
  const filters = $derived({
    q: search.q,
    repositoryId: search.repositoryId,
    type: search.type,
    vulnerable: inventory ? search.vulnerable : undefined,
    deprecated: search.deprecated,
    status: search.status,
    grade: search.grade,
    activity: search.activity,
  });
  const position = $derived({ cursor: search.cursor, pageSize: search.pageSize });

  const affected = createQuery(() => ({
    queryKey: ["packages-affected", filters, position, search.sort, search.dir],
    queryFn: () =>
      api<Page<AffectedRow>>(
        `/packages/affected${toQuery({
          ...filters,
          ...position,
          sort: AFFECTED_SORTS.find((s) => s === search.sort),
          dir: search.dir,
        })}`,
      ),
    placeholderData: keepPreviousData,
    enabled: !inventory,
  }));
  const affectedCounts = createQuery(() => ({
    queryKey: ["package-counts", "affected", { ...filters, status: undefined, grade: undefined }],
    queryFn: () =>
      api<StatusCounts & { grades: Record<Grade | "none", number> }>(
        `/packages/affected/counts${toQuery({ ...filters, status: undefined, grade: undefined })}`,
      ),
    placeholderData: keepPreviousData,
    enabled: !inventory,
  }));
  const list = createQuery(() => ({
    queryKey: ["packages", filters, position, search.sort, search.dir],
    queryFn: () =>
      api<Page<PackageRow>>(
        `/packages${toQuery({ ...filters, ...position, sort: search.sort, dir: search.dir })}`,
      ),
    placeholderData: keepPreviousData,
    enabled: inventory,
  }));
  /** The inventory's counts; both views read the packages set aside and the types from them. */
  const counts = createQuery(() => ({
    queryKey: ["package-counts", { ...filters, status: undefined }],
    queryFn: () =>
      api<StatusCounts & { inactive: number; types: string[] }>(
        `/packages/counts${toQuery({ ...filters, status: undefined })}`,
      ),
    placeholderData: keepPreviousData,
  }));
  const grades = createQuery(() => ({
    queryKey: ["package-grades", { ...filters, grade: undefined }],
    queryFn: () =>
      api<Record<Grade | "none", number>>(`/packages/grades${toQuery({ ...filters, grade: undefined })}`),
    placeholderData: keepPreviousData,
    enabled: inventory,
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
  const statusCounts = $derived(inventory ? counts.data : affectedCounts.data);
  const gradeCounts = $derived(inventory ? grades.data : affectedCounts.data?.grades);

  const navigate = (next: PackageSearch, replace = false) =>
    goto(href(page.url.pathname, next), { reset: false, replace });
  const setSearch = (patch: Partial<PackageSearch>, replace = false) =>
    navigate({ ...search, cursor: undefined, ...patch }, replace);
  const sortProps = $derived({
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as PackageSearch["sort"], dir }),
  });
  /** The two views sort by different columns: a switch starts from each one's own order. */
  const setView = (view: "affected" | "inventory") =>
    setSearch({
      view: view === "inventory" ? "inventory" : undefined,
      sort: undefined,
      dir: undefined,
      vulnerable: undefined,
    });

  /** The filters behind "More filters"; open by themselves while one of them is set. */
  const extraSet = $derived(
    [
      search.grade,
      search.type,
      search.activity,
      search.deprecated,
      inventory ? search.vulnerable : undefined,
    ].filter(Boolean).length,
  );
  let moreOpen = $state(false);
  const showMore = $derived(moreOpen || extraSet > 0);
  const moreId = $props.id();

  /** Rows of the affected view whose repository list is open. */
  let expanded = $state<string[]>([]);
  const rowKey = (row: { type: string; name: string; version: string }) =>
    `${row.type} ${row.name} ${row.version}`;
  const toggle = (key: string) => {
    expanded = expanded.includes(key) ? expanded.filter((k) => k !== key) : [...expanded, key];
  };
</script>

{#snippet headerActions()}
  <ExportMenu
    path="/packages/export"
    hint={t("packages.exportHint")}
    filters={{ ...filters, view: inventory ? undefined : "affected" }}
  />
{/snippet}
{#snippet deprecationOf(d: Deprecation)}
  {#if d}
    <span class="mt-1 flex flex-wrap items-baseline gap-1.5" data-testid="package-deprecation">
      <Badge tone="neutral">{t(`deprecated.${d.state}`)}</Badge>
      {#if d.message}<span class="text-muted-foreground">{d.message}</span>{/if}
    </span>
  {/if}
{/snippet}

<PageHeader title={t("packages.title")} description={t("packages.description")} actions={headerActions} />
<div class="mb-3 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("packages.viewLabel")}
    value={inventory ? "inventory" : "affected"}
    options={[
      { value: "affected", label: t("packages.viewAffected") },
      { value: "inventory", label: t("packages.viewInventory") },
    ]}
    onChange={setView}
  />
  <Segmented
    label={t("packages.statusFilter")}
    value={search.status ?? "all"}
    options={STATUSES.map((s) => ({
      value: s,
      label: s === "clean" && !inventory ? t("packages.statusLower") : t(`repositories.status.${s}`),
      count: statusCounts ? statusCounts[s] : null,
    }))}
    onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
  />
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
  <Button
    variant="secondary"
    aria-expanded={showMore}
    aria-controls={moreId}
    disabled={extraSet > 0}
    onclick={() => (moreOpen = !moreOpen)}
  >
    <SlidersHorizontal aria-hidden="true" class="size-4" />
    {extraSet > 0 ? t("packages.moreFiltersCount", { count: extraSet }) : t("packages.moreFilters")}
  </Button>
  <SearchInput
    class="ml-auto"
    label={t("packages.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>
{#if showMore}
  <div id={moreId} class="mb-4 flex flex-wrap items-center gap-3" data-testid="package-more-filters">
    <GradeFilter value={search.grade} counts={gradeCounts} withNone={false} onChange={(grade) => setSearch({ grade })} />
    {#if (counts.data?.types.length ?? 0) > 1 || search.type}
      <Select
        aria-label={t("packages.typeFilter")}
        value={search.type ?? ""}
        onchange={(e) => setSearch({ type: e.currentTarget.value || undefined })}
        class="max-w-44"
      >
        <option value="">{t("packages.allTypes")}</option>
        {#each counts.data?.types ?? [] as type (type)}
          <option value={type}>{type}</option>
        {/each}
      </Select>
    {/if}
    {#if !search.repositoryId && (search.activity || (counts.data?.inactive ?? 0) > 0)}
      <Segmented
        label={t("repositories.activityFilter")}
        value={search.activity ?? "active"}
        options={[
          { value: "active", label: t("repositories.activityActive") },
          { value: "inactive", label: t("repositories.activityInactive") },
        ]}
        onChange={(activity) => setSearch({ activity: activity === "active" ? undefined : "inactive" })}
      />
    {/if}
    {#if inventory}
      <label class="flex items-center gap-2 text-sm whitespace-nowrap">
        <Checkbox
          checked={search.vulnerable === "1"}
          onchange={(e) => setSearch({ vulnerable: e.currentTarget.checked ? "1" : undefined })}
        />
        {t("packages.vulnerableOnly")}
      </label>
    {/if}
    {#if deprecatedOn}
      <label class="flex items-center gap-2 text-sm whitespace-nowrap">
        <Checkbox
          checked={search.deprecated === "1"}
          onchange={(e) => setSearch({ deprecated: e.currentTarget.checked ? "1" : undefined })}
        />
        {t("deprecated.filter")}
      </label>
    {/if}
  </div>
{:else}
  <div class="mb-1"></div>
{/if}

{#if !inventory}
  <Card>
    <table class="w-full text-left" data-testid="packages-affected">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <SortHeader column="name" label={t("packages.columnName")} natural="asc" class="px-5" {...sortProps} />
          <SortHeader
            column="severity"
            label={t("packages.columnOpen")}
            natural="desc"
            class="px-3"
            current={search.sort ?? "severity"}
            dir={search.dir}
            onSort={sortProps.onSort}
          />
          <th class="px-3 py-2.5 font-medium">{t("packages.columnFix")}</th>
          <SortHeader
            column="repositories"
            label={t("packages.columnRepositories")}
            natural="desc"
            class="px-3"
            {...sortProps}
          />
          <th class="hidden px-2 py-2.5 font-medium @3xl:table-cell">{t("grades.column")}</th>
          <th class="hidden px-5 py-2.5 font-medium @wide:table-cell">{t("packages.columnType")}</th>
        </tr>
      </thead>
      <tbody>
        {#each affected.data?.items ?? [] as p (rowKey(p))}
          {@const key = rowKey(p)}
          {@const open = expanded.includes(key)}
          <tr class="border-b align-top last:border-0" data-testid="affected-row">
            <td class="px-5 py-2.5 text-sm" data-testid="package-name">
              <span class="font-mono break-all">{p.name}</span>
              <span class="ml-1.5 font-mono break-all text-muted-foreground">{p.version}</span>
              {@render deprecationOf(p.deprecation)}
            </td>
            <td class="px-3 py-2.5">
              <a
                href={href("/findings", { repositoryId: search.repositoryId, q: p.name })}
                class="hover:opacity-80"
              >
                <SeverityBadge severity={severityOfRank(p.worstSeverityRank)} count={p.openFindings} />
              </a>
            </td>
            <td class="px-3 py-2.5 text-sm" data-testid="package-fix">
              {#if p.fix}
                <span class="font-mono">{p.fix.version}</span>
                {#if p.fix.majorUpgrade}
                  <span class="block text-muted-foreground">{t("packages.majorUpgrade")}</span>
                {/if}
                {#if p.fix.unresolved > 0}
                  <span class="block text-muted-foreground">{t("packages.unresolved", { count: p.fix.unresolved })}</span>
                {/if}
              {:else}
                <span class="text-muted-foreground">{t("packages.noFix")}</span>
              {/if}
            </td>
            <td class="px-3 py-2.5 text-sm">
              {#if p.repositories === 1 && p.repositoryList[0]}
                <RepositoryLink id={p.repositoryList[0].id} name={p.repositoryList[0].name} />
              {:else}
                <button
                  type="button"
                  class="inline-flex items-center gap-1 rounded-sm underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                  aria-expanded={open}
                  aria-label={t("packages.showRepositories", { name: p.name, version: p.version })}
                  onclick={() => toggle(key)}
                >
                  {t("packages.repositoriesCount", { count: p.repositories })}
                  <ChevronDown aria-hidden="true" class="size-4 transition-transform {open ? 'rotate-180' : ''}" />
                </button>
              {/if}
            </td>
            <td class="hidden px-2 py-2.5 @3xl:table-cell" data-testid="package-grade">
              {#if p.grade}<GradeLetter grade={p.grade} />{/if}
            </td>
            <td class="hidden px-5 py-2.5 text-sm @wide:table-cell">{p.type}</td>
          </tr>
          {#if open}
            <tr class="border-b bg-muted" data-testid="affected-repositories">
              <td colspan="6" class="px-5 py-2.5 text-sm">
                <span class="flex flex-wrap gap-x-4 gap-y-1">
                  {#each p.repositoryList as r (r.id)}
                    <RepositoryLink id={r.id} name={r.name} />
                  {/each}
                  {#if p.repositories > p.repositoryList.length}
                    <span class="text-muted-foreground">
                      {t("packages.moreRepositories", { count: p.repositories - p.repositoryList.length })}
                    </span>
                  {/if}
                </span>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
    <QueryStatus query={affected} />
    {#if affected.data && affected.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">{t("packages.emptyAffected")}</p>
    {/if}
    {#if affected.data}
      <Pagination
        page={affected.data}
        onCursor={(cursor) => navigate({ ...search, cursor })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>
{:else}
  <Card>
    <table class="w-full text-left" data-testid="packages-inventory">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <SortHeader column="name" label={t("packages.columnName")} natural="asc" class="px-5" {...sortProps} />
          <th class="px-3 py-2.5 font-medium">{t("packages.columnVersion")}</th>
          <SortHeader
            column="repository"
            label={t("findings.columnRepository")}
            natural="asc"
            class="px-3"
            {...sortProps}
          />
          <SortHeader
            column="findings"
            label={t("packages.columnOpen")}
            natural="desc"
            class="px-3"
            {...sortProps}
          />
          <SortHeader
            column="grade"
            label={t("grades.column")}
            natural="desc"
            class="hidden px-2 @3xl:table-cell"
            {...sortProps}
          />
          <SortHeader
            column="type"
            label={t("packages.columnType")}
            natural="asc"
            class="hidden px-3 @wide:table-cell"
            {...sortProps}
          />
          <th class="hidden px-5 py-2.5 font-medium @xwide:table-cell">{t("packages.columnLicenses")}</th>
        </tr>
      </thead>
      <tbody>
        {#each list.data?.items ?? [] as p (p.id)}
          <tr class="border-b align-top last:border-0">
            <td class="px-5 py-2.5 text-sm" data-testid="package-name">
              <span class="font-mono break-all">{p.name}</span>
              {@render deprecationOf(p.deprecation)}
            </td>
            <td class="px-3 py-2.5 font-mono text-sm break-all">{p.version || "–"}</td>
            <td class="px-3 py-2.5">
              <RepositoryLink id={p.repositoryId} name={p.repositoryName} />
            </td>
            <td class="px-3 py-2.5">
              {#if p.openFindings > 0 && p.worstSeverityRank !== null}
                <a href={href("/findings", { repositoryId: p.repositoryId, q: p.name })} class="hover:opacity-80">
                  <SeverityBadge severity={severityOfRank(p.worstSeverityRank)} count={p.openFindings} />
                </a>
              {:else}
                <span class="text-sm text-muted-foreground">{t("packages.noOpen")}</span>
              {/if}
            </td>
            <td class="hidden px-2 py-2.5 @3xl:table-cell" data-testid="package-grade">
              {#if p.grade}<GradeLetter grade={p.grade} />{/if}
            </td>
            <td class="hidden px-3 py-2.5 text-sm @wide:table-cell">{p.type}</td>
            <td class="hidden px-5 py-2.5 font-mono text-sm break-all text-muted-foreground @xwide:table-cell">
              {p.licenses?.length ? p.licenses.join(", ") : "–"}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && list.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">{t("packages.empty")}</p>
    {/if}
    {#if list.data}
      <Pagination
        page={list.data}
        onCursor={(cursor) => navigate({ ...search, cursor })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>
{/if}
