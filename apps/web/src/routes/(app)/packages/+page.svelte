<script lang="ts">
  import { SEVERITIES, SEVERITY_RANK, type Severity } from "@garnetops/core";
  import { Package } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import SortHeader, { type SortDir } from "#lib/components/SortHeader.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { type PackageSearch, packageSearch, toQuery } from "#lib/search.ts";
  import type { Page, RepositoryRow } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

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
  }

  const severityOfRank = (rank: number): Severity =>
    SEVERITIES.find((s) => SEVERITY_RANK[s] === rank) ?? "unknown";

  const search: PackageSearch = $derived(parseSearch(packageSearch, new URL(page.url.href)));
  const list = createQuery(() => ({
    queryKey: ["packages", search],
    queryFn: () => api<Page<PackageRow>>(`/packages${toQuery(search)}`),
    placeholderData: keepPreviousData,
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
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
</script>

<PageHeader icon={Package} title={t("packages.title")} description={t("packages.description")} />
<div class="mb-4 flex flex-wrap items-center gap-3">
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
  <label class="flex items-center gap-2 text-sm whitespace-nowrap">
    <Checkbox
      checked={search.vulnerable === "1"}
      onchange={(e) => setSearch({ vulnerable: e.currentTarget.checked ? "1" : undefined })}
    />
    {t("packages.vulnerableOnly")}
  </label>
  <SearchInput
    class="ml-auto"
    label={t("packages.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>
<Card>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <SortHeader column="name" label={t("packages.columnName")} natural="asc" class="px-5" {...sortProps} />
        <th class="px-3 py-2.5 font-medium">{t("packages.columnVersion")}</th>
        <SortHeader
          column="type"
          label={t("packages.columnType")}
          natural="asc"
          class="hidden px-3 @3xl:table-cell"
          {...sortProps}
        />
        <SortHeader
          column="repository"
          label={t("findings.columnRepository")}
          natural="asc"
          class="px-3"
          {...sortProps}
        />
        <th class="hidden px-3 py-2.5 font-medium @5xl:table-cell">
          {t("packages.columnLicenses")}
        </th>
        <SortHeader column="findings" label={t("packages.columnOpen")} natural="desc" class="px-5" {...sortProps} />
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as p (p.id)}
        <tr class="border-b align-top last:border-0">
          <td class="px-5 py-2.5 font-mono text-sm break-all">{p.name}</td>
          <td class="px-3 py-2.5 font-mono text-sm break-all">{p.version || "–"}</td>
          <td class="hidden px-3 py-2.5 text-sm @3xl:table-cell">{p.type}</td>
          <td class="px-3 py-2.5">
            <RepositoryLink id={p.repositoryId} name={p.repositoryName} />
          </td>
          <td class="hidden px-3 py-2.5 font-mono text-sm break-all text-muted-foreground @5xl:table-cell">
            {p.licenses?.length ? p.licenses.join(", ") : "–"}
          </td>
          <td class="px-5 py-2.5">
            {#if p.openFindings > 0 && p.worstSeverityRank !== null}
              <a href={href("/findings", { repositoryId: p.repositoryId, q: p.name })} class="hover:opacity-80">
                <SeverityBadge severity={severityOfRank(p.worstSeverityRank)} count={p.openFindings} />
              </a>
            {:else}
              <span class="text-sm text-muted-foreground">{t("packages.noOpen")}</span>
            {/if}
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
