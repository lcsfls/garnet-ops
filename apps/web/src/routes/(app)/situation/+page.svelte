<script lang="ts">
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import { cn } from "#lib/cn.ts";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import StateIcon from "#lib/components/ui/StateIcon.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { type SituationSearch, situationSearch, toQuery } from "#lib/search.ts";
  import { TONE_CLASSES } from "#lib/severity-meta.ts";
  import type { Page, Severity } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  /**
   * The situation (ADR 0052): each open vulnerability once, over repositories, running containers and hosts, known exploited
   * first. A row opens the vulnerability's page with every system and what fixes it.
   */
  interface Row {
    id: string;
    severity: Severity;
    cvssScore: number | null;
    knownExploited: boolean;
    repositories: number;
    containers: number;
    hosts: number;
    systems: number;
    fixKnown: boolean;
    packages: string[];
    packageCount: number;
  }
  const SHOW = ["all", "exploited", "critical", "high"] as const;
  type Answer = Page<Row> & { counts: Record<(typeof SHOW)[number], number>; hostsOn: boolean };

  const search: SituationSearch = $derived(parseSearch(situationSearch, new URL(page.url.href)));
  const list = createQuery(() => ({
    queryKey: ["situation", search],
    queryFn: () => api<Answer>(`/situation${toQuery(search)}`),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  }));
  const navigate = (next: SituationSearch, replace = false) =>
    goto(href(page.url.pathname, next), { reset: false, replace });
  const setSearch = (patch: Partial<SituationSearch>, replace = false) =>
    navigate({ ...search, cursor: undefined, ...patch }, replace);
  const filtered = $derived(Boolean(search.q || search.show || search.kind));
  const KINDS = ["repository", "container", "host"] as const;
</script>

<PageHeader title={t("situation.title")} description={t("situation.description")} />
<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("situation.showFilter")}
    value={search.show ?? "all"}
    options={SHOW.map((s) => ({
      value: s,
      label: t(`situation.show.${s}`),
      count: list.data ? list.data.counts[s] : null,
    }))}
    onChange={(show) => setSearch({ show: show === "all" ? undefined : show })}
  />
  {#if list.data?.hostsOn}
    <Select
      aria-label={t("situation.kindFilter")}
      value={search.kind ?? ""}
      onchange={(e) => {
        const kind = KINDS.find((k) => k === e.currentTarget.value);
        setSearch({ kind });
      }}
      class="max-w-48"
    >
      <option value="">{t("situation.allKinds")}</option>
      {#each KINDS as kind (kind)}
        <option value={kind}>{t(`situation.kinds.${kind}`)}</option>
      {/each}
    </Select>
  {/if}
  <SearchInput
    class="ml-auto"
    label={t("situation.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>
{#if list.data && !list.data.hostsOn}
  <p class="mb-4 text-sm text-muted-foreground" data-testid="situation-hosts-off">{t("situation.hostsOff")}</p>
{/if}
<Card>
  <table class="w-full text-left" data-testid="situation-list">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("situation.columnVulnerability")}</th>
        <th class="px-3 py-2.5 font-medium">{t("situation.columnSeverity")}</th>
        <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("situation.columnPackages")}</th>
        <th class="px-3 py-2.5 font-medium">{t("situation.columnSystems")}</th>
        <th class="hidden px-5 py-2.5 font-medium @wide:table-cell">{t("situation.columnFix")}</th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as row (row.id)}
        <tr class="border-b align-top last:border-0" data-testid="situation-row">
          <td class="px-5 py-2.5">
            <a
              class="font-mono font-medium underline-offset-4 hover:underline"
              href={`/situation/${encodeURIComponent(row.id)}`}>{row.id}</a
            >
            {#if row.knownExploited}
              <span class={cn("mt-0.5 flex items-center gap-1 text-sm", TONE_CLASSES.critical.text)}>
                <StateIcon name="flame" class="size-3.5" />{t("situation.exploited")}
              </span>
            {/if}
          </td>
          <td class="px-3 py-2.5">
            <SeverityBadge severity={row.severity} />
            {#if row.cvssScore !== null}
              <span class="mt-0.5 block text-sm text-muted-foreground"
                >{t("situation.cvss", { score: row.cvssScore.toFixed(1) })}</span
              >
            {/if}
          </td>
          <td class="hidden px-3 py-2.5 font-mono text-sm break-all @3xl:table-cell">
            {row.packages.join(", ")}
            {#if row.packageCount > row.packages.length}
              <span class="font-sans text-muted-foreground">
                {t("situation.morePackages", { count: row.packageCount - row.packages.length })}
              </span>
            {/if}
          </td>
          <td class="px-3 py-2.5 text-sm">
            {#if row.repositories > 0}<span class="block">{t("situation.repositories", { count: row.repositories })}</span>{/if}
            {#if row.containers > 0}<span class="block">{t("situation.containers", { count: row.containers })}</span>{/if}
            {#if row.hosts > 0}<span class="block">{t("situation.hosts", { count: row.hosts })}</span>{/if}
          </td>
          <td class="hidden px-5 py-2.5 text-sm @wide:table-cell">
            {#if row.fixKnown}{t("situation.fixKnown")}{:else}<span class="text-muted-foreground">{t("situation.noFix")}</span>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">
      {filtered ? t("situation.emptyFiltered") : t("situation.empty")}
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
