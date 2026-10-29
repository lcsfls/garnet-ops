<script lang="ts">
  import { Globe, KeyRound, Network, Plus, ShieldCheck } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import SortHeader, { type SortDir } from "#lib/components/SortHeader.svelte";
  import Tile from "#lib/components/Tile.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import AddWebsiteDialog from "#lib/components/websites/AddWebsiteDialog.svelte";
  import ModuleOff from "#lib/components/websites/ModuleOff.svelte";
  import WebsiteRow from "#lib/components/websites/WebsiteRow.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { toQuery, WEBSITE_STATUSES, type WebsiteSearch, websiteSearch } from "#lib/search.ts";
  import type { Page } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { type ExposureCounts, isBusy, SEVERITY_ORDER, type WebsiteAsset } from "#lib/websites.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * Website monitoring (ADR 0023, a module since ADR 0033): the organisation's own public domains, host names and addresses,
   * seen from the outside. Everyone reads; owners and admins add, check and verify.
   */
  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const on = $derived(me.organization.modules?.websites === true);
  const canEdit = $derived(isAdmin(me));
  const search = $derived(parseSearch(websiteSearch, page.url));

  const query = createQuery(() => ({
    queryKey: ["websites", "list", search],
    queryFn: () => api<Page<WebsiteAsset>>(`/exposure${toQuery(search, ["add"])}`),
    enabled: on,
    placeholderData: keepPreviousData,
    // Follow the worker until the first look at a new website is done.
    refetchInterval: (q: { state: { data?: Page<WebsiteAsset> } }) =>
      q.state.data?.items.some(isBusy) ? 3000 : false,
  }));
  const counts = createQuery(() => ({
    queryKey: ["websites", "counts", search.q ?? ""],
    queryFn: () => api<ExposureCounts>(`/exposure/counts${toQuery({ q: search.q })}`),
    enabled: on,
    placeholderData: keepPreviousData,
  }));
  const c = $derived(counts.data);

  function setSearch(patch: Partial<WebsiteSearch>, replace = false) {
    void goto(href(page.url.pathname, { ...search, cursor: undefined, ...patch }), { replace, reset: false });
  }
  const onSort = (sort: string | undefined, dir: SortDir | undefined) =>
    setSearch({ sort: sort as WebsiteSearch["sort"], dir });
  const tileHref = (patch: Partial<WebsiteSearch>) => href("/websites", patch);
</script>

<PageHeader icon={Globe} title={t("websites.title")} description={t("websites.description")}>
  {#snippet actions()}
    {#if on && canEdit}
      <Button onclick={() => setSearch({ add: "1" })}>
        <Plus aria-hidden="true" class="size-4" />
        {t("websites.add")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>

{#if !on}
  <ModuleOff canSwitch={canEdit} />
{:else}
  <details class="mb-4 rounded-xl border bg-card px-5 py-3 text-sm shadow-xs" data-testid="websites-help">
    <summary class="cursor-pointer font-medium">{t("websites.helpSummary")}</summary>
    <div class="mt-3 grid gap-3 text-muted-foreground @wide:grid-cols-3">
      <section>
        <h2 class="font-medium text-foreground">{t("websites.helpStage1Title")}</h2>
        <p>{t("websites.helpStage1Text")}</p>
      </section>
      <section>
        <h2 class="font-medium text-foreground">{t("websites.helpStage2Title")}</h2>
        <p>{t("websites.helpStage2Text")}</p>
      </section>
      <section>
        <h2 class="font-medium text-foreground">{t("websites.helpNeverTitle")}</h2>
        <p>{t("websites.helpNeverText")}</p>
      </section>
      <p class="@wide:col-span-3">{t("websites.notLegalAdvice")}</p>
    </div>
  </details>

  <!-- Key figures: every one leads to the list it counts. More of them from the wide step on. -->
  <div class="mb-4 hidden gap-3 @wide:grid @wide:grid-cols-4 @xwide:grid-cols-6" data-testid="websites-figures">
    <Tile label={t("websites.figureAssets")} value={c?.all ?? 0} href={tileHref({})}>
      {#snippet icon()}<Globe aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile label={t("websites.figureAttention")} value={c?.attention ?? 0} href={tileHref({ status: "attention" })}>
      {#snippet icon()}<ShieldCheck aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile label={t("websites.figureUnverified")} value={c?.unverified ?? 0} href={tileHref({ status: "unverified" })}>
      {#snippet icon()}<KeyRound aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile label={t("websites.figureStage2")} value={c?.stage2 ?? 0} href={tileHref({ status: "stage2" })}>
      {#snippet icon()}<Network aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <div class="hidden @xwide:contents">
      <Tile label={t("websites.figureCritical")} value={c?.open.critical ?? 0} href={tileHref({ sort: "critical" })} />
      <Tile label={t("websites.figureHigh")} value={c?.open.high ?? 0} href={tileHref({ sort: "high" })} />
    </div>
  </div>

  <div class="mb-4 flex flex-wrap items-center gap-3">
    <Segmented
      label={t("websites.statusFilter")}
      value={search.status ?? "all"}
      options={WEBSITE_STATUSES.map((s) => ({
        value: s,
        label: t(`websites.status.${s}`),
        count: c ? c[s] : null,
      }))}
      onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
    />
    <SearchInput
      class="ml-auto"
      label={t("websites.search")}
      value={search.q ?? ""}
      onChange={(q) => setSearch({ q: q || undefined }, true)}
    />
  </div>

  <Card>
    <table class="w-full text-left" data-testid="websites-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <SortHeader
            column="value"
            label={t("websites.columnAsset")}
            natural="asc"
            class="px-5"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="verification"
            label={t("websites.columnVerification")}
            natural="asc"
            class="hidden px-3 @3xl:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          {#each SEVERITY_ORDER as severity (severity)}
            <SortHeader
              column={severity}
              label={t(`severity.${severity}`)}
              natural="desc"
              align="right"
              class={severity === "low" ? "hidden px-3 @wide:table-cell" : "px-3"}
              current={search.sort}
              dir={search.dir}
              {onSort}
            />
          {/each}
          <SortHeader
            column="certificate"
            label={t("websites.columnCertificate")}
            natural="asc"
            class="hidden px-3 @wide:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("websites.columnStage1")}</th>
          <SortHeader
            column="stage2"
            label={t("websites.columnStage2")}
            natural="asc"
            class="hidden px-3 @3xl:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          <SortHeader
            column="lastPassive"
            label={t("websites.columnLastCheck")}
            natural="desc"
            class="hidden px-3 @3xl:table-cell"
            current={search.sort}
            dir={search.dir}
            {onSort}
          />
          {#if canEdit}
            <th class="w-14 px-3 py-2.5 text-right font-medium @wide:px-5">
              <span class="sr-only">{t("websites.columnActions")}</span>
            </th>
          {/if}
        </tr>
      </thead>
      <tbody>
        {#each query.data?.items ?? [] as asset (asset.id)}
          <WebsiteRow {asset} {canEdit} />
        {/each}
      </tbody>
    </table>
    <QueryStatus {query} />
    {#if query.data && query.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">
        {search.q || search.status ? t("websites.noMatch") : t("websites.empty")}
      </p>
    {/if}
    {#if query.data}
      <Pagination
        page={query.data}
        onCursor={(cursor) => void goto(href(page.url.pathname, { ...search, cursor }), { reset: false })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>
  {#if c}
    <p class="mt-3 text-sm text-muted-foreground">{t("websites.limitNote", { count: c.all, limit: c.limit })}</p>
  {/if}

  {#if canEdit && search.add === "1"}
    <AddWebsiteDialog onClose={() => setSearch({ add: undefined }, true)} />
  {/if}
{/if}
