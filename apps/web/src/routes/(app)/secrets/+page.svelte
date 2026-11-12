<script lang="ts">
  import { SECRET_SEVERITIES, type SecretSeverity } from "@garnetops/core/secrets";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import IgnoreRules, { type IgnoreDraft } from "#lib/components/secrets/IgnoreRules.svelte";
  import SecretDetail from "#lib/components/secrets/SecretDetail.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import {
    placeText,
    type SecretRow,
    type SecretState,
    secretCountsQuery,
    secretRuleName,
  } from "#lib/secrets.ts";
  import type { Page, RepositoryRow } from "#lib/types.ts";
  import { href } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * Secrets and sensitive files found in repositories (ADR 0049). The list, and the chosen one beside it at the wide steps or
   * below it on smaller screens (AGENTS.md rule 5). Nothing here shows a value: GarnetOps never has it.
   */
  let { data }: { data: PageData } = $props();

  const STATES = ["open", "ignored", "revoked", "dismissed", "all"] as const;
  type View = (typeof STATES)[number];
  const params = $derived(page.url.searchParams);
  const view: View = $derived(
    (STATES as readonly string[]).includes(params.get("state") ?? "")
      ? (params.get("state") as View)
      : "open",
  );
  const severity = $derived(
    (params.get("severity") ?? "")
      .split(",")
      .filter((s): s is SecretSeverity => (SECRET_SEVERITIES as readonly string[]).includes(s)),
  );
  const repositoryId = $derived(params.get("repositoryId") ?? undefined);
  const selected = $derived(params.get("id") ?? null);
  const setSearch = (patch: Record<string, string | undefined>) =>
    goto(
      href(page.url.pathname, {
        state: view === "open" ? undefined : view,
        severity: severity.length ? severity.join(",") : undefined,
        repositoryId,
        id: selected ?? undefined,
        ...patch,
      }),
      { reset: false },
    );

  const filters = $derived(
    href("", { state: view, severity: severity.join(",") || undefined, repositoryId }),
  );
  const list = createQuery(() => ({
    queryKey: ["secrets", filters],
    queryFn: () => api<{ items: SecretRow[]; more: boolean }>(`/secrets${filters}`),
    placeholderData: keepPreviousData,
  }));
  const counts = createQuery(() => secretCountsQuery(href("", { repositoryId })));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
  const canEdit = $derived(data.me.role !== "viewer");
  const canIgnore = $derived(isAdmin(data.me));
  let ignoreDraft = $state<IgnoreDraft | null>(null);

  const toggleSeverity = (s: SecretSeverity) =>
    setSearch({
      severity:
        (severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s]).join(",") || undefined,
    });
  const stateCount = (s: View) =>
    counts.data
      ? s === "all"
        ? counts.data.states.open +
          counts.data.states.ignored +
          counts.data.states.revoked +
          counts.data.states.dismissed
        : counts.data.states[s as SecretState | "ignored"]
      : null;
</script>

{#snippet headerActions()}
  <ExportMenu
    path="/secrets/export"
    hint={t("secrets.export.hint")}
    filters={{ state: view, severity: severity.join(",") || undefined, repositoryId }}
  />
{/snippet}
<PageHeader title={t("secrets.title")} description={t("secrets.description")} actions={headerActions} />
<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("secrets.stateLabel")}
    value={view}
    options={STATES.map((s) => ({ value: s, label: t(`secrets.state.${s}`), count: stateCount(s) }))}
    onChange={(value) => setSearch({ state: value === "open" ? undefined : value })}
  />
  <fieldset class="flex flex-wrap gap-1.5">
    <legend class="sr-only">{t("secrets.severityLabel")}</legend>
    {#each SECRET_SEVERITIES as s (s)}
      <button
        type="button"
        aria-pressed={severity.includes(s)}
        class="rounded-md border border-control px-1.5 py-1 hover:bg-[var(--hover-bg)] aria-pressed:bg-[var(--neutral-bg)] aria-pressed:font-semibold"
        onclick={() => toggleSeverity(s)}
      >
        <SeverityBadge severity={s} />
        {#if view === "open" && counts.data}
          <span class="ml-1 text-sm tabular-nums">{counts.data.open[s] ?? 0}</span>
        {/if}
      </button>
    {/each}
  </fieldset>
  <Select
    aria-label={t("secrets.repository")}
    value={repositoryId ?? ""}
    onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined, id: undefined })}
    class="max-w-56"
  >
    <option value="">{t("findings.allRepositories")}</option>
    {#each repositories.data?.items ?? [] as r (r.id)}
      <option value={r.id}>{r.name}</option>
    {/each}
  </Select>
</div>

<div class="grid items-start gap-4 @[1450px]:grid-cols-[minmax(0,1fr)_32rem]">
  <Card>
    <table class="w-full text-left" data-testid="secrets-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("secrets.columnSeverity")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnRule")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnRepository")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnWhere")}</th>
          <th class="hidden px-5 py-2.5 font-medium @4xl:table-cell">{t("secrets.columnFirstSeen")}</th>
        </tr>
      </thead>
      <tbody>
        {#each list.data?.items ?? [] as s (s.id)}
          <tr
            class="border-b align-top last:border-0 {selected === s.id ? 'bg-[var(--row-selected-bg)]' : ''}"
            data-testid="secret-row"
          >
            <td class="px-5 py-2.5"><SeverityBadge severity={s.severity} /></td>
            <td class="px-3 py-2.5">
              <a
                href={href(page.url.pathname, {
                  state: view === "open" ? undefined : view,
                  severity: severity.join(",") || undefined,
                  repositoryId,
                  id: s.id,
                })}
                aria-current={selected === s.id ? "true" : undefined}
                class="link text-sm {selected === s.id ? 'font-semibold' : ''}">{secretRuleName(s.ruleId)}</a
              >
            </td>
            <td class="px-3 py-2.5"><RepositoryLink id={s.repositoryId} name={s.repositoryName} /></td>
            <td class="px-3 py-2.5 text-sm">
              {#if s.place}
                <span class="font-mono break-all">{placeText(s.place)}</span>
                {#if s.treeLocationCount > 1}
                  <span class="block text-muted-foreground">{t("secrets.morePlaces", { count: s.treeLocationCount - 1 })}</span>
                {/if}
              {:else}
                <span class="text-muted-foreground">{t("secrets.onlyInHistory")}</span>
              {/if}
            </td>
            <td class="hidden px-5 py-2.5 text-sm text-muted-foreground @4xl:table-cell">{formatRelative(s.firstSeenAt)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && list.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground" data-testid="secrets-empty">
        {view === "open" && severity.length === 0 ? t("secrets.empty") : t("secrets.emptyOther")}
      </p>
    {/if}
    {#if list.data?.more}
      <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("secrets.more")}</p>
    {/if}
  </Card>
  {#if selected}
    {#key selected}
      <SecretDetail id={selected} {canEdit} {canIgnore} onIgnoreSimilar={(draft) => (ignoreDraft = draft)} />
    {/key}
  {/if}
</div>
<div class="mt-4">
  <IgnoreRules me={data.me} bind:draft={ignoreDraft} />
</div>
