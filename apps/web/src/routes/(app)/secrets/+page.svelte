<script lang="ts">
  import { SECRET_SEVERITIES, type SecretSeverity } from "@garnetops/core/secrets";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { SvelteSet } from "svelte/reactivity";
  import { ApiError, api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import CloseSecretsDialog from "#lib/components/secrets/CloseSecretsDialog.svelte";
  import IgnoreRules, { type IgnoreDraft } from "#lib/components/secrets/IgnoreRules.svelte";
  import SecretDetail from "#lib/components/secrets/SecretDetail.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { rowClick } from "#lib/row-link.ts";
  import {
    placeText,
    type SecretRow,
    type SecretState,
    secretCountsQuery,
    secretRuleName,
  } from "#lib/secrets.ts";
  import { toast } from "#lib/toast.svelte.ts";
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
  const q = $derived(params.get("q") ?? undefined);
  const selected = $derived(params.get("id") ?? null);
  const setSearch = (patch: Record<string, string | undefined>) =>
    goto(
      href(page.url.pathname, {
        state: view === "open" ? undefined : view,
        severity: severity.length ? severity.join(",") : undefined,
        repositoryId,
        q,
        id: selected ?? undefined,
        ...patch,
      }),
      { reset: false },
    );

  const filters = $derived(
    href("", { state: view, severity: severity.join(",") || undefined, repositoryId, q }),
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
  const queryClient = useQueryClient();
  const items = $derived(list.data?.items ?? []);

  /** Rows ticked for one action on all of them. A change of the filters starts again: what is ticked is always on screen. */
  const ticked = new SvelteSet<string>();
  $effect(() => {
    void filters;
    ticked.clear();
  });
  const allTicked = $derived(items.length > 0 && items.every((s) => ticked.has(s.id)));
  const someTicked = $derived(ticked.size > 0 && !allTicked);
  const tickedRows = $derived(items.filter((s) => ticked.has(s.id)));
  const canClose = $derived(tickedRows.some((s) => s.state === "open"));
  const canReopen = $derived(tickedRows.some((s) => s.state !== "open"));
  const toggleAll = () => {
    if (allTicked) ticked.clear();
    else for (const s of items) ticked.add(s.id);
  };
  const toggle = (id: string) => (ticked.has(id) ? ticked.delete(id) : ticked.add(id));

  /** After closing the shown one, the next one in the list is shown: working down a list needs no extra click. */
  function showNext() {
    const at = items.findIndex((s) => s.id === selected);
    const next = items[at + 1] ?? items[at - 1];
    setSearch({ id: next && next.id !== selected ? next.id : undefined });
  }

  let bulkAction = $state<"revoke" | "dismiss" | null>(null);
  let bulkError = $state<string | null>(null);
  const bulk = createMutation(() => ({
    mutationFn: (body: { action: "revoke" | "dismiss" | "reopen"; reason?: string }) =>
      api<{ changed: number; skipped: number }>("/secrets/bulk", {
        method: "POST",
        body: { ids: [...ticked], ...body },
      }),
    onSuccess: async (result: { changed: number; skipped: number }) => {
      bulkAction = null;
      ticked.clear();
      toast.success(
        result.skipped > 0
          ? t("secrets.bulk.doneSkipped", { count: result.changed, skipped: result.skipped })
          : t("secrets.bulk.done", { count: result.changed }),
      );
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["secrets"] }),
        queryClient.invalidateQueries({ queryKey: ["secret"] }),
        queryClient.invalidateQueries({ queryKey: ["secret-counts"] }),
      ]);
    },
    onError: (e: Error) => {
      if (e instanceof ApiError && e.status === 422) bulkError = e.problem?.errors?.[0]?.message ?? null;
      else toast.error(t("errors.actionFailed"));
    },
  }));

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
    filters={{ state: view, severity: severity.join(",") || undefined, repositoryId, q }}
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
  <SearchInput
    class="ml-auto"
    label={t("secrets.search")}
    value={q ?? ""}
    onChange={(value) => setSearch({ q: value || undefined, id: undefined })}
  />
</div>

<div class="grid items-start gap-4 @[1450px]:grid-cols-[minmax(0,1fr)_32rem]">
  <Card>
    {#if canEdit && ticked.size > 0}
      <div
        class="sticky top-0 z-10 flex flex-wrap items-center gap-2 rounded-t-xl border-b bg-[var(--neutral-bg)] px-5 py-2.5"
        role="region"
        aria-label={t("secrets.bulk.label")}
        data-testid="secrets-bulk"
      >
        <span class="mr-2 text-sm font-semibold" aria-live="polite">{t("secrets.bulk.ticked", { count: ticked.size })}</span>
        {#if canClose}
          <Button class="h-8 px-3 text-sm" onclick={() => ((bulkAction = "revoke"), (bulkError = null))}>{t("secrets.revoke")}</Button>
          <Button class="h-8 px-3 text-sm" onclick={() => ((bulkAction = "dismiss"), (bulkError = null))}>{t("secrets.dismiss")}</Button>
        {/if}
        {#if canReopen}
          <Button class="h-8 px-3 text-sm" disabled={bulk.isPending} onclick={() => bulk.mutate({ action: "reopen" })}>
            {t("secrets.reopen")}
          </Button>
        {/if}
        <button type="button" class="link ml-auto text-sm" onclick={() => ticked.clear()}>{t("secrets.bulk.clear")}</button>
      </div>
    {/if}
    <table class="w-full text-left" data-testid="secrets-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          {#if canEdit}
            <th class="w-10 py-2.5 pr-0 pl-5">
              <Checkbox
                aria-label={t("secrets.bulk.all")}
                checked={allTicked}
                indeterminate={someTicked}
                disabled={items.length === 0}
                onchange={toggleAll}
              />
            </th>
          {/if}
          <th class="{canEdit ? 'px-3' : 'px-5'} py-2.5 font-medium">{t("secrets.columnSeverity")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnRule")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnRepository")}</th>
          <th class="px-3 py-2.5 font-medium">{t("secrets.columnWhere")}</th>
          <th class="hidden px-5 py-2.5 font-medium @4xl:table-cell">{t("secrets.columnFirstSeen")}</th>
        </tr>
      </thead>
      <tbody>
        {#each list.data?.items ?? [] as s (s.id)}
          <tr
            class="row-link border-b align-top last:border-0"
            aria-selected={selected === s.id}
            data-testid="secret-row"
            onclick={rowClick(() => setSearch({ id: s.id }))}
          >
            {#if canEdit}
              <td class="py-2.5 pr-0 pl-5">
                <Checkbox
                  aria-label={t("secrets.bulk.one", { rule: secretRuleName(s.ruleId), repository: s.repositoryName })}
                  checked={ticked.has(s.id)}
                  onchange={() => toggle(s.id)}
                />
              </td>
            {/if}
            <td class="{canEdit ? 'px-3' : 'px-5'} py-2.5"><SeverityBadge severity={s.severity} /></td>
            <td class="px-3 py-2.5">
              <a
                href={href(page.url.pathname, {
                  state: view === "open" ? undefined : view,
                  severity: severity.join(",") || undefined,
                  repositoryId,
                  q,
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
    <!-- Beside the list it stays in view while the list scrolls (AGENTS.md rule 5). -->
    <div class="order-first self-start @[1450px]:order-none @[1450px]:sticky @[1450px]:top-0 @[1450px]:max-h-[calc(100dvh-8.5rem)] @[1450px]:overflow-y-auto @[1450px]:rounded-lg">
      {#key selected}
        <SecretDetail
          id={selected}
          {canEdit}
          {canIgnore}
          onIgnoreSimilar={(draft) => (ignoreDraft = draft)}
          onClosed={view === "open" || view === "ignored" ? showNext : undefined}
        />
      {/key}
    </div>
  {/if}
</div>
<div class="mt-4">
  <IgnoreRules me={data.me} bind:draft={ignoreDraft} />
</div>

<CloseSecretsDialog
  action={bulkAction}
  count={ticked.size}
  pending={bulk.isPending}
  error={bulkError}
  onSubmit={(reason) => bulkAction && bulk.mutate({ action: bulkAction, reason })}
  onClose={() => (bulkAction = null)}
/>
