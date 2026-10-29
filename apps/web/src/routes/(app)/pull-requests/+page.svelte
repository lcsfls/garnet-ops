<script lang="ts">
  import { GitPullRequestArrow, RefreshCw, TriangleAlert } from "@lucide/svelte";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import GateBadge from "#lib/components/GateBadge.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { type PullRequestSearch, pullRequestSearch } from "#lib/search.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import type { PullRequestRow, PullRequestSource } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  const KNOWN_PROBLEMS = [
    "forge-unknown",
    "token-rejected",
    "forbidden",
    "not-found",
    "rate-limited",
  ] as const;
  const GATES = ["all", "passed", "notes", "blocked", "checking", "none"] as const;

  /**
   * Open pull requests of the repositories the person sees, with the quality gate result of each head commit (ADR 0032).
   * Titles and names come from the forge and are shown as text only; links are built from the repository address.
   */
  let { data }: { data: PageData } = $props();
  const canCheck = $derived(data.me.role !== "viewer");
  const search: PullRequestSearch = $derived(parseSearch(pullRequestSearch, page.url));
  const queryClient = useQueryClient();
  /** After **Refresh**, look again every few seconds for a minute: the worker reads the forges in the background. */
  let pollUntil = $state(0);
  const REFRESH_POLL_MS = 60_000;

  const list = createQuery(() => {
    const until = pollUntil;
    return {
      queryKey: ["pull-requests", search],
      queryFn: () =>
        api<{ items: PullRequestRow[]; truncated: boolean }>(
          href("/pull-requests", { repositoryId: search.repositoryId, gate: search.gate, q: search.q }),
        ),
      placeholderData: keepPreviousData,
      // A queued check turns into a result a little later.
      refetchInterval: (query: { state: { data?: { items: PullRequestRow[] } } }) =>
        Date.now() < until || query.state.data?.items.some((p) => p.checking) ? 4000 : 60_000,
    };
  });
  const sources = createQuery(() => {
    const until = pollUntil;
    return {
      queryKey: ["pull-request-sources"],
      queryFn: () => api<PullRequestSource[]>("/pull-requests/sources"),
      refetchInterval: () => (Date.now() < until ? 4000 : 60_000),
    };
  });
  const failing = $derived((sources.data ?? []).filter((s) => s.problem));

  const setSearch = (patch: Partial<PullRequestSearch>, replace = false) =>
    goto(href(page.url.pathname, { ...search, ...patch }), { reset: false, replace });

  const refresh = createMutation(() => ({
    mutationFn: () => api("/pull-requests/refresh", { method: "POST" }),
    onSuccess: () => {
      pollUntil = Date.now() + REFRESH_POLL_MS;
      toast.success(t("pullRequests.refreshQueued"));
    },
    onError: (e: Error) =>
      toast.error(
        e instanceof ApiError && e.status === 429 ? t("errors.tooManyAttempts") : t("errors.actionFailed"),
      ),
  }));
  const check = createMutation(() => ({
    mutationFn: (p: PullRequestRow) => api(`/pull-requests/${p.id}/check`, { method: "POST" }),
    onSuccess: async (_: unknown, p: PullRequestRow) => {
      toast.success(t("pullRequests.checkQueued", { number: p.number }));
      await queryClient.invalidateQueries({ queryKey: ["pull-requests"] });
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));

  function problemText(code: string | null): string {
    const known = KNOWN_PROBLEMS.find((k) => k === code);
    return known ? t(`pullRequests.problems.${known}`) : t("pullRequests.problemOther", { code: code ?? "" });
  }
</script>

<PageHeader icon={GitPullRequestArrow} title={t("pullRequests.title")} description={t("pullRequests.description")}>
  {#snippet actions()}
    {#if canCheck}
      <Button variant="outline" disabled={refresh.isPending} onclick={() => refresh.mutate()}>
        <RefreshCw aria-hidden="true" class="size-4" />
        {t("pullRequests.refresh")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>

<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("pullRequests.gateFilter")}
    value={search.gate ?? "all"}
    options={GATES.map((g) => ({
      value: g,
      label:
        g === "all"
          ? t("pullRequests.gateAll")
          : g === "checking"
            ? t("pullRequests.gateChecking")
            : g === "none"
              ? t("pullRequests.gateNone")
              : t(`gates.result.${g}`),
    }))}
    onChange={(gate) => setSearch({ gate: gate === "all" ? undefined : (gate as PullRequestSearch["gate"]) })}
  />
  <Select
    aria-label={t("pullRequests.columnRepository")}
    value={search.repositoryId ?? ""}
    onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined })}
    class="max-w-56"
  >
    <option value="">{t("findings.allRepositories")}</option>
    {#each sources.data ?? [] as r (r.id)}
      <option value={r.id}>{r.name}</option>
    {/each}
  </Select>
  <SearchInput
    class="ml-auto"
    label={t("pullRequests.search")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>

{#if failing.length > 0}
  <div class="mb-4 rounded-xl border bg-card px-5 py-3 text-sm" data-testid="pull-request-sources">
    <div class="flex items-center gap-2 font-medium text-warning-text">
      <TriangleAlert aria-hidden="true" class="size-4" />{t("pullRequests.sourcesTitle")}
    </div>
    <ul class="mt-1 grid gap-0.5 text-muted-foreground">
      {#each failing as s (s.id)}
        <li>{t("pullRequests.sourceProblem", { name: s.name, problem: problemText(s.problem) })}</li>
      {/each}
    </ul>
  </div>
{/if}

<Card>
  <p class="border-b px-5 py-3 text-sm text-muted-foreground">{t("pullRequests.hint")}</p>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("pullRequests.columnPullRequest")}</th>
        <th class="px-3 py-2.5 font-medium">{t("pullRequests.columnRepository")}</th>
        <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("pullRequests.columnBranches")}</th>
        <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("pullRequests.columnUpdated")}</th>
        <th class="px-5 py-2.5 font-medium">{t("pullRequests.columnGate")}</th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as p (p.id)}
        <tr class="border-b align-top last:border-0" data-testid="pull-request">
          <td class="max-w-0 px-5 py-2.5 @wide:max-w-none">
            <div class="flex flex-wrap items-center gap-2">
              <a
                href={p.url}
                target="_blank"
                rel="noopener noreferrer"
                class="min-w-0 font-medium break-words text-primary-text hover:underline"
              >
                <span class="text-muted-foreground">#{p.number}</span>
                {p.title}
              </a>
              {#if p.draft}<Badge tone="neutral">{t("pullRequests.draft")}</Badge>{/if}
            </div>
            {#if p.author}
              <div class="text-[13px] text-muted-foreground">{t("pullRequests.by", { author: p.author })}</div>
            {/if}
          </td>
          <td class="px-3 py-2.5"><RepositoryLink id={p.repositoryId} name={p.repositoryName} /></td>
          <td class="hidden px-3 py-2.5 font-mono text-sm break-all @wide:table-cell">
            {p.headRef ?? "–"} → {p.baseRef ?? "–"}
          </td>
          <td class="hidden px-3 py-2.5 text-sm whitespace-nowrap text-muted-foreground @3xl:table-cell">
            {#if p.updatedAt}
              <time datetime={p.updatedAt} title={formatDateTime(p.updatedAt)}>{formatRelative(p.updatedAt)}</time>
            {/if}
          </td>
          <td class="px-5 py-2.5">
            <div class="flex flex-wrap items-center gap-2">
              {#if p.checking}
                <span class="text-sm text-muted-foreground">{t("pullRequests.checking")}</span>
              {:else if p.gate}
                <a href={href("/gates", { repositoryId: p.repositoryId })} title={t("pullRequests.openGate")}>
                  <GateBadge result={p.gate.result} />
                </a>
              {:else}
                <span class="text-sm text-muted-foreground">{t("pullRequests.notChecked")}</span>
              {/if}
              {#if canCheck && !p.checking}
                <Button
                  variant="outline"
                  class="h-8 whitespace-nowrap"
                  aria-label={t("pullRequests.checkNowFor", { number: p.number, repository: p.repositoryName })}
                  disabled={check.isPending}
                  onclick={() => check.mutate(p)}
                >
                  {t("pullRequests.checkNow")}
                </Button>
              {/if}
            </div>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">
      {search.gate || search.repositoryId || search.q ? t("pullRequests.emptyFiltered") : t("pullRequests.empty")}
    </p>
  {/if}
  {#if list.data?.truncated}
    <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("pullRequests.truncated")}</p>
  {/if}
</Card>
