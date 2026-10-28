<script lang="ts">
  import { ExternalLink, TriangleAlert } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api } from "../../api.ts";
  import { camelCode, isBusy, PR_TONE, safeHttpsUrl } from "../../fixes.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { type FixSearch, toQuery } from "../../search.ts";
  import type { FixPrRow, Page } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import Pagination from "../Pagination.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import Badge from "../ui/Badge.svelte";
  import Select from "../ui/Select.svelte";
  import type { SetFixSearch } from "./FixProposals.svelte";

  const PR_STATES = ["open", "merged", "closed", "failed"] as const;

  /** The pull requests GarnetOps opened (ADR 0014), newest first, filtered by state. */
  let { search, setSearch }: { search: FixSearch; setSearch: SetFixSearch } = $props();

  const query = $derived(
    toQuery({ ...search, state: search.prState }, [
      "view",
      "prState",
      "id",
      "sort",
      "dir",
      "action",
      "severity",
      "ecosystem",
      "pr",
      "q",
    ]),
  );
  const list = createQuery(() => ({
    queryKey: ["fixes", "prs", query],
    queryFn: () => api<Page<FixPrRow>>(`/fixes/prs${query}`),
    placeholderData: keepPreviousData,
    refetchInterval: (q: { state: { data: Page<FixPrRow> | undefined } }) =>
      q.state.data?.items.some((i) => isBusy(i.state)) ? 3000 : false,
  }));
</script>

<div class="mb-4 flex flex-wrap items-center gap-3">
  <Select
    aria-label={t("fixes.prStateFilter")}
    value={search.prState ?? ""}
    onchange={(e) => setSearch({ prState: (e.currentTarget.value || undefined) as FixSearch["prState"] })}
    class="max-w-56"
  >
    <option value="">{t("fixes.allStates")}</option>
    {#each PR_STATES as s (s)}
      <option value={s}>{t(`fixes.prState.${s}`)}</option>
    {/each}
  </Select>
</div>
<Card class="@container/list">
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("fixes.columnChange")}</th>
        <th class="hidden px-3 py-2.5 font-medium @2xl/list:table-cell">
          {t("fixes.columnRepository")}
        </th>
        <th class="px-3 py-2.5 font-medium">{t("fixes.columnStatus")}</th>
        <th class="hidden px-3 py-2.5 font-medium @4xl/list:table-cell">
          {t("fixes.columnRequestedBy")}
        </th>
        <th class="hidden px-3 py-2.5 font-medium @5xl/list:table-cell">
          {t("fixes.columnCreated")}
        </th>
        <th class="hidden px-5 py-2.5 font-medium @7xl/list:table-cell">
          {t("fixes.columnChecked")}
        </th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as pr (pr.id)}
        {@const url = safeHttpsUrl(pr.url)}
        <tr class="border-b align-top last:border-0">
          <td class="px-5 py-2.5">
            <div class="font-mono font-medium break-all">{pr.packageName}</div>
            <div class="font-mono text-sm text-muted-foreground">
              {t("fixes.versionChange", { from: pr.from, to: pr.to })}
            </div>
            <div class="mt-1 flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
              <span class="break-all">{pr.manifestPath}</span>
              {#if pr.majorUpgrade}
                <Badge tone="outline">
                  <TriangleAlert aria-hidden="true" />
                  {t("fixes.majorUpgrade")}
                </Badge>
              {/if}
            </div>
          </td>
          <td class="hidden px-3 py-2.5 @2xl/list:table-cell">
            <RepositoryLink id={pr.repositoryId} name={pr.repositoryName} />
          </td>
          <td class="px-3 py-2.5">
            <div class="grid gap-1">
              <Badge tone={PR_TONE[pr.state]}>{t(`fixes.prState.${pr.state}`)}</Badge>
              {#if url && pr.number !== null}
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="inline-flex items-center gap-1 text-sm font-medium text-primary-text hover:underline"
                >
                  {t("fixes.prNumber", { number: pr.number })}
                  <ExternalLink aria-hidden="true" class="size-3.5" />
                  <span class="sr-only">{t("fixes.openOnForge")}</span>
                </a>
              {/if}
              {#if pr.state === "failed" && pr.reason}
                <span class="text-sm text-destructive-text">
                  {t(`fixes.failure.${camelCode(pr.reason)}` as MessageKey)}
                </span>
              {/if}
              {#if pr.state === "open" && pr.reason}
                <span class="text-sm text-muted-foreground">
                  {t("fixes.prCheckProblem", {
                    reason: t(`fixes.failure.${camelCode(pr.reason)}` as MessageKey),
                  })}
                </span>
              {/if}
            </div>
          </td>
          <td class="hidden px-3 py-2.5 text-sm @4xl/list:table-cell">{pr.requestedBy ?? "–"}</td>
          <td class="hidden px-3 py-2.5 text-sm whitespace-nowrap @5xl/list:table-cell">
            <time datetime={pr.createdAt}>{formatDateTime(pr.createdAt)}</time>
            <div class="text-muted-foreground">{formatRelative(pr.createdAt)}</div>
          </td>
          <td class="hidden px-5 py-2.5 text-sm @7xl/list:table-cell">
            {#if pr.lastCheckedAt}
              {formatRelative(pr.lastCheckedAt)}
            {:else}
              <span class="text-muted-foreground">–</span>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("fixes.emptyPrs")}</p>
  {/if}
  {#if list.data}
    <Pagination
      page={list.data}
      onCursor={(cursor) =>
        void goto(href(page.url.pathname, { ...search, cursor }), { reset: false })}
      onPageSize={(pageSize) => setSearch({ pageSize })}
    />
  {/if}
</Card>
