<script lang="ts">
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatNumber } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { scanErrorText } from "../../scan-error.ts";
  import { toQuery } from "../../search.ts";
  import type { Page, ScanRow } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Pagination from "../Pagination.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import ScanStateBadge from "../ui/ScanStateBadge.svelte";

  const TRIGGER_KEYS = {
    manual: "repository.triggerManual",
    schedule: "repository.triggerSchedule",
    webhook: "repository.triggerWebhook",
  } as const;

  /** Every scan of one repository, newest first. */
  let {
    id,
    cursor,
    pageSize,
    onCursor,
    onPageSize,
  }: {
    id: string;
    cursor?: string | undefined;
    pageSize?: number | undefined;
    onCursor: (cursor: string | undefined) => void;
    onPageSize: (size: number) => void;
  } = $props();

  const scans = createQuery(() => ({
    queryKey: ["scans", id, cursor, pageSize],
    queryFn: () => api<Page<ScanRow>>(`/scans${toQuery({ repositoryId: id, cursor, pageSize })}`),
    placeholderData: keepPreviousData,
  }));
</script>

<Card>
  <CardHeader title={t("repository.scanHistory")} description={t("repository.scanHistoryDescription")} />
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("repository.columnWhen")}</th>
        <th class="px-3 py-2.5 font-medium">{t("repository.columnResult")}</th>
        <th class="hidden px-3 py-2.5 text-right font-medium @xl:table-cell">{t("repository.columnPackages")}</th>
        <th class="hidden px-5 py-2.5 font-medium @3xl:table-cell">{t("repository.columnCommit")}</th>
      </tr>
    </thead>
    <tbody>
      {#each scans.data?.items ?? [] as s (s.id)}
        {@const at = s.finishedAt ?? s.createdAt}
        <tr class="border-b align-top last:border-0">
          <td class="px-5 py-2.5 text-sm whitespace-nowrap">
            <time datetime={at}>{formatDateTime(at)}</time>
            <div class="text-muted-foreground">{t(TRIGGER_KEYS[s.trigger])}</div>
          </td>
          <td class="px-3 py-2.5">
            <ScanStateBadge state={s.state} />
            {#if s.state === "succeeded"}
              <a
                href={href("/findings", { scanId: s.id, state: "all" })}
                class="mt-1 block text-sm text-muted-foreground hover:underline"
              >
                {t("overview.scanSummary", { added: s.newFindings ?? 0, resolved: s.resolvedFindings ?? 0 })}
              </a>
            {:else if s.error}
              <div class="mt-1 text-sm text-destructive-text">{scanErrorText(s.error)}</div>
            {/if}
          </td>
          <td class="hidden px-3 py-2.5 text-right tabular-nums @xl:table-cell">
            {s.packageCount === null ? "–" : formatNumber(s.packageCount)}
          </td>
          <td class="hidden px-5 py-2.5 font-mono text-sm @3xl:table-cell">
            {s.commitSha ? s.commitSha.slice(0, 12) : "–"}
            {#if s.branch}<div class="font-sans text-muted-foreground">{s.branch}</div>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={scans} />
  {#if scans.data && scans.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("overview.noScans")}</p>
  {/if}
  {#if scans.data}
    <Pagination page={scans.data} {onCursor} {onPageSize} />
  {/if}
</Card>
