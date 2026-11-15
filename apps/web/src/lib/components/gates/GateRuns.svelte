<script lang="ts">
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { type GateSearch, toQuery } from "../../search.ts";
  import type { GateRunRow, Page, RepositoryRow } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import GateBadge from "../GateBadge.svelte";
  import Pagination from "../Pagination.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import Segmented from "../Segmented.svelte";
  import Select from "../ui/Select.svelte";
  import { gateReason } from "./gate-reason.ts";

  /** The latest gate runs, newest first; by result (with counts) and repository, as on the repositories page. */
  let {
    search,
    onCursor,
    onPageSize,
    onFilter,
  }: {
    search: GateSearch;
    onCursor: (cursor: string | undefined) => void;
    onPageSize: (pageSize: GateSearch["pageSize"]) => void;
    onFilter: (patch: Pick<GateSearch, "result" | "runsRepositoryId">) => void;
  } = $props();

  const RESULTS = ["all", "passed", "notes", "blocked"] as const;
  const filters = $derived({ result: search.result, repositoryId: search.runsRepositoryId });
  const runs = createQuery(() => ({
    queryKey: ["gate-runs", search.cursor, search.pageSize, filters],
    queryFn: () =>
      api<Page<GateRunRow>>(
        `/gates/runs${toQuery({ cursor: search.cursor, pageSize: search.pageSize, ...filters })}`,
      ),
    placeholderData: keepPreviousData,
  }));
  const counts = createQuery(() => ({
    queryKey: ["gate-run-counts", filters.repositoryId],
    queryFn: () =>
      api<Record<(typeof RESULTS)[number], number>>(
        `/gates/runs/counts${toQuery({ repositoryId: filters.repositoryId })}`,
      ),
    placeholderData: keepPreviousData,
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));

  function duration(run: GateRunRow) {
    if (!run.startedAt || !run.finishedAt) return "–";
    const s = Math.max(0, Math.round((Date.parse(run.finishedAt) - Date.parse(run.startedAt)) / 1000));
    return s < 60
      ? t("gates.seconds", { count: s })
      : t("gates.minutes", { minutes: Math.floor(s / 60), seconds: s % 60 });
  }
</script>

<Card>
  <CardHeader title={t("gates.runsTitle")} description={t("gates.runsDescription")} />
  <div class="flex flex-wrap items-center gap-3 px-5 pb-4">
    <Segmented
      label={t("gates.resultFilter")}
      value={search.result ?? "all"}
      options={RESULTS.map((r) => ({
        value: r,
        label: r === "all" ? t("pullRequests.gateAll") : t(`gates.result.${r}`),
        count: counts.data ? counts.data[r] : null,
      }))}
      onChange={(result) => onFilter({ result: result === "all" ? undefined : result })}
    />
    <Select
      aria-label={t("gates.runsRepository")}
      value={search.runsRepositoryId ?? ""}
      onchange={(e) => onFilter({ runsRepositoryId: e.currentTarget.value || undefined })}
      class="max-w-56"
    >
      <option value="">{t("findings.allRepositories")}</option>
      {#each repositories.data?.items ?? [] as r (r.id)}
        <option value={r.id}>{r.name}</option>
      {/each}
    </Select>
  </div>
  <QueryStatus query={runs} />
  {#if runs.data && runs.data.items.length === 0}
    <p class="px-5 pb-6 text-muted-foreground">
      {filters.result || filters.repositoryId ? t("gates.runsEmptyFiltered") : t("gates.runsEmpty")}
    </p>
  {/if}
  {#if runs.data && runs.data.items.length > 0}
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("findings.columnRepository")}</th>
          <th class="px-3 py-2.5 font-medium">{t("gates.columnTrigger")}</th>
          <th class="px-3 py-2.5 font-medium">{t("gates.columnResult")}</th>
          <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("gates.columnReason")}</th>
          <th class="hidden px-3 py-2.5 text-right font-medium @wide:table-cell">{t("gates.columnDuration")}</th>
          <th class="px-5 py-2.5 font-medium">{t("gates.columnTime")}</th>
        </tr>
      </thead>
      <tbody>
        {#each runs.data.items as run (run.id)}
          <tr class="border-b align-top last:border-0">
            <td class="px-5 py-2.5">
              <RepositoryLink id={run.repositoryId} name={run.repositoryName} class="font-medium" />
            </td>
            <td class="px-3 py-2.5 text-sm">
              {t(`gates.trigger.${run.trigger}`)}
              {#if run.ref || run.commitSha}
                <div class="font-mono text-[13px] break-all text-muted-foreground">
                  {[run.ref ?? run.branch, run.commitSha?.slice(0, 7)].filter(Boolean).join(" · ")}
                </div>
              {/if}
            </td>
            <td class="px-3 py-2.5">
              <GateBadge result={run.result} />
            </td>
            <td class="hidden px-3 py-2.5 text-sm text-muted-foreground @3xl:table-cell">
              {gateReason(run.matches)}
            </td>
            <td class="hidden px-3 py-2.5 text-right text-sm tabular-nums @wide:table-cell">
              {duration(run)}
            </td>
            <td class="px-5 py-2.5 text-sm whitespace-nowrap">
              <time datetime={run.createdAt} title={formatDateTime(run.createdAt)} class="dash-time">
                {formatRelative(run.createdAt)}
              </time>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <Pagination page={runs.data} {onCursor} {onPageSize} />
  {/if}
</Card>
