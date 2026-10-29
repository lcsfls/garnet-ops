<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { type ExposureDetail, type ExposureHistoryRow, errorKey } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";

  /** The latest runs of both stages. */
  let { detail, class: className = "" }: { detail: ExposureDetail; class?: string } = $props();

  function result(run: ExposureHistoryRow): string {
    if (run.state === "queued" || run.state === "running") return t(`websites.runState.${run.state}`);
    if (run.state === "failed") {
      const key = errorKey(run.error);
      return key ? t(key) : (run.error ?? "");
    }
    const c = run.findingCounts ?? {};
    const total = (c.critical ?? 0) + (c.high ?? 0) + (c.medium ?? 0) + (c.low ?? 0);
    const ports =
      run.stage === "active" && run.openPorts !== null
        ? ` · ${t("websites.runOpenPorts", { count: run.openPorts })}`
        : "";
    return `${t("websites.runFindings", { count: total })}${ports}`;
  }
</script>

<Card class={className}>
  <CardHeader title={t("websites.historyTitle")} description={t("websites.historyDescription")} />
  {#if detail.runs.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("websites.historyNone")}</p>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm" data-testid="websites-history">
        <thead class="text-muted-foreground">
          <tr class="border-y">
            <th class="px-5 py-2 font-medium">{t("websites.historyWhen")}</th>
            <th class="px-3 py-2 font-medium">{t("websites.historyStage")}</th>
            <th class="hidden px-3 py-2 font-medium @3xl:table-cell">{t("websites.historyTrigger")}</th>
            <th class="px-3 py-2 font-medium">{t("websites.historyResult")}</th>
          </tr>
        </thead>
        <tbody>
          {#each detail.runs as run (run.id)}
            <tr class="border-b align-top last:border-0">
              <td class="px-5 py-2.5 whitespace-nowrap">
                <time datetime={run.createdAt} title={formatDateTime(run.createdAt)}>{formatRelative(run.createdAt)}</time>
              </td>
              <td class="px-3 py-2.5">{t(`websites.stageName.${run.stage}`)}</td>
              <td class="hidden px-3 py-2.5 @3xl:table-cell">{t(`websites.trigger.${run.trigger}`)}</td>
              <td class={["px-3 py-2.5", run.state === "failed" && "text-destructive-text"]}>{result(run)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Card>
