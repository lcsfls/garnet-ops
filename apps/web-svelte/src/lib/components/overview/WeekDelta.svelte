<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { TrendDay } from "../../trend.ts";

  /** Change of open findings of one severity against seven days ago, from the trend. */
  let { days, severity }: { days: TrendDay[]; severity: "critical" | "high" } = $props();
  const today = $derived(days[days.length - 1]);
  const weekAgo = $derived(days[days.length - 8]);
</script>

{#if today && weekAgo}
  {@const diff = today[severity] - weekAgo[severity]}
  {#if diff === 0}
    {t("overview.deltaSame")}
  {:else}
    {diff < 0 ? t("overview.deltaDown", { count: Math.abs(diff) }) : t("overview.deltaUp", { count: diff })}
  {/if}
{/if}
