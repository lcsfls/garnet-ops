<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { trendDays } from "../../trend.ts";
  import type { Overview } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import TrendChart from "../TrendChart.svelte";

  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  /** Open findings of one repository over 30 days. */
  let { id }: { id: string } = $props();
  const trend = createQuery(() => ({
    queryKey: ["repository", id, "trend", timeZone],
    queryFn: () => api<Overview["trend"]>(`/repositories/${id}/trend?tz=${encodeURIComponent(timeZone)}`),
  }));
</script>

<Card>
  <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
  {#if trend.data}
    <div class="px-5 pt-4 pb-4">
      <TrendChart days={trendDays(trend.data)} repositoryId={id} />
    </div>
  {:else}
    <QueryStatus query={trend} />
  {/if}
</Card>
