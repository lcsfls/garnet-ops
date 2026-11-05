<script lang="ts">
  import { Flame, ShieldAlert, TriangleAlert, Wrench } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { trendDays } from "../../trend.ts";
  import type { Overview } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Tile from "../Tile.svelte";
  import TrendChart from "../TrendChart.svelte";
  import Activity from "./Activity.svelte";
  import FixFirst from "./FixFirst.svelte";
  import HeroBanner from "./HeroBanner.svelte";
  import VulnerabilityData from "./VulnerabilityData.svelte";
  import WeekDelta from "./WeekDelta.svelte";

  /**
   * The overview (AGENTS.md rules 5 and 6): the top statement, four key figures, then two columns from the wide step on:
   * what to fix and the trend on the left, what happened and the data behind it on the right. Each column stacks its own
   * cards, so no card is stretched to the height of its neighbour. At xwide the cards gain columns, not padding.
   */
  let { data, admin }: { data: Overview; admin: boolean } = $props();

  const days = $derived(trendDays(data.trend));
  const series = (severity: "critical" | "high") => days.map((d) => d[severity]);
  const fixHint = (severity: "critical" | "high") =>
    t("overview.fixAvailable", { count: data.fixableBySeverity[severity] ?? 0 });
</script>

<div class="grid gap-4">
  <HeroBanner {data} />

  <div class="grid grid-cols-2 gap-4 @3xl:grid-cols-4" data-testid="overview-kpis">
    <Tile
      label={t("overview.criticalOpen")}
      value={data.open.critical ?? 0}
      tone="critical"
      hint={fixHint("critical")}
      href={href("/findings", { severity: "critical" })}
      trend={series("critical")}
    >
      {#snippet icon()}<Flame aria-hidden="true" class="size-4" />{/snippet}
      {#snippet delta()}<WeekDelta {days} severity="critical" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.highOpen")}
      value={data.open.high ?? 0}
      tone="high"
      hint={fixHint("high")}
      href={href("/findings", { severity: "high" })}
      trend={series("high")}
    >
      {#snippet icon()}<TriangleAlert aria-hidden="true" class="size-4" />{/snippet}
      {#snippet delta()}<WeekDelta {days} severity="high" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.fixable")}
      value={data.fixableOpen}
      tone="neutral"
      hint={t("overview.fixableHint")}
      href={href("/findings", { fixable: "1" })}
    >
      {#snippet icon()}<Wrench aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.knownExploited")}
      value={data.knownExploitedOpen}
      tone="critical"
      hint={t("overview.knownExploitedHint")}
      href={href("/findings", { kev: "1" })}
    >
      {#snippet icon()}<ShieldAlert aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
  </div>

  <div class="grid items-start gap-4 @wide:grid-cols-[minmax(0,2fr)_minmax(0,1fr)] @xwide:grid-cols-[minmax(0,5fr)_minmax(0,3fr)]">
    <div class="grid min-w-0 content-start gap-4">
      <FixFirst items={data.remedies} summary={data.remedySummary} />
      <Card>
        <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
        <div class="px-5 pb-4">
          <TrendChart {days} />
        </div>
      </Card>
    </div>
    <div class="grid min-w-0 content-start gap-4">
      <Activity items={data.activity} />
      <VulnerabilityData data={data.vulnerabilityData} sources={data.vulnerabilitySources} {admin} />
    </div>
  </div>
</div>
