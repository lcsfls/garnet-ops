<script lang="ts">
  import { Flame, GitBranch, ShieldAlert, ShieldCheck, TriangleAlert, Wrench } from "@lucide/svelte";
  import { cn } from "../../cn.ts";
  import { t } from "../../i18n.svelte.ts";
  import { trendDays } from "../../trend.ts";
  import type { Overview } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Tile from "../Tile.svelte";
  import TrendChart from "../TrendChart.svelte";
  import Banner from "../ui/Banner.svelte";
  import Activity from "./Activity.svelte";
  import FixFirst from "./FixFirst.svelte";
  import RecentGateRuns from "./RecentGateRuns.svelte";
  import RecentScans from "./RecentScans.svelte";
  import VulnerabilityData from "./VulnerabilityData.svelte";
  import WeekDelta from "./WeekDelta.svelte";

  let { data, admin }: { data: Overview; admin: boolean } = $props();

  const days = $derived(trendDays(data.trend));
  const critical = $derived(data.open.critical ?? 0);
  const fixHint = (severity: "critical" | "high") =>
    t("overview.fixAvailable", { count: data.fixableBySeverity[severity] ?? 0 });
</script>

<div class="grid gap-4">
  {#if critical > 0}
    <Banner title={t("overview.criticalBanner", { count: critical })}>
      {t("overview.criticalBannerHint", {
        repos: data.repositories.blocked,
        exploited: data.knownExploitedOpen,
      })}
      {#snippet action()}
        <a
          href={href("/findings", { severity: "critical" })}
          class="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
        >
          {t("overview.viewFindings")}
        </a>
      {/snippet}
    </Banner>
  {/if}

  <div class="grid grid-cols-2 gap-4 @3xl:grid-cols-3 @xwide:grid-cols-6">
    <Tile
      label={t("overview.criticalOpen")}
      value={critical}
      hint={fixHint("critical")}
      href={href("/findings", { severity: "critical" })}
    >
      {#snippet icon()}<Flame aria-hidden="true" class="size-4 text-destructive-text" />{/snippet}
      {#snippet delta()}<WeekDelta {days} severity="critical" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.highOpen")}
      value={data.open.high ?? 0}
      hint={fixHint("high")}
      href={href("/findings", { severity: "high" })}
    >
      {#snippet icon()}<TriangleAlert aria-hidden="true" class="size-4" />{/snippet}
      {#snippet delta()}<WeekDelta {days} severity="high" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.knownExploited")}
      value={data.knownExploitedOpen}
      hint={t("overview.knownExploitedHint")}
      href={href("/findings", { kev: "1" })}
    >
      {#snippet icon()}<ShieldAlert aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.fixable")}
      value={data.fixableOpen}
      hint={t("overview.fixableHint")}
      href={href("/findings", { fixable: "1" })}
    >
      {#snippet icon()}<Wrench aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.blockedRepos")}
      value={data.repositories.blocked}
      hint={`${t("overview.reposTotal", { count: data.repositories.total })} · ${t("overview.neverScanned", { count: data.repositories.never_scanned })}`}
      href={href("/repositories", { status: "blocked" })}
    >
      {#snippet icon()}<GitBranch aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("overview.accepted")}
      value={data.states.accepted ?? 0}
      hint={t("overview.acceptedHint")}
      href={href("/findings", { state: "accepted" })}
    >
      {#snippet icon()}<ShieldCheck aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
  </div>

  <!-- Mockup .ov-grid: two columns at the base step, four at xwide. -->
  <div
    class={cn(
      "grid gap-4 @wide:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]",
      "@wide:[grid-template-areas:'attn_act'_'gates_scans'_'trend_data']",
      "@xwide:grid-cols-4 @xwide:[grid-template-areas:'attn_attn_gates_act'_'trend_trend_data_scans']",
    )}
  >
    <div class="min-w-0 @wide:[grid-area:attn]">
      <FixFirst items={data.fixFirst} />
    </div>
    <div class="min-w-0 @wide:[grid-area:act]">
      <Activity items={data.activity} />
    </div>
    <div class="min-w-0 @wide:[grid-area:gates]">
      <RecentGateRuns />
    </div>
    <div class="min-w-0 @wide:[grid-area:scans]">
      <RecentScans items={data.recentScans} />
    </div>
    <div class="min-w-0 @wide:[grid-area:trend]">
      <Card class="h-full">
        <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
        <div class="px-5 pb-4">
          <TrendChart {days} />
        </div>
      </Card>
    </div>
    <div class="min-w-0 @wide:[grid-area:data]">
      <VulnerabilityData data={data.vulnerabilityData} sources={data.vulnerabilitySources} admin={admin} />
    </div>
  </div>
</div>
