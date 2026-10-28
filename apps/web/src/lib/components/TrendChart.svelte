<script lang="ts">
  import { formatCalendarDate, formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";
  import { TREND_SEVERITIES, type TrendDay, type TrendSeverity } from "../trend.ts";
  import { href } from "../url.ts";

  const FILL: Record<TrendSeverity, string> = {
    critical: "fill-chart-critical",
    high: "fill-chart-high",
    medium: "fill-chart-medium",
    low: "fill-chart-low",
  };
  const SWATCH: Record<TrendSeverity, string> = {
    critical: "bg-chart-critical",
    high: "bg-chart-high",
    medium: "bg-chart-medium",
    low: "bg-chart-low",
  };

  const total = (d: TrendDay) => TREND_SEVERITIES.reduce((sum, s) => sum + d[s], 0);

  /**
   * Stacked bars of open findings per day. Each bar names its day and counts on hover; the legend links to the matching
   * findings, so the chart leads somewhere like every other figure on the overview.
   */
  let { days, repositoryId }: { days: TrendDay[]; repositoryId?: string } = $props();
  const titleId = $props.id();
  const W = 600;
  const H = 160;
  const gap = 4;
  const barWidth = $derived((W - gap * (days.length - 1)) / days.length);
  const max = $derived(Math.max(1, ...days.map(total)));
  const first = $derived(days[0]);
  const last = $derived(days[days.length - 1]);

  /** The stacked segments of one day, bottom to top in severity order low -> critical. */
  function segments(d: TrendDay) {
    let y = H;
    return [...TREND_SEVERITIES].reverse().flatMap((s) => {
      const h = (d[s] / max) * (H - 4);
      y -= h;
      return h > 0 ? [{ s, y, h }] : [];
    });
  }
</script>

<div>
  <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" role="img" aria-labelledby={titleId} class="block h-44 w-full">
    <title id={titleId}>
      {t("overview.trendSummary", {
        first: first ? formatCalendarDate(first.day) : "",
        firstCount: first ? total(first) : 0,
        last: last ? formatCalendarDate(last.day) : "",
        lastCount: last ? total(last) : 0,
      })}
    </title>
    {#each days as d, i (d.day)}
      <g>
        <title
          >{`${formatCalendarDate(d.day)}: ${TREND_SEVERITIES.map((s) => `${formatNumber(d[s])} ${t(`severity.${s}`)}`).join(", ")}`}</title
        >
        <!-- An invisible full-height bar, so hovering a quiet day still shows its numbers. -->
        <rect x={i * (barWidth + gap)} y={0} width={barWidth} height={H} class="fill-transparent" />
        {#each segments(d) as seg (seg.s)}
          <rect
            x={i * (barWidth + gap)}
            y={seg.y}
            width={barWidth}
            height={Math.max(0, seg.h - 1)}
            rx={1.5}
            class={FILL[seg.s]}
          />
        {/each}
      </g>
    {/each}
  </svg>
  <ul class="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
    {#each TREND_SEVERITIES as s (s)}
      <li>
        <a
          href={href("/findings", { severity: s, repositoryId })}
          class="inline-flex items-center gap-1.5 hover:text-foreground hover:underline"
        >
          <span aria-hidden="true" class="size-2.5 rounded-sm {SWATCH[s]}"></span>
          {t(`severity.${s}`)}
          <span class="text-foreground">{last ? formatNumber(last[s]) : 0}</span>
        </a>
      </li>
    {/each}
  </ul>
</div>
