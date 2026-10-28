<script lang="ts" module>
  export interface BarSeries<K extends string> {
    key: K;
    label: string;
    /** Tailwind fill class of the bars, e.g. "fill-chart-critical". */
    fill: string;
    /** Tailwind background class of the legend swatch, e.g. "bg-chart-critical". */
    swatch: string;
    /** Where the legend entry leads: the list behind the series, as a link such as `/findings?severity=high`. */
    link?: string;
  }

  export interface BarBucket<K extends string> {
    key: string;
    /** The bucket in words: a day, or the days of a week. */
    label: string;
    values: Record<K, number>;
  }
</script>

<script lang="ts" generics="K extends string">
  import { formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";

  /**
   * Bars per day or week: stacked (parts of one whole, such as open findings by severity) or
   * grouped (two counts side by side, such as found and resolved). Each bucket names its days and
   * counts on hover, the legend names every series with its total (or last value) and links to
   * the list behind it, and the same numbers are available as a table, so nothing depends on
   * colour or on hovering alone.
   */
  let {
    buckets,
    series,
    mode,
    summary,
    legendValue = "total",
  }: {
    buckets: BarBucket<K>[];
    series: BarSeries<K>[];
    mode: "stacked" | "grouped";
    /** One sentence for screen readers: what the chart shows and its main result. */
    summary: string;
    /** What the legend shows next to each series: the sum over all buckets or the last bucket's value. */
    legendValue?: "total" | "last";
  } = $props();

  const titleId = $props.id();
  const W = 600;
  const H = 160;
  const gap = $derived(buckets.length > 40 ? 2 : 4);
  const slot = $derived((W - gap * (buckets.length - 1)) / Math.max(buckets.length, 1));
  const sumOf = (b: BarBucket<K>) => series.reduce((s, x) => s + b.values[x.key], 0);
  const max = $derived(
    Math.max(
      1,
      ...buckets.map((b) => (mode === "stacked" ? sumOf(b) : Math.max(...series.map((x) => b.values[x.key])))),
    ),
  );
  const legend = (key: K) =>
    legendValue === "last"
      ? (buckets.at(-1)?.values[key] ?? 0)
      : buckets.reduce((s, b) => s + b.values[key], 0);
  const first = $derived(buckets[0]);
  const last = $derived(buckets.at(-1));

  /** The visible bars of one bucket: stacked bottom to top in reverse series order, or side by side. */
  function bars(b: BarBucket<K>, x0: number) {
    const out: { key: K; x: number; y: number; width: number; height: number; fill: string }[] = [];
    if (mode === "stacked") {
      let y = H;
      for (const s of [...series].reverse()) {
        const h = (b.values[s.key] / max) * (H - 4);
        y -= h;
        if (h > 0) out.push({ key: s.key, x: x0, y, width: slot, height: Math.max(0, h - 1), fill: s.fill });
      }
    } else {
      const w = (slot - 1) / series.length;
      series.forEach((s, j) => {
        const h = (b.values[s.key] / max) * (H - 4);
        if (h > 0) out.push({ key: s.key, x: x0 + j * (w + 1), y: H - h, width: w, height: h, fill: s.fill });
      });
    }
    return out;
  }
</script>

{#snippet legendContent(s: BarSeries<K>)}
  <span aria-hidden="true" class="size-2.5 rounded-sm {s.swatch}"></span>{s.label}<span class="text-foreground tabular-nums"
    >{formatNumber(legend(s.key))}</span
  >
{/snippet}

<div>
  <div class="flex items-baseline justify-between text-xs text-muted-foreground tabular-nums">
    <span>{formatNumber(max)}</span>
  </div>
  <svg
    viewBox="0 0 {W} {H}"
    preserveAspectRatio="none"
    role="img"
    aria-labelledby={titleId}
    class="block h-44 w-full border-b border-border"
  >
    <title id={titleId}>{summary}</title>
    {#each buckets as b, i (b.key)}
      {@const x0 = i * (slot + gap)}
      <g>
        <title>{`${b.label}: ${series.map((s) => `${formatNumber(b.values[s.key])} ${s.label}`).join(", ")}`}</title>
        <!-- An invisible full-height bar, so hovering a quiet bucket still shows its numbers. -->
        <rect x={x0} y={0} width={slot} height={H} class="fill-transparent" />
        {#each bars(b, x0) as bar (bar.key)}
          <rect x={bar.x} y={bar.y} width={bar.width} height={bar.height} rx={1.5} class={bar.fill} />
        {/each}
      </g>
    {/each}
  </svg>
  <div class="mt-1 flex justify-between gap-4 text-xs text-muted-foreground">
    <span>{first?.label}</span>
    <span>{last?.label}</span>
  </div>
  <ul class="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
    {#each series as s (s.key)}
      <li>
        {#if s.link}
          <a href={s.link} class="inline-flex items-center gap-1.5 hover:text-foreground hover:underline">
            {@render legendContent(s)}
          </a>
        {:else}
          <span class="inline-flex items-center gap-1.5">{@render legendContent(s)}</span>
        {/if}
      </li>
    {/each}
  </ul>
  <details class="mt-2 text-sm">
    <summary class="cursor-pointer text-muted-foreground hover:text-foreground">
      {t("statistics.showTable")}
    </summary>
    <div class="mt-2 max-h-72 overflow-auto">
      <table class="w-full text-left tabular-nums">
        <thead class="text-muted-foreground">
          <tr>
            <th scope="col" class="py-1 pr-3 font-normal">
              {t("statistics.period")}
            </th>
            {#each series as s (s.key)}
              <th scope="col" class="py-1 pr-3 text-right font-normal">
                {s.label}
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each buckets as b (b.key)}
            <tr class="border-t">
              <th scope="row" class="py-1 pr-3 font-normal">
                {b.label}
              </th>
              {#each series as s (s.key)}
                <td class="py-1 pr-3 text-right">
                  {formatNumber(b.values[s.key])}
                </td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </details>
</div>
