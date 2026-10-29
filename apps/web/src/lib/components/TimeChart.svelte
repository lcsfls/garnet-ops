<script lang="ts" module>
  export interface ChartSeries<K extends string> {
    key: K;
    label: string;
    /** Tailwind fill class of the marks, e.g. "fill-chart-critical". */
    fill: string;
    /** Tailwind stroke class of the line on top of an area, e.g. "stroke-chart-critical". */
    stroke?: string;
    /** Tailwind background class of the legend swatch and the readout key, e.g. "bg-chart-critical". */
    swatch: string;
    /** Where the legend entry leads: the list behind the series, as a link such as `/findings?severity=high`. */
    link?: string;
  }

  export interface ChartBucket<K extends string> {
    key: string;
    /** The bucket in words: a day, or the days of a week. */
    label: string;
    values: Record<K, number>;
  }
</script>

<script lang="ts" generics="K extends string">
  import { goto } from "$app/navigation";
  import { columnPath, niceTicks } from "../chart.ts";
  import { chartFocus } from "../chart-focus.svelte.ts";
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";

  /**
   * Counts per day or week, three ways: stacked areas (parts of one whole over time, such as open findings
   * by severity), stacked columns (results per bucket, such as gate runs), or diverging columns (one count
   * above the baseline and one below, such as found and resolved). A crosshair follows the pointer or the
   * arrow keys and names every series of that bucket; charts with the same `sync` group move their
   * crosshairs together. The legend names every series with its total (or last value) and links to the
   * list behind it, and the same numbers are available as a table, so nothing depends on colour or on
   * hovering alone.
   */
  let {
    buckets,
    series,
    kind,
    summary,
    granularity,
    legendValue = "total",
    sync,
    linkOf,
    selectHint,
  }: {
    buckets: ChartBucket<K>[];
    series: ChartSeries<K>[];
    /** "diverging" takes two series: the first above the baseline, the second below. */
    kind: "area" | "columns" | "diverging";
    /** One sentence for screen readers: what the chart shows and its main result. */
    summary: string;
    granularity: "day" | "week";
    /** What the legend shows next to each series: the sum over all buckets or the last bucket's value. */
    legendValue?: "total" | "last";
    /** Charts with the same group share their crosshair. */
    sync?: string;
    /**
     * The list behind one series in one bucket. A click on the chart, Enter on the keyboard (the first series)
     * and the numbers in the table lead there.
     */
    linkOf?: (index: number, key: K) => string | undefined;
    /** Where a click or Enter leads, in words, for screen readers. */
    selectHint?: string;
  } = $props();

  const uid = $props.id();
  const H = 176;
  const PAD_TOP = 8;
  const PAD_LEFT = 40;
  const GAP = 2;

  let width = $state(0);
  let localIndex = $state<number | null>(null);

  const n = $derived(buckets.length);
  const plotH = H - PAD_TOP - 1;
  const band = $derived(n > 0 ? Math.max(0, width - PAD_LEFT) / n : 0);
  const barW = $derived(Math.max(1, Math.min(24, band - GAP)));
  const cx = (i: number) => PAD_LEFT + band * (i + 0.5);

  const sumOf = (b: ChartBucket<K>) => series.reduce((s, x) => s + b.values[x.key], 0);
  const largest = $derived(
    kind === "diverging"
      ? Math.max(0, ...buckets.flatMap((b) => series.map((s) => b.values[s.key])))
      : Math.max(0, ...buckets.map(sumOf)),
  );
  const ticks = $derived(niceTicks(largest));
  const domainTop = $derived(ticks.at(-1) ?? 1);
  /** The baseline: the bottom of the plot, or its middle when the second series runs below it. */
  const base = $derived(kind === "diverging" ? PAD_TOP + plotH / 2 : PAD_TOP + plotH);
  const scale = $derived((kind === "diverging" ? plotH / 2 : plotH) / domainTop);
  const y = (v: number) => base - v * scale;

  /** Each series' lower and upper edge per bucket, stacked from the last series up (low severity at the bottom). */
  const stacked = $derived.by(() => {
    const lower = buckets.map(() => 0);
    return [...series].reverse().map((s) => {
      const lo = [...lower];
      const hi = buckets.map((b, i) => {
        lower[i] = (lower[i] ?? 0) + b.values[s.key];
        return lower[i];
      });
      return { s, lo, hi };
    });
  });

  const point = (v: number, i: number) => `${cx(i)},${y(v)}`;
  const areaPath = (lo: number[], hi: number[]) =>
    `M${hi.map(point).join("L")}L${lo.map(point).reverse().join("L")}Z`;
  const linePath = (hi: number[]) => `M${hi.map(point).join("L")}`;

  /** The columns of one bucket, with a 2px gap between stacked segments. */
  function columns(i: number): { key: K; d: string; fill: string }[] {
    const b = buckets[i];
    if (!b) return [];
    const x = cx(i) - barW / 2;
    if (kind === "diverging") {
      const [up, down] = series;
      const out: { key: K; d: string; fill: string }[] = [];
      const u = up ? b.values[up.key] : 0;
      const d = down ? b.values[down.key] : 0;
      if (up && u > 0) out.push({ key: up.key, d: columnPath(x, Math.min(y(u), base - 2), base - 1, barW, "top"), fill: up.fill });
      if (down && d > 0) {
        out.push({ key: down.key, d: columnPath(x, base + 1, Math.max(y(-d), base + 2), barW, "bottom"), fill: down.fill });
      }
      return out;
    }
    const sum = sumOf(b);
    return stacked.flatMap(({ s, lo, hi }) => {
      const from = lo[i] ?? 0;
      const to = hi[i] ?? 0;
      if (to === from) return [];
      const top = y(to);
      const bottom = from > 0 ? y(from) - GAP : base;
      return [{ key: s.key, d: columnPath(x, top, Math.max(top + 1, bottom), barW, to === sum ? "top" : null), fill: s.fill }];
    });
  }

  /** The gridlines: values up from the baseline, mirrored below it for diverging columns. */
  const grid = $derived(
    kind === "diverging"
      ? [...ticks.map((v) => ({ v, at: y(v) })), ...ticks.slice(1).map((v) => ({ v, at: y(-v) }))]
      : ticks.map((v) => ({ v, at: y(v) })),
  );

  const active = $derived.by(() => {
    const i = sync ? (chartFocus.group === sync ? chartFocus.index : null) : localIndex;
    return i !== null && i < n ? i : null;
  });
  const owns = $derived(sync ? chartFocus.owner === uid : localIndex !== null);

  function setActive(i: number | null) {
    if (!sync) {
      localIndex = i;
      return;
    }
    chartFocus.group = i === null ? null : sync;
    chartFocus.index = i;
    chartFocus.owner = i === null ? null : uid;
  }

  function release() {
    if (!sync || chartFocus.owner === uid) setActive(null);
  }

  function indexAt(e: MouseEvent): number | null {
    if (n === 0 || band === 0) return null;
    const rect = (e.currentTarget as Element).getBoundingClientRect();
    return Math.min(n - 1, Math.max(0, Math.floor((e.clientX - rect.left - PAD_LEFT) / band)));
  }

  function onKeydown(e: KeyboardEvent) {
    if (n === 0) return;
    const i = active ?? n - 1;
    const next =
      e.key === "ArrowLeft"
        ? Math.max(0, i - 1)
        : e.key === "ArrowRight"
          ? Math.min(n - 1, i + 1)
          : e.key === "Home"
            ? 0
            : e.key === "End"
              ? n - 1
              : undefined;
    if (next !== undefined) {
      e.preventDefault();
      setActive(next);
    } else if (e.key === "Escape" && active !== null) {
      e.preventDefault();
      setActive(null);
    } else if ((e.key === "Enter" || e.key === " ") && active !== null && series[0]) {
      const link = linkOf?.(active, series[0].key);
      if (!link) return;
      e.preventDefault();
      void goto(link);
    }
  }

  /** The readout of one bucket: every series, then the total, or the net change of diverging columns. */
  function readout(i: number) {
    const b = buckets[i];
    if (!b) return null;
    const rows = series.map((s) => ({ key: s.key, label: s.label, swatch: s.swatch, value: b.values[s.key] }));
    const [up, down] = series;
    const net = kind === "diverging" && up && down ? b.values[up.key] - b.values[down.key] : null;
    return {
      label: b.label,
      rows,
      extra:
        net === null
          ? { label: t("statistics.total"), value: formatNumber(sumOf(b)) }
          : { label: t("statistics.net"), value: `${net > 0 ? "+" : ""}${formatNumber(net)}` },
    };
  }
  const current = $derived(active === null ? null : readout(active));
  /** The current bucket in words: what a screen reader says as the arrow keys move the crosshair. */
  const valueText = $derived(
    current
      ? `${current.label}: ${current.rows.map((r) => `${formatNumber(r.value)} ${r.label}`).join(", ")}; ${current.extra.label} ${current.extra.value}`
      : (buckets.at(-1)?.label ?? ""),
  );

  const legend = (key: K) =>
    legendValue === "last" ? (buckets.at(-1)?.values[key] ?? 0) : buckets.reduce((s, b) => s + b.values[key], 0);
</script>

{#snippet legendContent(s: ChartSeries<K>)}
  <span aria-hidden="true" class="size-2.5 rounded-sm {s.swatch}"></span>{s.label}<span class="text-foreground tabular-nums"
    >{formatNumber(legend(s.key))}</span
  >
{/snippet}

<div>
  <div
    role="slider"
    tabindex="0"
    aria-label={summary}
    aria-valuemin={0}
    aria-valuemax={Math.max(0, n - 1)}
    aria-valuenow={active ?? Math.max(0, n - 1)}
    aria-valuetext={valueText}
    aria-describedby="{uid}-keys"
    class={cn("relative rounded-md outline-offset-4", linkOf && "cursor-pointer")}
    bind:clientWidth={width}
    onfocus={() => {
      if (active === null && n > 0) setActive(n - 1);
    }}
    onblur={release}
    onkeydown={onKeydown}
  >
    <svg
      aria-hidden="true"
      width={width || undefined}
      height={H}
      class="block w-full overflow-visible select-none"
      onpointermove={(e) => setActive(indexAt(e))}
      onpointerdown={(e) => setActive(indexAt(e))}
      onpointerleave={(e) => {
        if (e.pointerType === "mouse") release();
      }}
      onclick={(e) => {
        const i = indexAt(e);
        if (i === null || !linkOf) return;
        // Diverging columns: above the baseline is the first series, below it the second.
        const below = kind === "diverging" && e.clientY - e.currentTarget.getBoundingClientRect().top > base;
        const s = series[below ? 1 : 0];
        const link = s && linkOf(i, s.key);
        if (link) void goto(link);
      }}
    >
      {#if width > 0}
        {#each grid as g (g.at)}
          <line
            x1={PAD_LEFT}
            x2={width}
            y1={Math.round(g.at) + 0.5}
            y2={Math.round(g.at) + 0.5}
            class={g.v === 0 ? "stroke-muted-foreground/50" : "stroke-border"}
            shape-rendering="crispEdges"
          />
          <text
            x={PAD_LEFT - 8}
            y={g.at}
            text-anchor="end"
            dominant-baseline="middle"
            class="fill-muted-foreground text-xs tabular-nums">{formatNumber(g.v)}</text
          >
        {/each}

        {#if active !== null && kind !== "area"}
          <rect x={PAD_LEFT + band * active} y={PAD_TOP} width={band} height={plotH} class="fill-muted" />
        {/if}

        {#if kind === "area"}
          {#each stacked as layer (layer.s.key)}
            <path d={areaPath(layer.lo, layer.hi)} class={layer.s.fill} fill-opacity="0.1" />
          {/each}
          {#each stacked as layer (layer.s.key)}
            <path
              d={linePath(layer.hi)}
              class={layer.s.stroke}
              fill="none"
              stroke-width="2"
              stroke-linejoin="round"
              stroke-linecap="round"
            />
          {/each}
          {#if active !== null}
            <line
              x1={cx(active)}
              x2={cx(active)}
              y1={PAD_TOP}
              y2={base}
              class="stroke-muted-foreground/60"
              shape-rendering="crispEdges"
            />
            {#each stacked as layer (layer.s.key)}
              {#if (layer.hi[active] ?? 0) > (layer.lo[active] ?? 0)}
                <circle
                  cx={cx(active)}
                  cy={y(layer.hi[active] ?? 0)}
                  r="4"
                  class="{layer.s.fill} stroke-card"
                  stroke-width="2"
                />
              {/if}
            {/each}
          {/if}
        {:else}
          {#each buckets as b, i (b.key)}
            {#each columns(i) as c (c.key)}
              <path d={c.d} class={c.fill} />
            {/each}
          {/each}
        {/if}
      {/if}
    </svg>

    {#if current && owns && active !== null}
      {@const x = cx(active)}
      {@const left = x < width / 2}
      <div
        aria-hidden="true"
        class={cn(
          "pointer-events-none absolute top-0 z-10 min-w-40 rounded-md border bg-card px-3 py-2 text-sm text-card-foreground shadow-md",
          !left && "-translate-x-full",
        )}
        style:left="{left ? x + 12 : x - 12}px"
      >
        <div class="mb-1 text-xs text-muted-foreground">{current.label}</div>
        <ul class="grid gap-0.5">
          {#each current.rows as r (r.key)}
            <li class="flex items-center gap-2">
              <span class="h-0.5 w-3 rounded-full {r.swatch}"></span>
              <span class="font-medium tabular-nums">{formatNumber(r.value)}</span>
              <span class="text-muted-foreground">{r.label}</span>
            </li>
          {/each}
          <li class="mt-1 flex items-center gap-2 border-t pt-1">
            <span class="w-3"></span>
            <span class="font-medium tabular-nums">{current.extra.value}</span>
            <span class="text-muted-foreground">{current.extra.label}</span>
          </li>
        </ul>
      </div>
    {/if}
    <p id="{uid}-keys" class="sr-only">
      {t(granularity === "day" ? "statistics.chartKeysDays" : "statistics.chartKeysWeeks")}
      {selectHint ?? ""}
    </p>
  </div>
  <div class="mt-1 flex justify-between gap-4 pl-10 text-xs text-muted-foreground">
    <span>{buckets[0]?.label}</span>
    <span>{buckets.at(-1)?.label}</span>
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
          {#each buckets as b, i (b.key)}
            <tr class="border-t">
              <th scope="row" class="py-1 pr-3 font-normal">
                {b.label}
              </th>
              {#each series as s (s.key)}
                {@const link = b.values[s.key] > 0 ? linkOf?.(i, s.key) : undefined}
                <td class="py-1 pr-3 text-right">
                  {#if link}
                    <a href={link} class="hover:underline">{formatNumber(b.values[s.key])}</a>
                  {:else}
                    {formatNumber(b.values[s.key])}
                  {/if}
                </td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </details>
</div>
