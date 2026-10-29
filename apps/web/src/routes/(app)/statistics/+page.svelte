<script lang="ts" module>
  import type { TrendSeverity } from "#lib/trend.ts";

  // Days and weeks are the viewer's own calendar days, so the API needs the browser's zone.
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  const SEVERITY_FILL: Record<TrendSeverity, { fill: string; stroke: string; swatch: string }> = {
    critical: { fill: "fill-chart-critical", stroke: "stroke-chart-critical", swatch: "bg-chart-critical" },
    high: { fill: "fill-chart-high", stroke: "stroke-chart-high", swatch: "bg-chart-high" },
    medium: { fill: "fill-chart-medium", stroke: "stroke-chart-medium", swatch: "bg-chart-medium" },
    low: { fill: "fill-chart-low", stroke: "stroke-chart-low", swatch: "bg-chart-low" },
  };

  /** The time charts of the page share one crosshair. */
  const SYNC = "statistics";

  const sumOf = (counts: Partial<Record<string, number>>) =>
    Object.values(counts).reduce<number>((s, n) => s + (n ?? 0), 0);
</script>

<script lang="ts">
  import {
    ChartColumn,
    CircleCheck,
    CircleX,
    GitPullRequest,
    SearchCheck,
    ShieldCheck,
  } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Tile from "#lib/components/Tile.svelte";
  import TimeChart, { type ChartBucket, type ChartSeries } from "#lib/components/TimeChart.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { cn } from "#lib/cn.ts";
  import { formatCalendarDate, formatNumber, formatPercent, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { STATISTICS_RANGES, type StatisticsRange, statisticsSearch } from "#lib/search.ts";
  import { TREND_SEVERITIES } from "#lib/trend.ts";
  import type { Statistics, StatisticsBucket, StatisticsRanking } from "#lib/types.ts";
  import { href } from "#lib/url.ts";

  /**
   * What happened over the last 30, 90 or 365 days: findings found and resolved, how long fixes
   * took, gate results, scans and fix pull requests, and where today's open findings are. The
   * overview answers "what needs attention now"; this page answers "are we getting better".
   */
  const search = $derived(statisticsSearch.parse(Object.fromEntries(page.url.searchParams)));
  const days: StatisticsRange = $derived(search.days ?? 30);
  const query = createQuery(() => ({
    queryKey: ["statistics", days, timeZone],
    queryFn: () => api<Statistics>(`/statistics?days=${days}&tz=${encodeURIComponent(timeZone)}`),
    placeholderData: keepPreviousData,
  }));
  const data = $derived(query.data);

  /** "12 Oct 2026" for a day, "5 Oct 2026 – 11 Oct 2026" for a week. */
  function bucketLabel(b: StatisticsBucket): string {
    return b.start === b.end
      ? formatCalendarDate(b.start)
      : `${formatCalendarDate(b.start)} – ${formatCalendarDate(b.end)}`;
  }

  function severitySeries(): ChartSeries<TrendSeverity>[] {
    return TREND_SEVERITIES.map((s) => ({
      key: s,
      label: t(`severity.${s}`),
      ...SEVERITY_FILL[s],
      link: href("/findings", { severity: s }),
    }));
  }

  function bySeverity(b: StatisticsBucket, pick: "open" | "opened" | "resolved"): ChartBucket<TrendSeverity> {
    const counts = b[pick];
    return {
      key: b.start,
      label: bucketLabel(b),
      values: {
        critical: counts.critical ?? 0,
        high: counts.high ?? 0,
        medium: counts.medium ?? 0,
        low: counts.low ?? 0,
      },
    };
  }

  /** The findings behind one column of "Found and resolved": first seen, or resolved, in that day or week. */
  function foundResolvedLink(b: StatisticsBucket | undefined, key: "found" | "resolved"): string | undefined {
    if (!b) return undefined;
    return key === "found"
      ? href("/findings", { state: "all", firstSeenFrom: b.start, firstSeenTo: b.end, sort: "firstSeen", dir: "desc" })
      : href("/findings", { state: "resolved", resolvedFrom: b.start, resolvedTo: b.end });
  }

  /** The share of gate runs that passed, per bucket; a gap where no gate ran. */
  const passRate = (b: StatisticsBucket) => {
    const runs = b.gates.passed + b.gates.notes + b.gates.blocked;
    return runs > 0 ? b.gates.passed / runs : null;
  };

  /** A median in days as words: hours below one day, one decimal below ten days. */
  function duration(days: number): string {
    return days < 1
      ? t("statistics.hours", { count: Math.max(1, Math.round(days * 24)) })
      : t("statistics.days", { count: days < 10 ? Math.round(days * 10) / 10 : Math.round(days) });
  }
</script>

{#snippet keyFigures(data: Statistics)}
  {@const { totals, range } = data}
  {@const gateRuns = totals.gates.passed + totals.gates.notes + totals.gates.blocked}
  {@const scans = totals.scans.succeeded + totals.scans.failed}
  <div class="grid grid-cols-2 gap-4 @3xl:grid-cols-3 @5xl:grid-cols-5">
    <Tile
      label={t("statistics.found")}
      value={totals.opened}
      hint={t("statistics.previousRange", { days: range.days, count: totals.previous.opened })}
      href={href("/findings", { state: "all", sort: "firstSeen", dir: "desc" })}
      trend={data.buckets.map((b) => sumOf(b.opened))}
    >
      {#snippet icon()}<SearchCheck aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("statistics.resolved")}
      value={totals.resolved}
      hint={t("statistics.previousRange", { days: range.days, count: totals.previous.resolved })}
      href={href("/findings", { state: "resolved" })}
      trend={data.buckets.map((b) => sumOf(b.resolved))}
    >
      {#snippet icon()}<CircleCheck aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("statistics.gatePassRate")}
      value={totals.gates.passed}
      display={gateRuns > 0 ? formatPercent(totals.gates.passed / gateRuns) : "–"}
      hint={t("statistics.gateRuns", { passed: totals.gates.passed, count: gateRuns })}
      href="/gates"
      trend={data.buckets.map(passRate)}
    >
      {#snippet icon()}<ShieldCheck aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("statistics.fixPrsMerged")}
      value={totals.fixPrs.merged}
      hint={t("statistics.fixPrsOpened", { count: totals.fixPrs.opened })}
      href={href("/fixes", { view: "prs", prState: "merged" })}
    >
      {#snippet icon()}<GitPullRequest aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
    <Tile
      label={t("statistics.failedScans")}
      value={totals.scans.failed}
      hint={t("statistics.scansTotal", { count: scans })}
      href="/repositories"
    >
      {#snippet icon()}<CircleX aria-hidden="true" class="size-4" />{/snippet}
    </Tile>
  </div>
{/snippet}

{#snippet openCard(data: Statistics)}
  {@const first = data.buckets[0]}
  {@const last = data.buckets.at(-1)}
  <Card>
    <CardHeader
      title={t("statistics.openTitle")}
      description={t(data.range.granularity === "day" ? "statistics.openPerDay" : "statistics.openPerWeek")}
    />
    <div class="px-5 pb-5">
      <TimeChart
        buckets={data.buckets.map((b) => bySeverity(b, "open"))}
        series={severitySeries()}
        kind="area"
        granularity={data.range.granularity}
        sync={SYNC}
        legendValue="last"
        summary={t("statistics.openSummary", {
          first: first ? formatCalendarDate(first.end) : "",
          firstCount: first ? sumOf(first.open) : 0,
          last: last ? formatCalendarDate(last.end) : "",
          lastCount: last ? sumOf(last.open) : 0,
        })}
      />
    </div>
  </Card>
{/snippet}

{#snippet foundResolvedCard(data: Statistics)}
  {@const buckets: ChartBucket<"found" | "resolved">[] = data.buckets.map((b) => ({
    key: b.start,
    label: bucketLabel(b),
    values: { found: sumOf(b.opened), resolved: sumOf(b.resolved) },
  }))}
  <Card>
    <CardHeader
      title={t("statistics.foundResolvedTitle")}
      description={t(
        data.range.granularity === "day" ? "statistics.foundResolvedPerDay" : "statistics.foundResolvedPerWeek",
      )}
    />
    <div class="px-5 pb-5">
      <TimeChart
        {buckets}
        kind="diverging"
        granularity={data.range.granularity}
        sync={SYNC}
        linkOf={(i, key) => foundResolvedLink(data.buckets[i], key)}
        selectHint={t("statistics.foundResolvedSelect")}
        series={[
          {
            key: "found",
            label: t("statistics.found"),
            fill: "fill-info",
            swatch: "bg-info",
            link: href("/findings", { state: "all", sort: "firstSeen", dir: "desc" }),
          },
          {
            key: "resolved",
            label: t("statistics.resolved"),
            fill: "fill-success",
            swatch: "bg-success",
            link: href("/findings", { state: "resolved" }),
          },
        ]}
        summary={t("statistics.foundResolvedSummary", {
          found: data.totals.opened,
          resolved: data.totals.resolved,
        })}
      />
    </div>
  </Card>
{/snippet}

{#snippet gatesCard(data: Statistics)}
  {@const buckets: ChartBucket<"passed" | "notes" | "blocked">[] = data.buckets.map((b) => ({
    key: b.start,
    label: bucketLabel(b),
    values: b.gates,
  }))}
  {@const g = data.totals.gates}
  <Card>
    <CardHeader title={t("statistics.gatesTitle")} description={t("statistics.gatesDescription")} />
    <div class="px-5 pb-5">
      <TimeChart
        {buckets}
        kind="columns"
        granularity={data.range.granularity}
        sync={SYNC}
        series={[
          { key: "passed", label: t("gates.result.passed"), fill: "fill-success", swatch: "bg-success" },
          {
            key: "notes",
            label: t("gates.result.notes"),
            fill: "fill-chart-medium",
            swatch: "bg-chart-medium",
          },
          {
            key: "blocked",
            label: t("gates.result.blocked"),
            fill: "fill-chart-critical",
            swatch: "bg-chart-critical",
          },
        ]}
        summary={t("statistics.gatesSummary", { passed: g.passed, notes: g.notes, blocked: g.blocked })}
      />
    </div>
  </Card>
{/snippet}

{#snippet timeToFixCard(data: Statistics)}
  {@const longest = Math.max(0, ...data.timeToFix.map((r) => r.medianDays ?? 0))}
  <Card>
    <CardHeader
      title={t("statistics.timeToFixTitle")}
      description={t("statistics.timeToFixDescription", { days: data.range.days })}
    />
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr>
          <th scope="col" class="px-5 py-2 font-normal">
            {t("statistics.severity")}
          </th>
          <th scope="col" class="w-full px-3 py-2 text-right font-normal">
            {t("statistics.median")}
          </th>
          <th scope="col" class="px-5 py-2 text-right font-normal">
            {t("statistics.resolved")}
          </th>
        </tr>
      </thead>
      <tbody>
        {#each data.timeToFix as row (row.severity)}
          <tr class="border-t">
            <th scope="row" class="px-5 py-2.5 font-normal">
              <SeverityBadge severity={row.severity} />
            </th>
            <td class="px-3 py-2.5 text-right tabular-nums">
              {#if row.medianDays === null}
                <span class="text-muted-foreground">{t("statistics.noneResolved")}</span>
              {:else}
                <!-- The median as a bar, the longest one full width, with its value at the end. -->
                <div class="flex items-center gap-3">
                  <div aria-hidden="true" class="flex h-3 min-w-0 flex-1 items-center">
                    <span
                      class="h-full min-w-1 rounded-r-[4px] bg-muted-foreground/45"
                      style:width="{longest > 0 ? (row.medianDays / longest) * 100 : 0}%"
                    ></span>
                  </div>
                  <span class="w-20 shrink-0 whitespace-nowrap">{duration(row.medianDays)}</span>
                </div>
              {/if}
            </td>
            <td class="px-5 py-2.5 text-right tabular-nums">{formatNumber(row.resolved)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </Card>
{/snippet}

{#snippet severityCounts(row: StatisticsRanking)}
  <span class="inline-flex flex-wrap justify-end gap-x-3 gap-y-0.5 text-sm tabular-nums">
    {#each TREND_SEVERITIES.filter((s) => row[s] > 0) as s (s)}
      <span class="inline-flex items-center gap-1.5" title={t(`severity.${s}`)}>
        <span aria-hidden="true" class="size-2 rounded-full {SEVERITY_FILL[s].swatch}"></span>
        <span class="sr-only">{t(`severity.${s}`)}</span>
        {formatNumber(row[s])}
      </span>
    {/each}
  </span>
{/snippet}

<!-- Which dot is which severity, once per ranking, so the counts never depend on colour alone. -->
{#snippet severityKey()}
  <ul aria-hidden="true" class="flex flex-wrap gap-x-3 gap-y-1 px-5 pb-3 text-[13px] text-muted-foreground">
    {#each TREND_SEVERITIES as s (s)}
      <li class="inline-flex items-center gap-1.5">
        <span class="size-2 rounded-full {SEVERITY_FILL[s].swatch}"></span>
        {t(`severity.${s}`)}
      </li>
    {/each}
  </ul>
{/snippet}

<!-- Open findings of one row as a stacked bar, scaled to the row with the most, segments 2px apart. -->
{#snippet severityMeter(row: StatisticsRanking, most: number)}
  {@const total = TREND_SEVERITIES.reduce((n, s) => n + row[s], 0)}
  <div
    aria-hidden="true"
    class="mt-1.5 flex h-1.5 min-w-1 gap-0.5"
    style:width="{most > 0 ? (total / most) * 100 : 0}%"
  >
    {#each TREND_SEVERITIES.filter((s) => row[s] > 0) as s (s)}
      <span class="h-full min-w-0.5 basis-0 first:rounded-l-[2px] last:rounded-r-[2px] {SEVERITY_FILL[s].swatch}" style:flex-grow={row[s]}
      ></span>
    {/each}
  </div>
{/snippet}

{#snippet repositoriesCard(rows: Statistics["repositories"])}
  {@const most = Math.max(0, ...rows.map((r) => TREND_SEVERITIES.reduce((n, s) => n + r[s], 0)))}
  <Card>
    <CardHeader title={t("statistics.repositoriesTitle")} description={t("statistics.rankingDescription")} />
    {#if rows.length > 0}{@render severityKey()}{/if}
    {#if rows.length === 0}
      <p class="px-5 pb-5 text-muted-foreground">{t("statistics.noOpenFindings")}</p>
    {:else}
      <ol>
        {#each rows as r (r.id)}
          <li class="flex items-center gap-3 border-t px-5 py-2.5">
            <div class="min-w-0 flex-1">
              <RepositoryLink id={r.id} name={r.name} class="block truncate font-medium" />
              {@render severityMeter(r, most)}
            </div>
            <a
              href={href("/findings", { repositoryId: r.id })}
              class="hover:underline"
              aria-label={t("statistics.openInRepository", { count: r.open, name: r.name })}
            >
              {@render severityCounts(r)}
            </a>
          </li>
        {/each}
      </ol>
    {/if}
  </Card>
{/snippet}

{#snippet packagesCard(rows: Statistics["packages"])}
  {@const most = Math.max(0, ...rows.map((r) => TREND_SEVERITIES.reduce((n, s) => n + r[s], 0)))}
  <Card>
    <CardHeader title={t("statistics.packagesTitle")} description={t("statistics.rankingDescription")} />
    {#if rows.length > 0}{@render severityKey()}{/if}
    {#if rows.length === 0}
      <p class="px-5 pb-5 text-muted-foreground">{t("statistics.noOpenFindings")}</p>
    {:else}
      <ol>
        {#each rows as p (`${p.type}:${p.name}`)}
          <li class="flex items-center gap-3 border-t px-5 py-2.5">
            <div class="min-w-0 flex-1">
              <a
                href={href("/packages", { q: p.name, vulnerable: "1" })}
                class="block truncate font-mono text-[14px] hover:underline"
              >
                {p.name}
              </a>
              <div class="text-[13px] text-muted-foreground">
                {p.type} · {t("statistics.inRepositories", { count: p.repositories })}
              </div>
              {@render severityMeter(p, most)}
            </div>
            {@render severityCounts(p)}
          </li>
        {/each}
      </ol>
    {/if}
  </Card>
{/snippet}

{#snippet oldestCard(rows: Statistics["oldest"])}
  <Card>
    <CardHeader title={t("statistics.oldestTitle")} description={t("statistics.oldestDescription")}>
      {#snippet actions()}
        <a
          href={href("/findings", { sort: "firstSeen", dir: "asc" })}
          class="text-sm text-muted-foreground hover:text-foreground hover:underline"
        >
          {t("statistics.allByAge")}
        </a>
      {/snippet}
    </CardHeader>
    {#if rows.length === 0}
      <p class="px-5 pb-5 text-muted-foreground">{t("statistics.noOldest")}</p>
    {:else}
      <ol class="@wide:grid @wide:grid-cols-2">
        {#each rows as o (o.id)}
          <li class="flex items-center gap-3 border-t px-5 py-2.5">
            <SeverityBadge severity={o.severity} />
            <div class="min-w-0 flex-1">
              <a
                href={href("/findings", { id: o.id, severity: o.severity })}
                class="block truncate font-medium hover:underline"
              >
                {o.vulnerabilityId}
              </a>
              <div class="truncate text-[13px] text-muted-foreground">
                <span class="font-mono">{o.packageName} {o.packageVersion}</span> · {o.repositoryName}
              </div>
            </div>
            <span class="text-sm whitespace-nowrap text-muted-foreground">
              {t("statistics.openSince", { when: formatRelative(o.firstSeenAt) })}
            </span>
          </li>
        {/each}
      </ol>
    {/if}
  </Card>
{/snippet}

<PageHeader icon={ChartColumn} title={t("statistics.title")} description={t("statistics.description")}>
  {#snippet actions()}
    <Segmented
      label={t("statistics.range")}
      value={String(days)}
      options={STATISTICS_RANGES.map((d) => ({
        value: String(d),
        label: t("statistics.lastDays", { count: d }),
      }))}
      onChange={(value) =>
        void goto(
          href(page.url.pathname, {
            days: Number(value) === 30 ? undefined : (Number(value) as StatisticsRange),
          }),
          { reset: false },
        )}
    />
  {/snippet}
</PageHeader>
{#if !data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  <div class={cn("grid gap-4", query.isFetching && "opacity-70 motion-safe:transition-opacity")}>
    {#if query.isError}
      <Card>
        <QueryStatus {query} />
      </Card>
    {/if}
    {@render keyFigures(data)}
    <div class="grid items-start gap-4 @wide:grid-cols-2 @xwide:grid-cols-3">
      {@render openCard(data)}
      {@render foundResolvedCard(data)}
      {@render gatesCard(data)}
      {@render timeToFixCard(data)}
      {@render repositoriesCard(data.repositories)}
      {@render packagesCard(data.packages)}
    </div>
    {@render oldestCard(data.oldest)}
  </div>
{/if}
