import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ChartColumn, CircleCheck, CircleX, GitPullRequest, SearchCheck, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { type BarBucket, BarChart, type BarSeries } from "../../components/bar-chart.tsx";
import { Segmented } from "../../components/filters.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { Tile } from "../../components/tile.tsx";
import { SeverityBadge } from "../../components/ui/badge.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatCalendarDate, formatNumber, formatPercent, formatRelative } from "../../lib/format.ts";
import { STATISTICS_RANGES, type StatisticsRange, statisticsSearch } from "../../lib/search.ts";
import { TREND_SEVERITIES, type TrendSeverity } from "../../lib/trend.ts";
import type { Statistics, StatisticsBucket, StatisticsRanking } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/statistics")({
  validateSearch: statisticsSearch,
  component: StatisticsPage,
});

// Days and weeks are the viewer's own calendar days, so the API needs the browser's zone.
const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

const SEVERITY_FILL: Record<TrendSeverity, { fill: string; swatch: string }> = {
  critical: { fill: "fill-chart-critical", swatch: "bg-chart-critical" },
  high: { fill: "fill-chart-high", swatch: "bg-chart-high" },
  medium: { fill: "fill-chart-medium", swatch: "bg-chart-medium" },
  low: { fill: "fill-chart-low", swatch: "bg-chart-low" },
};

const sumOf = (counts: Partial<Record<string, number>>) =>
  Object.values(counts).reduce<number>((s, n) => s + (n ?? 0), 0);

/**
 * What happened over the last 30, 90 or 365 days: findings found and resolved, how long fixes
 * took, gate results, scans and fix pull requests, and where today's open findings are. The
 * overview answers "what needs attention now"; this page answers "are we getting better".
 */
function StatisticsPage() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const days: StatisticsRange = search.days ?? 30;
  const query = useQuery({
    queryKey: ["statistics", days, timeZone],
    queryFn: () => api<Statistics>(`/statistics?days=${days}&tz=${encodeURIComponent(timeZone)}`),
    placeholderData: keepPreviousData,
  });
  const { data } = query;

  return (
    <>
      <PageHeader
        icon={ChartColumn}
        title={t("statistics.title")}
        description={t("statistics.description")}
        actions={
          <Segmented
            label={t("statistics.range")}
            value={String(days)}
            options={STATISTICS_RANGES.map((d) => ({
              value: String(d),
              label: t("statistics.lastDays", { count: d }),
            }))}
            onChange={(value) =>
              navigate({
                search: { days: Number(value) === 30 ? undefined : (Number(value) as StatisticsRange) },
              })
            }
          />
        }
      />
      {!data ? (
        <Card>
          <QueryStatus query={query} />
        </Card>
      ) : (
        <div className={cn("grid gap-4", query.isFetching && "opacity-70 motion-safe:transition-opacity")}>
          {query.isError ? (
            <Card>
              <QueryStatus query={query} />
            </Card>
          ) : null}
          <KeyFigures data={data} />
          <div className="grid items-start gap-4 @wide:grid-cols-2 @xwide:grid-cols-3">
            <OpenCard data={data} />
            <FoundResolvedCard data={data} />
            <GatesCard data={data} />
            <TimeToFixCard data={data} />
            <RepositoriesCard rows={data.repositories} />
            <PackagesCard rows={data.packages} />
          </div>
          <OldestCard rows={data.oldest} />
        </div>
      )}
    </>
  );
}

function KeyFigures({ data }: { data: Statistics }) {
  const { t } = useTranslation();
  const { totals, range } = data;
  const gateRuns = totals.gates.passed + totals.gates.notes + totals.gates.blocked;
  const scans = totals.scans.succeeded + totals.scans.failed;
  return (
    <div className="grid grid-cols-2 gap-4 @3xl:grid-cols-3 @5xl:grid-cols-5">
      <Tile
        label={t("statistics.found")}
        icon={<SearchCheck aria-hidden="true" className="size-4" />}
        value={totals.opened}
        hint={t("statistics.previousRange", { days: range.days, count: totals.previous.opened })}
        to="/findings"
        search={{ state: "all", sort: "firstSeen", dir: "desc" }}
      />
      <Tile
        label={t("statistics.resolved")}
        icon={<CircleCheck aria-hidden="true" className="size-4" />}
        value={totals.resolved}
        hint={t("statistics.previousRange", { days: range.days, count: totals.previous.resolved })}
        to="/findings"
        search={{ state: "resolved" }}
      />
      <Tile
        label={t("statistics.gatePassRate")}
        icon={<ShieldCheck aria-hidden="true" className="size-4" />}
        value={totals.gates.passed}
        display={gateRuns > 0 ? formatPercent(totals.gates.passed / gateRuns) : "–"}
        hint={t("statistics.gateRuns", { passed: totals.gates.passed, count: gateRuns })}
        to="/gates"
        search={{}}
      />
      <Tile
        label={t("statistics.fixPrsMerged")}
        icon={<GitPullRequest aria-hidden="true" className="size-4" />}
        value={totals.fixPrs.merged}
        hint={t("statistics.fixPrsOpened", { count: totals.fixPrs.opened })}
        to="/fixes"
        search={{ view: "prs", prState: "merged" }}
      />
      <Tile
        label={t("statistics.failedScans")}
        icon={<CircleX aria-hidden="true" className="size-4" />}
        value={totals.scans.failed}
        hint={t("statistics.scansTotal", { count: scans })}
        to="/repositories"
        search={{}}
      />
    </div>
  );
}

/** "12 Oct 2026" for a day, "5 Oct 2026 – 11 Oct 2026" for a week. */
function bucketLabel(b: StatisticsBucket): string {
  return b.start === b.end
    ? formatCalendarDate(b.start)
    : `${formatCalendarDate(b.start)} – ${formatCalendarDate(b.end)}`;
}

function severitySeries(t: (key: never) => string): BarSeries<TrendSeverity>[] {
  return TREND_SEVERITIES.map((s) => ({
    key: s,
    label: t(`severity.${s}` as never),
    ...SEVERITY_FILL[s],
    link: { to: "/findings", search: { severity: s } },
  }));
}

function bySeverity(b: StatisticsBucket, pick: "open" | "opened" | "resolved"): BarBucket<TrendSeverity> {
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

function OpenCard({ data }: { data: Statistics }) {
  const { t } = useTranslation();
  const buckets = data.buckets.map((b) => bySeverity(b, "open"));
  const first = data.buckets[0];
  const last = data.buckets.at(-1);
  return (
    <Card>
      <CardHeader
        title={t("statistics.openTitle")}
        description={t(data.range.granularity === "day" ? "statistics.openPerDay" : "statistics.openPerWeek")}
      />
      <div className="px-5 pb-5">
        <BarChart
          buckets={buckets}
          series={severitySeries(t as never)}
          mode="stacked"
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
  );
}

function FoundResolvedCard({ data }: { data: Statistics }) {
  const { t } = useTranslation();
  const buckets: BarBucket<"found" | "resolved">[] = data.buckets.map((b) => ({
    key: b.start,
    label: bucketLabel(b),
    values: { found: sumOf(b.opened), resolved: sumOf(b.resolved) },
  }));
  return (
    <Card>
      <CardHeader
        title={t("statistics.foundResolvedTitle")}
        description={t(
          data.range.granularity === "day"
            ? "statistics.foundResolvedPerDay"
            : "statistics.foundResolvedPerWeek",
        )}
      />
      <div className="px-5 pb-5">
        <BarChart
          buckets={buckets}
          mode="grouped"
          series={[
            {
              key: "found",
              label: t("statistics.found"),
              fill: "fill-info",
              swatch: "bg-info",
              link: { to: "/findings", search: { state: "all", sort: "firstSeen", dir: "desc" } },
            },
            {
              key: "resolved",
              label: t("statistics.resolved"),
              fill: "fill-success",
              swatch: "bg-success",
              link: { to: "/findings", search: { state: "resolved" } },
            },
          ]}
          summary={t("statistics.foundResolvedSummary", {
            found: data.totals.opened,
            resolved: data.totals.resolved,
          })}
        />
      </div>
    </Card>
  );
}

function GatesCard({ data }: { data: Statistics }) {
  const { t } = useTranslation();
  const buckets: BarBucket<"passed" | "notes" | "blocked">[] = data.buckets.map((b) => ({
    key: b.start,
    label: bucketLabel(b),
    values: b.gates,
  }));
  const g = data.totals.gates;
  return (
    <Card>
      <CardHeader title={t("statistics.gatesTitle")} description={t("statistics.gatesDescription")} />
      <div className="px-5 pb-5">
        <BarChart
          buckets={buckets}
          mode="stacked"
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
  );
}

/** A median in days as words: hours below one day, one decimal below ten days. */
function useDuration() {
  const { t } = useTranslation();
  return (days: number) =>
    days < 1
      ? t("statistics.hours", { count: Math.max(1, Math.round(days * 24)) })
      : t("statistics.days", { count: days < 10 ? Math.round(days * 10) / 10 : Math.round(days) });
}

function TimeToFixCard({ data }: { data: Statistics }) {
  const { t } = useTranslation();
  const duration = useDuration();
  return (
    <Card>
      <CardHeader
        title={t("statistics.timeToFixTitle")}
        description={t("statistics.timeToFixDescription", { days: data.range.days })}
      />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr>
            <th scope="col" className="px-5 py-2 font-normal">
              {t("statistics.severity")}
            </th>
            <th scope="col" className="px-5 py-2 text-right font-normal">
              {t("statistics.median")}
            </th>
            <th scope="col" className="px-5 py-2 text-right font-normal">
              {t("statistics.resolved")}
            </th>
          </tr>
        </thead>
        <tbody>
          {data.timeToFix.map((row) => (
            <tr key={row.severity} className="border-t">
              <th scope="row" className="px-5 py-2.5 font-normal">
                <SeverityBadge severity={row.severity} />
              </th>
              <td className="px-5 py-2.5 text-right tabular-nums">
                {row.medianDays === null ? (
                  <span className="text-muted-foreground">{t("statistics.noneResolved")}</span>
                ) : (
                  duration(row.medianDays)
                )}
              </td>
              <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(row.resolved)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function SeverityCounts({ row }: { row: StatisticsRanking }) {
  const { t } = useTranslation();
  return (
    <span className="inline-flex flex-wrap justify-end gap-x-3 gap-y-0.5 text-sm tabular-nums">
      {TREND_SEVERITIES.filter((s) => row[s] > 0).map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5" title={t(`severity.${s}`)}>
          <span aria-hidden="true" className={`size-2 rounded-full ${SEVERITY_FILL[s].swatch}`} />
          <span className="sr-only">{t(`severity.${s}`)}</span>
          {formatNumber(row[s])}
        </span>
      ))}
    </span>
  );
}

/** Which dot is which severity, once per ranking, so the counts never depend on colour alone. */
function SeverityKey() {
  const { t } = useTranslation();
  return (
    <ul
      aria-hidden="true"
      className="flex flex-wrap gap-x-3 gap-y-1 px-5 pb-3 text-[13px] text-muted-foreground"
    >
      {TREND_SEVERITIES.map((s) => (
        <li key={s} className="inline-flex items-center gap-1.5">
          <span className={`size-2 rounded-full ${SEVERITY_FILL[s].swatch}`} />
          {t(`severity.${s}`)}
        </li>
      ))}
    </ul>
  );
}

function RepositoriesCard({ rows }: { rows: Statistics["repositories"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("statistics.repositoriesTitle")}
        description={t("statistics.rankingDescription")}
      />
      {rows.length > 0 ? <SeverityKey /> : null}
      {rows.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("statistics.noOpenFindings")}</p>
      ) : (
        <ol>
          {rows.map((r) => (
            <li key={r.id} className="flex items-center gap-3 border-t px-5 py-2.5">
              <RepositoryLink id={r.id} name={r.name} className="min-w-0 flex-1 truncate font-medium" />
              <Link
                to="/findings"
                search={{ repositoryId: r.id }}
                className="hover:underline"
                aria-label={t("statistics.openInRepository", { count: r.open, name: r.name })}
              >
                <SeverityCounts row={r} />
              </Link>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

function PackagesCard({ rows }: { rows: Statistics["packages"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("statistics.packagesTitle")} description={t("statistics.rankingDescription")} />
      {rows.length > 0 ? <SeverityKey /> : null}
      {rows.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("statistics.noOpenFindings")}</p>
      ) : (
        <ol>
          {rows.map((p) => (
            <li key={`${p.type}:${p.name}`} className="flex items-center gap-3 border-t px-5 py-2.5">
              <div className="min-w-0 flex-1">
                <Link
                  to="/packages"
                  search={{ q: p.name, vulnerable: "1" }}
                  className="block truncate font-mono text-[14px] hover:underline"
                >
                  {p.name}
                </Link>
                <div className="text-[13px] text-muted-foreground">
                  {p.type} · {t("statistics.inRepositories", { count: p.repositories })}
                </div>
              </div>
              <SeverityCounts row={p} />
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

function OldestCard({ rows }: { rows: Statistics["oldest"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("statistics.oldestTitle")}
        description={t("statistics.oldestDescription")}
        actions={
          <Link
            to="/findings"
            search={{ sort: "firstSeen", dir: "asc" }}
            className="text-sm text-muted-foreground hover:text-foreground hover:underline"
          >
            {t("statistics.allByAge")}
          </Link>
        }
      />
      {rows.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("statistics.noOldest")}</p>
      ) : (
        <ol className="@wide:grid @wide:grid-cols-2">
          {rows.map((o) => (
            <li key={o.id} className="flex items-center gap-3 border-t px-5 py-2.5">
              <SeverityBadge severity={o.severity} />
              <div className="min-w-0 flex-1">
                <Link
                  to="/findings"
                  search={{ id: o.id, severity: o.severity }}
                  className="block truncate font-medium hover:underline"
                >
                  {o.vulnerabilityId}
                </Link>
                <div className="truncate text-[13px] text-muted-foreground">
                  <span className="font-mono">
                    {o.packageName} {o.packageVersion}
                  </span>{" "}
                  · {o.repositoryName}
                </div>
              </div>
              <span className="text-sm whitespace-nowrap text-muted-foreground">
                {t("statistics.openSince", { when: formatRelative(o.firstSeenAt) })}
              </span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
