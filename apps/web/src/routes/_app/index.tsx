import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, type LinkProps } from "@tanstack/react-router";
import {
  ArrowRight,
  Database,
  Flame,
  GitBranch,
  LayoutGrid,
  Plus,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Wrench,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { TrendChart } from "../../components/trend-chart.tsx";
import { ScanStateBadge, SeverityBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { useScanErrorText } from "../../lib/scan-error.ts";
import { type TrendDay, trendDays } from "../../lib/trend.ts";
import type { Overview } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/")({ component: OverviewPage });

// The trend is cut into the viewer's own calendar days, so the API needs the browser's zone.
const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const overviewQuery = {
  queryKey: ["overview", timeZone],
  queryFn: () => api<Overview>(`/overview?tz=${encodeURIComponent(timeZone)}`),
};

function OverviewPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const queryClient = useQueryClient();
  const query = useQuery({ ...overviewQuery, refetchInterval: 30_000 });
  const { data } = query;
  const [queued, setQueued] = useState<number | null>(null);

  const scanAll = useMutation({
    mutationFn: () => api<{ queued: number }>("/repositories/scan-all", { method: "POST" }),
    onSuccess: async (result) => {
      setQueued(result.queued);
      await queryClient.invalidateQueries();
    },
  });
  const canScan = me.role !== "viewer" && (data?.repositories.total ?? 0) > 0;

  return (
    <>
      <PageHeader
        icon={LayoutGrid}
        title={t("overview.title")}
        description={t("overview.description")}
        actions={
          <>
            {scanAll.isError ? (
              <span role="alert" className="text-sm text-destructive-text">
                {t("errors.actionFailed")}
              </span>
            ) : queued !== null ? (
              <span role="status" className="text-sm text-muted-foreground">
                {t("overview.scansQueued", { count: queued })}
              </span>
            ) : query.dataUpdatedAt ? (
              <span className="text-sm text-muted-foreground">
                {t("overview.updated", { when: formatRelative(new Date(query.dataUpdatedAt)) })}
              </span>
            ) : null}
            <Button
              variant="outline"
              className="size-10 px-0"
              aria-label={t("overview.refresh")}
              title={t("overview.refresh")}
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              <RefreshCw
                aria-hidden="true"
                className={cn("size-4", query.isFetching && "motion-safe:animate-spin")}
              />
            </Button>
            {canScan ? (
              <Button disabled={scanAll.isPending} onClick={() => scanAll.mutate()}>
                <ScanSearch aria-hidden="true" className="size-4" />
                {t("overview.scanAll")}
              </Button>
            ) : null}
          </>
        }
      />
      {!data ? (
        <Card>
          <QueryStatus query={query} />
        </Card>
      ) : data.repositories.total === 0 ? (
        <EmptyState />
      ) : (
        <>
          {query.isError ? (
            <Card className="mb-4">
              <QueryStatus query={query} />
            </Card>
          ) : null}
          <Dashboard data={data} />
        </>
      )}
    </>
  );
}

function Dashboard({ data }: { data: Overview }) {
  const { t } = useTranslation();
  const days = trendDays(data.trend);
  const critical = data.open.critical ?? 0;
  return (
    <div className="grid gap-4">
      {critical > 0 ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-card px-4 py-3 shadow-xs">
          <TriangleAlert aria-hidden="true" className="size-5 flex-none text-warning-text" />
          <div className="min-w-0 flex-[1_1_20rem]">
            <div className="font-semibold">{t("overview.criticalBanner", { count: critical })}</div>
            <div className="text-sm text-muted-foreground">
              {t("overview.criticalBannerHint", {
                repos: data.repositories.blocked,
                exploited: data.knownExploitedOpen,
              })}
            </div>
          </div>
          <Link
            to="/findings"
            search={{ severity: "critical" }}
            className="ml-auto inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
          >
            {t("overview.viewFindings")}
          </Link>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-4 @3xl:grid-cols-3 @xwide:grid-cols-6">
        <Tile
          label={t("overview.criticalOpen")}
          icon={<Flame aria-hidden="true" className="size-4 text-destructive-text" />}
          value={critical}
          delta={<WeekDelta days={days} severity="critical" />}
          to="/findings"
          search={{ severity: "critical" }}
        />
        <Tile
          label={t("overview.highOpen")}
          icon={<TriangleAlert aria-hidden="true" className="size-4" />}
          value={data.open.high ?? 0}
          delta={<WeekDelta days={days} severity="high" />}
          to="/findings"
          search={{ severity: "high" }}
        />
        <Tile
          label={t("overview.knownExploited")}
          icon={<ShieldAlert aria-hidden="true" className="size-4" />}
          value={data.knownExploitedOpen}
          hint={t("overview.knownExploitedHint")}
          to="/findings"
          search={{ kev: "1" }}
        />
        <Tile
          label={t("overview.fixable")}
          icon={<Wrench aria-hidden="true" className="size-4" />}
          value={data.fixableOpen}
          hint={t("overview.fixableHint")}
          to="/findings"
          search={{ fixable: "1" }}
        />
        <Tile
          label={t("overview.blockedRepos")}
          icon={<GitBranch aria-hidden="true" className="size-4" />}
          value={data.repositories.blocked}
          hint={`${t("overview.reposTotal", { count: data.repositories.total })} · ${t("overview.neverScanned", { count: data.repositories.never_scanned })}`}
          to="/repositories"
          search={{ status: "blocked" }}
        />
        <Tile
          label={t("overview.accepted")}
          icon={<ShieldCheck aria-hidden="true" className="size-4" />}
          value={data.states.accepted ?? 0}
          hint={t("overview.acceptedHint")}
          to="/findings"
          search={{ state: "accepted" }}
        />
      </div>

      <div className="grid gap-4 @wide:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <FixFirst items={data.fixFirst} />
        <RecentScans items={data.recentScans} />
        <TrendCard days={days} />
        <VulnerabilityData data={data.vulnerabilityData} />
      </div>
    </div>
  );
}

/** Change of open findings of one severity against seven days ago, from the trend. */
function WeekDelta({ days, severity }: { days: TrendDay[]; severity: "critical" | "high" }) {
  const { t } = useTranslation();
  const today = days[days.length - 1];
  const weekAgo = days[days.length - 8];
  if (!today || !weekAgo) return null;
  const diff = today[severity] - weekAgo[severity];
  if (diff === 0) return <>{t("overview.deltaSame")}</>;
  return (
    <>
      {diff < 0 ? t("overview.deltaDown", { count: Math.abs(diff) }) : t("overview.deltaUp", { count: diff })}
    </>
  );
}

function Tile({
  label,
  icon,
  value,
  delta,
  hint,
  to,
  search,
}: {
  label: string;
  icon: ReactNode;
  value: number;
  delta?: ReactNode;
  hint?: string;
  to: "/findings" | "/repositories";
  search: LinkProps["search"];
}) {
  return (
    <Link
      to={to}
      search={search}
      className="block rounded-lg border bg-card px-4 py-4 shadow-xs transition-colors hover:border-primary/40"
    >
      <div className="flex items-center justify-between gap-2 text-muted-foreground">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-1.5 text-3xl font-semibold tracking-tight">{formatNumber(value)}</div>
      {delta ? <div className="mt-0.5 text-sm text-muted-foreground">{delta}</div> : null}
      {hint ? <div className="mt-0.5 text-sm text-muted-foreground">{hint}</div> : null}
    </Link>
  );
}

function FixFirst({ items }: { items: Overview["fixFirst"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("overview.fixFirst")}
        description={t("overview.fixFirstDescription")}
        actions={
          <Link
            to="/findings"
            className="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline"
          >
            {t("overview.allFindings")}
            <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        }
      />
      {items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("overview.nothingToFix")}</p>
      ) : (
        <table className="w-full text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("findings.columnFinding")}</th>
              <th className="px-3 py-2.5 font-medium">{t("findings.columnRepository")}</th>
              <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">
                {t("overview.columnSource")}
              </th>
              <th className="px-3 py-2.5 font-medium">{t("findings.severityFilter")}</th>
              <th className="hidden px-5 py-2.5 font-medium @xl:table-cell">{t("findings.columnFixedIn")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f) => (
              <tr key={f.id} className="border-b last:border-0">
                <td className="px-5 py-2.5">
                  <Link
                    to="/findings"
                    search={{ id: f.id, state: "all" }}
                    className="font-medium hover:underline"
                  >
                    {f.vulnerabilityId}
                  </Link>
                  <div className="font-mono text-sm text-muted-foreground">
                    {f.packageName} {f.packageVersion}
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <RepositoryLink id={f.repositoryId} name={f.repositoryName} />
                </td>
                <td className="hidden px-3 py-2.5 text-sm text-muted-foreground @wide:table-cell">
                  {t("overview.sourceDependency", { type: f.packageType })}
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    <SeverityBadge severity={f.severity} />
                    {f.knownExploited ? (
                      <span className="text-sm text-destructive-text">{t("findings.kev")}</span>
                    ) : null}
                  </div>
                </td>
                <td className="hidden px-5 py-2.5 font-mono text-sm @xl:table-cell">
                  {f.fixedIn?.length ? (
                    f.fixedIn.join(", ")
                  ) : (
                    <span className="font-sans text-muted-foreground">{t("findings.noFix")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function RecentScans({ items }: { items: Overview["recentScans"] }) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  return (
    <Card>
      <CardHeader title={t("overview.recentScans")} description={t("overview.recentScansDescription")} />
      {items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("overview.noScans")}</p>
      ) : (
        <ul>
          {items.map((s) => {
            const at = s.finishedAt ?? s.createdAt;
            return (
              <li key={s.id} className="flex items-start gap-3 border-b px-5 py-3 last:border-0">
                <div className="min-w-0 flex-1">
                  <RepositoryLink
                    id={s.repositoryId}
                    name={s.repositoryName}
                    className="block truncate font-medium"
                  />
                  {s.state === "succeeded" ? (
                    <Link
                      to="/findings"
                      search={{ scanId: s.id, state: "all" }}
                      className="text-sm text-muted-foreground hover:underline"
                    >
                      {t("overview.scanSummary", {
                        added: s.newFindings ?? 0,
                        resolved: s.resolvedFindings ?? 0,
                      })}
                    </Link>
                  ) : s.error ? (
                    <div className="text-sm text-destructive-text">{scanErrorText(s.error)}</div>
                  ) : null}
                </div>
                <div className="flex flex-none flex-col items-end gap-1">
                  <ScanStateBadge state={s.state} />
                  <time dateTime={at} title={formatDateTime(at)} className="text-sm text-muted-foreground">
                    {formatRelative(at)}
                  </time>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

function TrendCard({ days }: { days: TrendDay[] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
      <div className="px-5 pt-4 pb-4">
        <TrendChart days={days} />
      </div>
    </Card>
  );
}

function VulnerabilityData({ data }: { data: Overview["vulnerabilityData"] }) {
  const { t } = useTranslation();
  const versions = Object.entries(data?.scannerVersions ?? {});
  return (
    <Card>
      <CardHeader title={t("overview.dataTitle")} description={t("overview.dataDescription")} />
      {data ? (
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 px-5 py-4 text-sm">
          <dt className="text-muted-foreground">{t("overview.dataAsOf")}</dt>
          <dd>
            {data.builtAt ? (
              <time dateTime={data.builtAt} title={formatDateTime(data.builtAt)}>
                {formatRelative(data.builtAt)}
              </time>
            ) : (
              t("overview.dataUnknown")
            )}
          </dd>
          <dt className="text-muted-foreground">{t("overview.dataScanners")}</dt>
          <dd className="font-mono">
            {versions.length
              ? versions.map(([name, v]) => `${name} ${v}`).join(", ")
              : t("overview.dataUnknown")}
          </dd>
          <dt className="text-muted-foreground">{t("overview.dataLastScan")}</dt>
          <dd>
            {data.scannedAt ? (
              <time dateTime={data.scannedAt} title={formatDateTime(data.scannedAt)}>
                {formatRelative(data.scannedAt)}
              </time>
            ) : (
              t("overview.dataUnknown")
            )}
          </dd>
        </dl>
      ) : (
        <p className="flex items-center gap-2 px-5 py-6 text-muted-foreground">
          <Database aria-hidden="true" className="size-4" />
          {t("overview.dataNone")}
        </p>
      )}
    </Card>
  );
}

function EmptyState() {
  const { t } = useTranslation();
  return (
    <Card className="max-w-2xl px-6 py-6">
      <h2 className="text-lg font-semibold">{t("overview.emptyTitle")}</h2>
      <p className="mt-1 text-muted-foreground">{t("overview.emptyDescription")}</p>
      <Link
        to="/repositories"
        search={{ add: "1" }}
        className="mt-5 inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
      >
        <Plus aria-hidden="true" className="size-4" />
        {t("repositories.add")}
      </Link>
    </Card>
  );
}
