import { levelOfFreshness, vulnDbFreshness } from "@garnetops/core/system-status";
import type { Messages } from "@garnetops/i18n";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  ArrowRight,
  ArrowUpCircle,
  CircleAlert,
  Clock,
  Database,
  Flame,
  FolderMinus,
  FolderPlus,
  GitBranch,
  LayoutGrid,
  type LucideIcon,
  Moon,
  Plus,
  RefreshCw,
  RotateCcw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Wrench,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { GateBadge } from "../../components/gate-badge.tsx";
import { isAdmin } from "../../components/nav.ts";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { StatusBadge } from "../../components/system-status.tsx";
import { Tile } from "../../components/tile.tsx";
import { TrendChart } from "../../components/trend-chart.tsx";
import { Banner } from "../../components/ui/alert.tsx";
import { ScanStateBadge, SeverityBadge, SeverityDot } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { rowClick } from "../../lib/row-link.ts";
import { useScanErrorText } from "../../lib/scan-error.ts";
import { type TrendDay, trendDays } from "../../lib/trend.ts";
import type { ActivityItem, GateRunRow, Overview, Page } from "../../lib/types.ts";

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
          <Dashboard data={data} admin={isAdmin(me)} />
        </>
      )}
    </>
  );
}

function Dashboard({ data, admin }: { data: Overview; admin: boolean }) {
  const { t } = useTranslation();
  const days = trendDays(data.trend);
  const critical = data.open.critical ?? 0;
  const fixHint = (severity: "critical" | "high") =>
    t("overview.fixAvailable", { count: data.fixableBySeverity[severity] ?? 0 });
  return (
    <div className="grid gap-4">
      {critical > 0 ? (
        <Banner
          title={t("overview.criticalBanner", { count: critical })}
          action={
            <Link
              to="/findings"
              search={{ severity: "critical" }}
              className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
            >
              {t("overview.viewFindings")}
            </Link>
          }
        >
          {t("overview.criticalBannerHint", {
            repos: data.repositories.blocked,
            exploited: data.knownExploitedOpen,
          })}
        </Banner>
      ) : null}

      <div className="grid grid-cols-2 gap-4 @3xl:grid-cols-3 @xwide:grid-cols-6">
        <Tile
          label={t("overview.criticalOpen")}
          icon={<Flame aria-hidden="true" className="size-4 text-destructive-text" />}
          value={critical}
          delta={<WeekDelta days={days} severity="critical" />}
          hint={fixHint("critical")}
          to="/findings"
          search={{ severity: "critical" }}
        />
        <Tile
          label={t("overview.highOpen")}
          icon={<TriangleAlert aria-hidden="true" className="size-4" />}
          value={data.open.high ?? 0}
          delta={<WeekDelta days={days} severity="high" />}
          hint={fixHint("high")}
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

      {/* Mockup .ov-grid: two columns at the base step, four at xwide. */}
      <div
        className={cn(
          "grid gap-4 @wide:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]",
          "@wide:[grid-template-areas:'attn_act'_'gates_scans'_'trend_data']",
          "@xwide:grid-cols-4 @xwide:[grid-template-areas:'attn_attn_gates_act'_'trend_trend_data_scans']",
        )}
      >
        <div className="min-w-0 @wide:[grid-area:attn]">
          <FixFirst items={data.fixFirst} />
        </div>
        <div className="min-w-0 @wide:[grid-area:act]">
          <Activity items={data.activity} />
        </div>
        <div className="min-w-0 @wide:[grid-area:gates]">
          <RecentGateRuns />
        </div>
        <div className="min-w-0 @wide:[grid-area:scans]">
          <RecentScans items={data.recentScans} />
        </div>
        <div className="min-w-0 @wide:[grid-area:trend]">
          <TrendCard days={days} />
        </div>
        <div className="min-w-0 @wide:[grid-area:data]">
          <VulnerabilityData
            data={data.vulnerabilityData}
            sources={data.vulnerabilitySources}
            admin={admin}
          />
        </div>
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

function FixFirst({ items }: { items: Overview["fixFirst"] }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <Card className="h-full">
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
        <p className="px-5 pb-6 text-muted-foreground">{t("overview.nothingToFix")}</p>
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
              <tr
                key={f.id}
                className="row-link border-b last:border-0"
                onClick={rowClick(
                  () => void navigate({ to: "/findings", search: { id: f.id, state: "all" } }),
                )}
              >
                <td className="px-5 py-2.5">
                  <div className="flex items-start gap-2.5">
                    <SeverityDot severity={f.severity} className="mt-2" />
                    <div className="min-w-0">
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
                    </div>
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

/** The last gate results (mockup "Recent gate runs"); only "Passed" is green. */
function RecentGateRuns() {
  const { t } = useTranslation();
  const runs = useQuery({
    queryKey: ["gate-runs", "recent"],
    queryFn: () => api<Page<GateRunRow>>("/gates/runs?pageSize=25"),
  });
  const items = runs.data?.items.slice(0, 5) ?? [];
  return (
    <Card className="h-full">
      <CardHeader
        title={t("gates.recentTitle")}
        description={t("gates.recentDescription")}
        actions={
          <Link
            to="/gates"
            className="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline"
          >
            {t("gates.allRuns")}
            <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        }
      />
      <QueryStatus query={runs} />
      {runs.data && items.length === 0 ? (
        <p className="px-5 pb-6 text-muted-foreground">{t("gates.runsEmpty")}</p>
      ) : null}
      <ul className="px-5 pb-3">
        {items.map((run) => (
          <li key={run.id} className="flex items-center gap-2.5 border-t py-2.5 first:border-t-0">
            <GateBadge result={run.result} />
            <span className="min-w-0 flex-1 truncate">
              <RepositoryLink id={run.repositoryId} name={run.repositoryName} />{" "}
              <span className="text-muted-foreground">· {t(`gates.trigger.${run.trigger}`)}</span>
            </span>
            <time
              dateTime={run.createdAt}
              title={formatDateTime(run.createdAt)}
              className="dash-time flex-none text-[13px] whitespace-nowrap text-muted-foreground"
            >
              {formatRelative(run.createdAt)}
            </time>
          </li>
        ))}
      </ul>
    </Card>
  );
}

const ACTIVITY_ICON: Record<string, LucideIcon> = {
  "repository.created": FolderPlus,
  "repository.deleted": FolderMinus,
  "finding.accepted": ShieldCheck,
  "finding.reopened": RotateCcw,
  "organization.scan_schedule_changed": Clock,
  "update.succeeded": ArrowUpCircle,
  "update.failed": CircleAlert,
  "schedule.run": Moon,
};

/** Recent organisation events (mockup "Activity"): icon chip, one line, when. */
function Activity({ items }: { items: ActivityItem[] }) {
  const { t } = useTranslation();
  return (
    <Card className="h-full">
      <CardHeader title={t("overview.activityTitle")} description={t("overview.activityDescription")} />
      {items.length === 0 ? (
        <p className="px-5 pb-6 text-muted-foreground">{t("overview.activityEmpty")}</p>
      ) : (
        <ul className="px-5 pb-3">
          {items.map((item) => {
            const Icon = ACTIVITY_ICON[item.kind] ?? Clock;
            const key = item.kind.replaceAll(".", "_") as keyof Messages["overview"]["activity"];
            return (
              <li
                key={`${item.kind}-${item.at}`}
                className="flex items-center gap-2.5 border-t py-2.5 first:border-t-0"
              >
                <span className="grid size-7 flex-none place-items-center rounded-[7px] bg-muted">
                  <Icon aria-hidden="true" className="size-3.5" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate">
                    {t(`overview.activity.${key}`, {
                      subject: item.subject ?? "",
                      count: item.count ?? 0,
                    })}
                  </div>
                  {item.actorName ? (
                    <div className="truncate text-[13px] text-muted-foreground">
                      {t("overview.activityBy", { name: item.actorName })}
                    </div>
                  ) : null}
                </div>
                <time
                  dateTime={item.at}
                  title={formatDateTime(item.at)}
                  className="dash-time flex-none text-[13px] whitespace-nowrap text-muted-foreground"
                >
                  {formatRelative(item.at)}
                </time>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

function RecentScans({ items }: { items: Overview["recentScans"] }) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  return (
    <Card className="h-full">
      <CardHeader title={t("overview.recentScans")} description={t("overview.recentScansDescription")} />
      {items.length === 0 ? (
        <p className="px-5 pb-6 text-muted-foreground">{t("overview.noScans")}</p>
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
                  <time
                    dateTime={at}
                    title={formatDateTime(at)}
                    className="dash-time text-sm text-muted-foreground"
                  >
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
    <Card className="h-full">
      <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
      <div className="px-5 pb-4">
        <TrendChart days={days} />
      </div>
    </Card>
  );
}

/** Display names of grype's advisory namespaces. */
const SOURCE_NAMES: Record<string, string> = {
  nvd: "NVD",
  github: "GitHub Advisories",
  debian: "Debian",
  ubuntu: "Ubuntu",
  alpine: "Alpine",
  redhat: "Red Hat",
  rhel: "Red Hat",
  amazon: "Amazon Linux",
  oracle: "Oracle Linux",
  sles: "SUSE",
  wolfi: "Wolfi",
  chainguard: "Chainguard",
  mariner: "Azure Linux",
};

function VulnerabilityData({
  data,
  sources,
  admin,
}: {
  data: Overview["vulnerabilityData"];
  sources: string[];
  admin: boolean;
}) {
  const { t } = useTranslation();
  const versions = Object.entries(data?.scannerVersions ?? {});
  // The same limits as the System status page (3 and 7 days); every member sees the age, admins can follow the link.
  const freshness = data?.builtAt ? vulnDbFreshness(data.builtAt, new Date()) : null;
  return (
    <Card className="h-full">
      <CardHeader
        title={t("overview.dataTitle")}
        description={t("overview.dataDescription")}
        actions={
          <div className="flex flex-wrap items-center justify-end gap-2">
            {freshness && freshness !== "unknown" ? (
              <StatusBadge level={levelOfFreshness(freshness)}>
                <span data-testid="overview-data-freshness">
                  {t(`systemStatus.vulnDb.state.${freshness}`)}
                </span>
              </StatusBadge>
            ) : null}
            {admin ? (
              <Link
                to="/system"
                data-testid="overview-system-status-link"
                className="text-sm text-primary-text underline-offset-4 hover:underline"
              >
                {t("overview.dataStatusLink")}
              </Link>
            ) : null}
          </div>
        }
      />
      {data ? (
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 px-5 pb-4 text-sm">
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
          <dt className="text-muted-foreground">{t("overview.dataSources")}</dt>
          <dd>
            {sources.length
              ? sources.map((s) => SOURCE_NAMES[s] ?? s).join(", ")
              : t("overview.dataSourcesNone")}
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
        <p className="flex items-center gap-2 px-5 pb-6 text-muted-foreground">
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
