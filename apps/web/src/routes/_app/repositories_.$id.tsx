import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Flame, GitBranch, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { ExportMenu } from "../../components/export-menu.tsx";
import { GradeSummary } from "../../components/grade-badge.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Tile } from "../../components/tile.tsx";
import { TrendChart } from "../../components/trend-chart.tsx";
import { ScanStateBadge, SeverityBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { WriteAccessCard } from "../../components/write-access-card.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { calendarDaysBetween } from "../../lib/dates.ts";
import { forgeOf } from "../../lib/forge.ts";
import { formatDate, formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { useScanErrorText } from "../../lib/scan-error.ts";
import { type RepositoryDetailSearch, repositoryDetailSearch, toQuery } from "../../lib/search.ts";
import { toast } from "../../lib/toast.ts";
import { trendDays } from "../../lib/trend.ts";
import type { Overview, Page, PatchRow, RepositoryDetail, ScanRow, Severity } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/repositories_/$id")({
  validateSearch: repositoryDetailSearch,
  component: RepositoryPage,
});

const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/**
 * One repository: what is open now, how that changed over 30 days, every scan, and the
 * patch history (which finding was fixed when, and which version the repository has now).
 */
function RepositoryPage() {
  const { t } = useTranslation();
  const { id } = Route.useParams();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();

  const repo = useQuery({
    queryKey: ["repository", id],
    queryFn: () => api<RepositoryDetail>(`/repositories/${id}`),
    refetchInterval: (q) =>
      (q.state.data?.lastScan && ["queued", "running"].includes(q.state.data.lastScan.state)) ||
      // The worker is checking a new write token (ADR 0014).
      q.state.data?.writeAccess.access?.status === "unchecked"
        ? 4000
        : false,
  });
  const scan = useMutation({
    mutationFn: () => api(`/repositories/${id}/scans`, { method: "POST" }),
    onSuccess: () => {
      toast.success(t("toast.scanQueued", { repository: repo.data?.name ?? "" }));
      return queryClient.invalidateQueries();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  });
  const setSearch = (patch: Partial<RepositoryDetailSearch>) =>
    navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  const data = repo.data;
  const busy = data?.lastScan ? ["queued", "running"].includes(data.lastScan.state) : false;

  return (
    <>
      <Link
        to="/repositories"
        className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
      >
        <ArrowLeft aria-hidden="true" className="size-4" />
        {t("repository.back")}
      </Link>
      <PageHeader
        icon={GitBranch}
        title={data?.name ?? t("common.loading")}
        description={data?.url ?? ""}
        meta={data ? <GradeSummary row={data} id={id} /> : null}
        actions={
          data ? (
            <>
              <ExportMenu filters={{ repositoryId: id, state: "all" }} />
              {me.role !== "viewer" ? (
                <Button disabled={busy || scan.isPending} onClick={() => scan.mutate()}>
                  <RefreshCw
                    aria-hidden="true"
                    className={cn("size-4", busy && "motion-safe:animate-spin")}
                  />
                  {busy && data.lastScan ? t(`scanState.${data.lastScan.state}`) : t("repositories.scanNow")}
                </Button>
              ) : null}
            </>
          ) : null
        }
      />
      {!data ? (
        <Card>
          <QueryStatus query={repo} />
        </Card>
      ) : (
        <div className="grid gap-4">
          {scan.isError ? (
            <p role="alert" className="text-sm text-destructive-text">
              {t("errors.actionFailed")}
            </p>
          ) : null}
          <div className="grid gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <Facts repo={data} />
            <div className="grid grid-cols-2 gap-4 @3xl:grid-cols-4">
              {SEVERITIES.map((severity) => (
                <Tile
                  key={severity}
                  label={t("repository.openOf", { severity: t(`severity.${severity}`) })}
                  icon={
                    severity === "critical" ? (
                      <Flame aria-hidden="true" className="size-4 text-destructive-text" />
                    ) : null
                  }
                  value={data.open[severity] ?? 0}
                  to="/findings"
                  search={{ repositoryId: id, severity }}
                />
              ))}
            </div>
          </div>
          <WriteAccessCard repo={data} me={me} />
          <div className="grid gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <RepositoryTrend id={id} />
            <ScanHistory
              id={id}
              cursor={search.scans}
              pageSize={search.scansPageSize}
              onCursor={(scans) => setSearch({ scans })}
              onPageSize={(scansPageSize) => setSearch({ scansPageSize, scans: undefined })}
            />
          </div>
          <PatchHistory
            id={id}
            cursor={search.patches}
            pageSize={search.patchesPageSize}
            onCursor={(patches) => setSearch({ patches })}
            onPageSize={(patchesPageSize) => setSearch({ patchesPageSize, patches: undefined })}
          />
        </div>
      )}
    </>
  );
}

const SOURCE_ACCESS = {
  none: "repositories.sourcePublic",
  "https-token": "repositories.sourceToken",
  "ssh-deploy-key": "repositories.sourceDeployKey",
} as const;

function Facts({ repo }: { repo: RepositoryDetail }) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  return (
    <Card>
      <CardHeader
        title={t("repository.facts")}
        actions={
          <Link
            to="/findings"
            search={{ repositoryId: repo.id }}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline"
          >
            {t("overview.allFindings")}
            <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        }
      />
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 px-5 py-4">
        <dt className="text-muted-foreground">{t("repositories.columnSource")}</dt>
        <dd>
          {forgeOf(repo.url)} · {t(SOURCE_ACCESS[repo.authKind])}
        </dd>
        <dt className="text-muted-foreground">{t("repositories.columnBranch")}</dt>
        <dd className="font-mono">{repo.branch ?? t("repositories.defaultBranch")}</dd>
        <dt className="text-muted-foreground">{t("repositories.columnLastScan")}</dt>
        <dd>
          <span className="inline-flex flex-wrap items-center gap-2">
            <ScanStateBadge state={repo.lastScan?.state ?? null} />
            {repo.lastScan?.finishedAt ? (
              <time dateTime={repo.lastScan.finishedAt} title={formatDateTime(repo.lastScan.finishedAt)}>
                {formatRelative(repo.lastScan.finishedAt)}
              </time>
            ) : null}
          </span>
          {repo.lastScan?.state === "failed" && repo.lastScan.error ? (
            <div className="mt-1 text-sm text-destructive-text">{scanErrorText(repo.lastScan.error)}</div>
          ) : null}
        </dd>
        <dt className="text-muted-foreground">{t("repository.resolvedTotal")}</dt>
        <dd>{formatNumber(repo.states.resolved ?? 0)}</dd>
        <dt className="text-muted-foreground">{t("overview.accepted")}</dt>
        <dd>{formatNumber(repo.states.accepted ?? 0)}</dd>
        <dt className="text-muted-foreground">{t("repository.added")}</dt>
        <dd>{formatDate(repo.createdAt)}</dd>
      </dl>
    </Card>
  );
}

function RepositoryTrend({ id }: { id: string }) {
  const { t } = useTranslation();
  const trend = useQuery({
    queryKey: ["repository", id, "trend", timeZone],
    queryFn: () => api<Overview["trend"]>(`/repositories/${id}/trend?tz=${encodeURIComponent(timeZone)}`),
  });
  return (
    <Card>
      <CardHeader title={t("overview.trendTitle")} description={t("overview.trendDescription")} />
      {trend.data ? (
        <div className="px-5 pt-4 pb-4">
          <TrendChart days={trendDays(trend.data)} repositoryId={id} />
        </div>
      ) : (
        <QueryStatus query={trend} />
      )}
    </Card>
  );
}

const TRIGGER_KEYS = {
  manual: "repository.triggerManual",
  schedule: "repository.triggerSchedule",
  webhook: "repository.triggerWebhook",
} as const;

function ScanHistory(props: {
  id: string;
  cursor?: string;
  pageSize?: number;
  onCursor: (cursor: string | undefined) => void;
  onPageSize: (size: number) => void;
}) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  const scans = useQuery({
    queryKey: ["scans", props.id, props.cursor, props.pageSize],
    queryFn: () =>
      api<Page<ScanRow>>(
        `/scans${toQuery({ repositoryId: props.id, cursor: props.cursor, pageSize: props.pageSize })}`,
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader title={t("repository.scanHistory")} description={t("repository.scanHistoryDescription")} />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("repository.columnWhen")}</th>
            <th className="px-3 py-2.5 font-medium">{t("repository.columnResult")}</th>
            <th className="hidden px-3 py-2.5 text-right font-medium @xl:table-cell">
              {t("repository.columnPackages")}
            </th>
            <th className="hidden px-5 py-2.5 font-medium @3xl:table-cell">{t("repository.columnCommit")}</th>
          </tr>
        </thead>
        <tbody>
          {scans.data?.items.map((s) => {
            const at = s.finishedAt ?? s.createdAt;
            return (
              <tr key={s.id} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5 text-sm whitespace-nowrap">
                  <time dateTime={at}>{formatDateTime(at)}</time>
                  <div className="text-muted-foreground">{t(TRIGGER_KEYS[s.trigger])}</div>
                </td>
                <td className="px-3 py-2.5">
                  <ScanStateBadge state={s.state} />
                  {s.state === "succeeded" ? (
                    <Link
                      to="/findings"
                      search={{ scanId: s.id, state: "all" }}
                      className="mt-1 block text-sm text-muted-foreground hover:underline"
                    >
                      {t("overview.scanSummary", {
                        added: s.newFindings ?? 0,
                        resolved: s.resolvedFindings ?? 0,
                      })}
                    </Link>
                  ) : s.error ? (
                    <div className="mt-1 text-sm text-destructive-text">{scanErrorText(s.error)}</div>
                  ) : null}
                </td>
                <td className="hidden px-3 py-2.5 text-right tabular-nums @xl:table-cell">
                  {s.packageCount === null ? "–" : formatNumber(s.packageCount)}
                </td>
                <td className="hidden px-5 py-2.5 font-mono text-sm @3xl:table-cell">
                  {s.commitSha ? s.commitSha.slice(0, 12) : "–"}
                  {s.branch ? <div className="font-sans text-muted-foreground">{s.branch}</div> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <QueryStatus query={scans} />
      {scans.data && scans.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("overview.noScans")}</p>
      ) : null}
      {scans.data ? (
        <Pagination page={scans.data} onCursor={props.onCursor} onPageSize={props.onPageSize} />
      ) : null}
    </Card>
  );
}

function PatchHistory(props: {
  id: string;
  cursor?: string;
  pageSize?: number;
  onCursor: (cursor: string | undefined) => void;
  onPageSize: (size: number) => void;
}) {
  const { t } = useTranslation();
  const patches = useQuery({
    queryKey: ["patches", props.id, props.cursor, props.pageSize],
    queryFn: () =>
      api<Page<PatchRow>>(
        `/repositories/${props.id}/patches${toQuery({ cursor: props.cursor, pageSize: props.pageSize })}`,
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader
        title={t("repository.patchHistory")}
        description={t("repository.patchHistoryDescription")}
      />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("repository.columnFixedOn")}</th>
            <th className="px-3 py-2.5 font-medium">{t("findings.columnFinding")}</th>
            <th className="px-3 py-2.5 font-medium">{t("findings.columnPackage")}</th>
            <th className="px-3 py-2.5 font-medium">{t("repository.columnChange")}</th>
            <th className="hidden px-5 py-2.5 font-medium @3xl:table-cell">
              {t("repository.columnOpenFor")}
            </th>
          </tr>
        </thead>
        <tbody>
          {patches.data?.items.map((p) => (
            <tr key={p.id} className="border-b align-top last:border-0">
              <td className="px-5 py-2.5 text-sm whitespace-nowrap">
                <time dateTime={p.resolvedAt} title={formatDateTime(p.resolvedAt)}>
                  {formatDate(p.resolvedAt)}
                </time>
              </td>
              <td className="px-3 py-2.5">
                <div className="mb-1">
                  <SeverityBadge severity={p.severity} />
                </div>
                <Link
                  to="/findings"
                  search={{ id: p.id, state: "all", repositoryId: props.id }}
                  className="font-medium break-all hover:underline"
                >
                  {p.vulnerabilityId}
                </Link>
              </td>
              <td className="px-3 py-2.5 font-mono text-sm break-all">
                {p.packageName}
                <div className="font-sans text-muted-foreground">{p.packageType}</div>
              </td>
              <td className="px-3 py-2.5 font-mono text-sm">
                {p.version} →{" "}
                {p.currentVersions.length ? (
                  p.currentVersions.join(", ")
                ) : (
                  <span className="font-sans text-muted-foreground">{t("repository.removed")}</span>
                )}
              </td>
              <td className="hidden px-5 py-2.5 text-sm text-muted-foreground @3xl:table-cell">
                {t("repository.days", {
                  count: Math.max(0, calendarDaysBetween(new Date(p.firstSeenAt), new Date(p.resolvedAt))),
                })}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <QueryStatus query={patches} />
      {patches.data && patches.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("repository.noPatches")}</p>
      ) : null}
      {patches.data ? (
        <Pagination page={patches.data} onCursor={props.onCursor} onPageSize={props.onPageSize} />
      ) : null}
    </Card>
  );
}
