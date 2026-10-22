import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  ArrowDown,
  ArrowUp,
  ExternalLink,
  Minus,
  Plus,
  Radar,
  RefreshCw,
  Settings,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AddServerWizard } from "../../components/add-server-wizard.tsx";
import { Segmented } from "../../components/filters.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Alert, Banner } from "../../components/ui/alert.tsx";
import { BADGE_TONE, Badge, SeverityBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { EnrollmentDialog } from "../../components/wazuh-enrollment.tsx";
import { type AgentListState, agentPrefill, XdrAgents } from "../../components/xdr-agents.tsx";
import { XdrSummaryCard } from "../../components/xdr-summary.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { type XdrSearch, xdrSearch } from "../../lib/search.ts";
import type {
  XdrAgent,
  XdrConnection,
  XdrFimEvent,
  XdrOverview,
  XdrWindow,
  XdrWindowData,
} from "../../lib/types.ts";
import { changeOf, PERIOD_KEY, useWazuhErrorText, XDR_SEVERITIES } from "../../lib/xdr.ts";

export const Route = createFileRoute("/_app/xdr")({
  validateSearch: xdrSearch,
  component: XdrPage,
});

const PERIODS = ["24h", "7d", "30d"] as const satisfies readonly XdrWindow[];

/** Infrastructure, XDR (ADR 0015): what the customer's Wazuh reports, read-only. */
function XdrPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();
  const errorText = useWazuhErrorText();
  const canEdit = me.role === "owner" || me.role === "admin";
  const canUse = me.role !== "viewer";
  const period = search.period ?? "24h";
  const [addingAgent, setAddingAgent] = useState<XdrAgent | null>(null);

  const overview = useQuery({
    queryKey: ["xdr-overview"],
    queryFn: () => api<XdrOverview>("/xdr/overview"),
    // Follow the worker while a sync is waiting or running.
    refetchInterval: (q) =>
      q.state.data?.connection?.run?.state === "queued" || q.state.data?.connection?.run?.state === "running"
        ? 3000
        : 60_000,
  });
  const sync = useMutation({
    mutationFn: () => api("/xdr/sync", { method: "POST" }),
    onSuccess: () =>
      queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("xdr-") }),
  });

  const data = overview.data;
  const connection = data?.connection ?? null;

  const setSearch = (patch: Partial<XdrSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, ...patch }), replace });
  const listState: AgentListState = {
    q: search.q,
    status: search.status,
    link: search.link,
    group: search.group,
    sort: search.sort,
    dir: search.dir,
    cursor: search.cursor,
    pageSize: search.pageSize,
  };
  const onList = (patch: AgentListState, replace = false) => setSearch(patch as Partial<XdrSearch>, replace);

  if (!data) {
    return (
      <>
        <PageHeader icon={Radar} title={t("xdr.title")} description={t("xdr.description")} />
        <Card>
          <QueryStatus query={overview} />
        </Card>
      </>
    );
  }
  if (!connection) {
    return (
      <>
        <PageHeader icon={Radar} title={t("xdr.title")} description={t("xdr.description")} />
        <Card>
          <div className="grid justify-items-start gap-3 px-5 py-6">
            <p className="max-w-[60ch] text-muted-foreground">
              {canEdit ? t("xdr.emptyAdmin") : t("xdr.emptyMember")}
            </p>
            {canEdit ? (
              <Link
                to="/settings"
                search={{ section: "xdr" }}
                className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground hover:bg-primary/90"
              >
                <Radar aria-hidden="true" className="size-4" />
                {t("xdr.connect")}
              </Link>
            ) : null}
          </div>
        </Card>
      </>
    );
  }

  const busy = connection.run?.state === "queued" || connection.run?.state === "running";
  const failed = connection.lastError ?? (connection.run?.state === "failed" ? connection.run.error : null);
  const window = data.windows?.[period];
  const confirmed = connection.endpoints.every((e) => e.certificate.status === "confirmed");
  const anyChanged = connection.endpoints.some((e) => e.certificate.status === "changed");
  const privilegesOpen = connection.privileges.extra.length > 0 && !connection.privileges.acknowledged;
  const ai = data.ai;

  return (
    <>
      <PageHeader
        icon={Radar}
        title={t("xdr.title")}
        description={t("xdr.description")}
        actions={
          <>
            {connection.dashboardUrl ? (
              <a
                href={connection.dashboardUrl}
                target="_blank"
                rel="noopener noreferrer"
                title={t("xdr.openDashboardHint")}
                className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
              >
                <ExternalLink aria-hidden="true" className="size-4" />
                {t("xdr.openDashboard")}
              </a>
            ) : null}
            {canUse ? (
              <Button variant="outline" onClick={() => setSearch({ enroll: "1" })}>
                <Plus aria-hidden="true" className="size-4" />
                {t("xdr.enrollButton")}
              </Button>
            ) : null}
            {canEdit && confirmed ? (
              <Button variant="outline" disabled={busy || sync.isPending} onClick={() => sync.mutate()}>
                <RefreshCw aria-hidden="true" className={cn("size-4", busy && "motion-safe:animate-spin")} />
                {busy ? t("xdr.syncing") : t("xdr.syncNow")}
              </Button>
            ) : null}
            {canEdit ? (
              <Link
                to="/settings"
                search={{ section: "xdr" }}
                className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
              >
                <Settings aria-hidden="true" className="size-4" />
                {t("xdr.manage")}
              </Link>
            ) : null}
          </>
        }
      />

      {anyChanged || !confirmed || privilegesOpen ? (
        <Banner
          title={
            anyChanged
              ? t("xdr.settings.certChangedTitle", { endpoint: t("xdr.endpointName.manager") })
              : privilegesOpen
                ? t("xdr.privilegesBadge")
                : t("xdr.attentionFinish")
          }
          action={
            canEdit ? (
              <Link
                to="/settings"
                search={{ section: "xdr" }}
                className="inline-flex h-9 items-center rounded-md border border-input bg-card px-3 font-medium shadow-xs hover:bg-accent"
              >
                {t("xdr.attentionFinish")}
              </Link>
            ) : undefined
          }
        />
      ) : null}
      {sync.isError ? (
        <div className="mb-4">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}

      <div className="grid gap-4">
        <ConnectionCard
          connection={connection}
          syncMinutes={data.syncIntervalMinutes ?? 15}
          failed={failed ? errorText(failed) : null}
          busy={busy}
        />

        <Card>
          <CardHeader
            title={t("xdr.alertsTitle")}
            description={t("xdr.alertsDescription")}
            actions={
              <Segmented
                label={t("xdr.periodLabel")}
                value={period}
                options={PERIODS.map((p) => ({ value: p, label: t(`xdr.period.${PERIOD_KEY[p]}`) }))}
                onChange={(p) => setSearch({ period: p === "24h" ? undefined : p })}
              />
            }
          />
          {window ? (
            <div className="grid gap-4 px-5 pb-5 @wide:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] @wide:items-start">
              <div className="grid gap-3">
                <AlertFigures window={window} />
                <p className="text-sm text-muted-foreground">{t("xdr.severityScale")}</p>
                {connection.lastSyncAt &&
                Date.parse(connection.lastSyncAt) - Date.parse(window.readAt) > 90_000 ? (
                  <p className="text-sm text-muted-foreground">
                    {t("xdr.staleWindow", { when: formatRelative(window.readAt) })}
                  </p>
                ) : null}
              </div>
              <PeriodsTable
                windows={data.windows ?? {}}
                active={period}
                onPick={(p) => setSearch({ period: p === "24h" ? undefined : p })}
              />
            </div>
          ) : (
            <p className="px-5 pb-5 text-muted-foreground">
              {connection.lastSyncAt || failed ? t("xdr.noAlertData") : t("xdr.waitingForData")}
            </p>
          )}
        </Card>

        <div className="grid items-start gap-4 @wide:grid-cols-2 @xwide:grid-cols-3">
          <Card>
            <CardHeader title={t("xdr.tacticsTitle")} description={t("xdr.tacticsDescription")} />
            <BarList
              rows={(window?.tactics ?? []).map((x) => ({ key: x.name, label: x.name, count: x.count }))}
              empty={t("xdr.tacticsEmpty")}
              column={t("xdr.columnTactic")}
              countColumn={t("xdr.columnAlerts")}
            />
          </Card>
          <Card>
            <CardHeader title={t("xdr.topAgentsTitle")} description={t("xdr.topAgentsDescription")} />
            <BarList
              rows={(window?.agents ?? []).map((x) => ({
                key: x.agentId,
                label: x.name,
                sub: x.agentId,
                count: x.count,
              }))}
              empty={t("xdr.topAgentsEmpty")}
              column={t("xdr.columnAgent")}
              countColumn={t("xdr.columnAlerts")}
            />
          </Card>
          <VulnerabilityCard vulnerabilities={data.vulnerabilities ?? null} />
        </div>

        <FimCard events={data.fim ?? []} count={window?.fim ?? 0} />

        {ai?.state === "ready" ? <XdrSummaryCard canAsk={canUse} model={ai.model} /> : null}

        <XdrAgents
          state={listState}
          onChange={onList}
          canEdit={canEdit}
          onAddAsServer={setAddingAgent}
          title={t("xdr.agentsTitle")}
          description={`${t("xdr.agentsDescription")} ${t("xdr.agentsSummary", {
            active: formatNumber(data.agents?.active ?? 0),
            total: formatNumber(data.agents?.total ?? 0),
          })}`}
        />
      </div>

      <EnrollmentDialog open={search.enroll === "1"} onClose={() => setSearch({ enroll: undefined }, true)} />
      {canEdit ? (
        <AddServerWizard
          open={addingAgent !== null}
          me={me}
          prefill={addingAgent ? agentPrefill(addingAgent, connection.name) : undefined}
          onClose={() => setAddingAgent(null)}
        />
      ) : null}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Connection                                                                  */
/* -------------------------------------------------------------------------- */

function ConnectionCard({
  connection,
  syncMinutes,
  failed,
  busy,
}: {
  connection: XdrConnection;
  syncMinutes: number;
  failed: string | null;
  busy: boolean;
}) {
  const { t } = useTranslation();
  const warnings = connection.run?.warnings ?? [];
  return (
    <Card>
      <CardHeader title={t("xdr.connectionTitle")} description={connection.name} />
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 px-5 pb-4 @3xl:grid-cols-4 @xwide:grid-cols-6">
        <div>
          <dt className="text-sm text-muted-foreground">{t("xdr.adapterLabel")}</dt>
          <dd className="flex flex-wrap items-center gap-1.5 font-medium">
            {connection.adapter ? t(`xdr.adapterName.${connection.adapter.id}`) : "–"}
            {connection.adapter?.preview ? (
              <span title={t("xdr.previewHint")}>
                <Badge tone="info">{t("xdr.preview")}</Badge>
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt className="text-sm text-muted-foreground">{t("xdr.managerVersion")}</dt>
          <dd className="font-mono text-sm">{connection.managerVersion ?? "–"}</dd>
        </div>
        <div>
          <dt className="text-sm text-muted-foreground">{t("xdr.indexerVersion")}</dt>
          <dd className="font-mono text-sm">{connection.indexerVersion ?? "–"}</dd>
        </div>
        <div>
          <dt className="text-sm text-muted-foreground">{t("xdr.lastSync")}</dt>
          <dd className="font-medium">
            {connection.lastSyncAt ? (
              <time dateTime={connection.lastSyncAt} title={formatDateTime(connection.lastSyncAt)}>
                {formatRelative(connection.lastSyncAt)}
              </time>
            ) : busy ? (
              t("xdr.syncing")
            ) : (
              t("xdr.neverSynced")
            )}
            <span className="block text-sm font-normal text-muted-foreground">
              {t("xdr.syncEvery", { minutes: syncMinutes })}
            </span>
          </dd>
        </div>
        <div className="col-span-2 flex flex-wrap items-center gap-1.5 @3xl:col-span-2">
          <Badge tone="neutral">{t("xdr.readOnlyBadge")}</Badge>
          {connection.endpoints.map((e) => (
            <Badge
              key={e.kind}
              tone={
                e.certificate.status === "changed"
                  ? "critical"
                  : e.certificate.status === "pending"
                    ? "info"
                    : "neutral"
              }
            >
              <ShieldAlert aria-hidden="true" />
              {t(`xdr.endpointName.${e.kind}`)}:{" "}
              {e.trust === "ca" && e.certificate.status === "confirmed"
                ? t("xdr.certificate.authority")
                : t(`xdr.certificate.${e.certificate.status}`)}
            </Badge>
          ))}
          {!connection.enabled ? <Badge tone="neutral">{t("xdr.settings.disabled")}</Badge> : null}
        </div>
      </dl>
      {failed || warnings.length > 0 ? (
        <div className="grid gap-1 border-t px-5 py-3">
          {failed ? <p className="text-sm text-destructive-text">{failed}</p> : null}
          {warnings.map((w) => (
            <p key={w} className="text-sm text-muted-foreground">
              {t(`xdr.warning.${w}` as never)}
            </p>
          ))}
        </div>
      ) : null}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Alerts                                                                      */
/* -------------------------------------------------------------------------- */

function ChangeLine({ now, before }: { now: number; before: number | null | undefined }) {
  const { t } = useTranslation();
  const change = changeOf(now, before);
  const Icon = change.kind === "up" ? ArrowUp : change.kind === "down" ? ArrowDown : Minus;
  const label =
    change.kind === "up"
      ? t("xdr.changeUp", { count: formatNumber(change.by) })
      : change.kind === "down"
        ? t("xdr.changeDown", { count: formatNumber(change.by) })
        : change.kind === "same"
          ? t("xdr.changeSame")
          : t("xdr.changeUnknown");
  return (
    <div className="flex items-center gap-1 text-sm text-muted-foreground">
      <Icon aria-hidden="true" className="size-3.5 flex-none" />
      <span>{label}</span>
      {before !== null && before !== undefined ? (
        <span className="hidden @xl:inline">· {t("xdr.previousCount", { count: formatNumber(before) })}</span>
      ) : null}
    </div>
  );
}

function AlertFigures({ window }: { window: XdrWindowData }) {
  const { t } = useTranslation();
  return (
    <dl className="grid grid-cols-2 gap-3 @3xl:grid-cols-5" data-testid="alert-figures">
      <div className="rounded-lg border px-3.5 py-3">
        <dt className="text-sm text-muted-foreground">{t("xdr.alertsTotal")}</dt>
        <dd className="text-2xl font-semibold tabular-nums">{formatNumber(window.total)}</dd>
        <ChangeLine now={window.total} before={window.previous?.total} />
      </div>
      {XDR_SEVERITIES.map((severity) => (
        <div key={severity} className="rounded-lg border px-3.5 py-3" data-severity={severity}>
          <dt>
            <SeverityBadge severity={severity} />
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums">
            {formatNumber(window.bySeverity[severity])}
          </dd>
          <ChangeLine now={window.bySeverity[severity]} before={window.previous?.bySeverity[severity]} />
        </div>
      ))}
    </dl>
  );
}

/** All periods at a glance: a plain table, one row per period. Wide screens show it beside the figures. */
function PeriodsTable({
  windows,
  active,
  onPick,
}: {
  windows: Partial<Record<XdrWindow, XdrWindowData>>;
  active: XdrWindow;
  onPick: (period: XdrWindow) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="hidden @wide:block">
      <h3 className="mb-1.5 text-sm font-medium">{t("xdr.periodsTitle")}</h3>
      <table className="w-full text-left text-sm">
        <thead className="text-muted-foreground">
          <tr className="border-b">
            <th className="py-1.5 pr-2 font-medium">{t("xdr.periodLabel")}</th>
            {XDR_SEVERITIES.map((s) => (
              <th key={s} className="px-2 py-1.5 text-right font-medium">
                {t(`severity.${s}`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PERIODS.map((p) => {
            const w = windows[p];
            return (
              <tr key={p} className={cn("border-b last:border-0", p === active && "bg-muted/50")}>
                <th scope="row" className="py-1.5 pr-2 text-left font-medium">
                  <button type="button" onClick={() => onPick(p)} className="hover:underline">
                    {t(`xdr.periodLong.${PERIOD_KEY[p]}`)}
                  </button>
                </th>
                {XDR_SEVERITIES.map((s) => (
                  <td key={s} className="px-2 py-1.5 text-right tabular-nums">
                    {w ? (
                      <span className={cn(w.bySeverity[s] > 0 ? "" : "text-muted-foreground")}>
                        {formatNumber(w.bySeverity[s])}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">–</span>
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Tactics, busiest agents                                                     */
/* -------------------------------------------------------------------------- */

/** A table whose count column carries a plain proportional bar. SVG, because the CSP allows no inline style. */
function BarList({
  rows,
  empty,
  column,
  countColumn,
}: {
  rows: { key: string; label: string; sub?: string; count: number }[];
  empty: string;
  column: string;
  countColumn: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  if (rows.length === 0) return <p className="px-5 pb-5 text-muted-foreground">{empty}</p>;
  return (
    <table className="w-full text-left">
      <thead className="text-sm text-muted-foreground">
        <tr className="border-y">
          <th className="px-5 py-2 font-medium">{column}</th>
          <th className="px-5 py-2 text-right font-medium">{countColumn}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key} className="border-b align-top last:border-0">
            <td className="px-5 py-2.5">
              <div className="break-words">{row.label}</div>
              {row.sub ? <div className="font-mono text-sm text-muted-foreground">{row.sub}</div> : null}
              <svg aria-hidden="true" className="mt-1.5 block h-1.5 w-full" preserveAspectRatio="none">
                <rect width="100%" height="100%" rx="3" className="fill-muted" />
                <rect
                  width={`${Math.max(2, Math.round((row.count / max) * 100))}%`}
                  height="100%"
                  rx="3"
                  className="fill-muted-foreground/60"
                />
              </svg>
            </td>
            <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(row.count)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function VulnerabilityCard({ vulnerabilities }: { vulnerabilities: XdrOverview["vulnerabilities"] | null }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("xdr.vulnTitle")} description={t("xdr.vulnDescription")} />
      {vulnerabilities ? (
        <div className="grid gap-3 px-5 pb-5">
          <dl className="grid grid-cols-2 gap-3">
            {XDR_SEVERITIES.map((s) => (
              <div key={s} className="rounded-lg border px-3 py-2">
                <dt>
                  <SeverityBadge severity={s} />
                </dt>
                <dd className="mt-1 text-xl font-semibold tabular-nums">
                  {formatNumber(vulnerabilities[s])}
                </dd>
              </div>
            ))}
          </dl>
          <p className="text-sm text-muted-foreground">
            {t("xdr.vulnAgents", { count: vulnerabilities.agentsAffected })}
          </p>
        </div>
      ) : (
        <p className="px-5 pb-5 text-muted-foreground">{t("xdr.vulnUnknown")}</p>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* File integrity                                                              */
/* -------------------------------------------------------------------------- */

function FimCard({ events, count }: { events: XdrFimEvent[]; count: number }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("xdr.fimTitle")} description={t("xdr.fimDescription", { count })} />
      {events.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("xdr.fimEmpty")}</p>
      ) : (
        <table className="w-full border-t text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("xdr.columnTime")}</th>
              <th className="px-3 py-2.5 font-medium">{t("xdr.columnAgent")}</th>
              <th className="px-3 py-2.5 font-medium">{t("xdr.columnPath")}</th>
              <th className="hidden px-5 py-2.5 font-medium @wide:table-cell">{t("xdr.columnEvent")}</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5 text-sm whitespace-nowrap">
                  <time dateTime={event.at} title={formatDateTime(event.at)}>
                    {formatRelative(event.at)}
                  </time>
                </td>
                <td className="px-3 py-2.5">
                  <span className="break-all">{event.agentName || event.agentId || "–"}</span>
                </td>
                <td className="px-3 py-2.5">
                  {/* Plain text exactly as the agent reported it: never a link, never markup. */}
                  <code className="font-mono text-sm break-all" data-testid="fim-path">
                    {event.path}
                  </code>
                  <span className="ml-2 text-sm text-muted-foreground @wide:hidden">
                    {t(`xdr.fimEvent.${event.event}`)}
                  </span>
                </td>
                <td className="hidden px-5 py-2.5 @wide:table-cell">
                  <span className={cn("rounded-md px-1.5 py-px text-sm", BADGE_TONE.neutral)}>
                    {t(`xdr.fimEvent.${event.event}`)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="border-t px-5 py-2.5 text-sm text-muted-foreground">{t("xdr.fimPathNote")}</p>
    </Card>
  );
}
