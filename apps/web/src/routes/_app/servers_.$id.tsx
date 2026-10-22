import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Fingerprint, Flame, Play, Server, ShieldAlert, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { GradeSummary } from "../../components/grade-badge.tsx";
import { HostKeyDialog } from "../../components/host-key-dialog.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { Alert, Banner } from "../../components/ui/alert.tsx";
import { Badge, SeverityBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Checkbox } from "../../components/ui/checkbox.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { Select } from "../../components/ui/select.tsx";
import { useStepUp } from "../../components/use-step-up.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDate, formatDateTime, formatNumber, formatPercent, formatRelative } from "../../lib/format.ts";
import { useHostErrorText } from "../../lib/host-error.ts";
import { type ServerDetailSearch, serverDetailSearch, toQuery } from "../../lib/search.ts";
import { serverIsBusy, serverState } from "../../lib/servers.ts";
import type {
  HostDetail,
  HostFindingRow,
  HostPackageRow,
  HostRunRow,
  Page,
  Severity,
} from "../../lib/types.ts";

export const Route = createFileRoute("/_app/servers_/$id")({
  validateSearch: serverDetailSearch,
  component: ServerPage,
});

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/**
 * One server: what it runs, its host key, the vulnerabilities matched against its packages,
 * the packages themselves and the history of inventories (ADR 0011).
 */
function ServerPage() {
  const { t } = useTranslation();
  const { id } = Route.useParams();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();
  const hostError = useHostErrorText();
  const stepUp = useStepUp(me.user.email);
  const canEdit = me.role === "owner" || me.role === "admin";
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removeFailed, setRemoveFailed] = useState(false);

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api<HostDetail>(`/hosts/${id}`),
    refetchInterval: (q) => (q.state.data && serverIsBusy(q.state.data) ? 3000 : false),
  });
  const inventory = useMutation({
    mutationFn: () => api(`/hosts/${id}/inventory`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries(),
  });
  const remove = useMutation({
    mutationFn: () => api(`/hosts/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries();
      await navigate({ to: "/servers", search: {} });
    },
    onError: (e) => {
      if (stepUp.handled(e, () => remove.mutate())) return setConfirmRemove(false);
      setRemoveFailed(true);
    },
  });
  const lookAgain = useMutation({
    mutationFn: () => api(`/hosts/${id}/host-key/scan`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries(),
  });
  const setSearch = (patch: Partial<ServerDetailSearch>) =>
    navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true });

  const data = host.data;
  const state = data ? serverState(data) : null;
  const busy = state?.key === "queued" || state?.key === "running";

  return (
    <>
      <Link
        to="/servers"
        search={{}}
        className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
      >
        <ArrowLeft aria-hidden="true" className="size-4" />
        {t("servers.back")}
      </Link>
      <PageHeader
        icon={Server}
        title={data?.name ?? t("common.loading")}
        description={data ? `${data.address}:${data.port}` : ""}
        meta={data ? <GradeSummary row={data} kind="server" id={id} /> : null}
        actions={
          data && canEdit ? (
            <>
              {data.hostKey.status === "confirmed" ? (
                <Button disabled={busy || inventory.isPending} onClick={() => inventory.mutate()}>
                  <Play aria-hidden="true" className="size-4" />
                  {busy && state ? t(`servers.state.${state.key}`) : t("servers.runInventory")}
                </Button>
              ) : null}
              <Button
                variant="outline"
                onClick={() => {
                  setRemoveFailed(false);
                  setConfirmRemove(true);
                }}
              >
                <Trash2 aria-hidden="true" className="size-4" />
                {t("servers.remove")}
              </Button>
            </>
          ) : null
        }
      />
      {!data ? (
        <Card>
          <QueryStatus query={host} />
        </Card>
      ) : (
        <div className="grid gap-4">
          {inventory.isError || lookAgain.isError ? (
            <Alert tone="error">{t("errors.actionFailed")}</Alert>
          ) : null}
          <HostKeyNotice
            host={data}
            canEdit={canEdit}
            onCheck={() => setSearch({ key: "1" })}
            onLookAgain={() => lookAgain.mutate()}
          />
          {data.lastError && data.hostKey.status !== "changed" && state?.key !== "hostKeyWaiting" ? (
            <Alert tone="error">{hostError(data.lastError)}</Alert>
          ) : null}
          <div className="grid grid-cols-2 gap-4 @3xl:grid-cols-4">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="rounded-xl border bg-card px-[18px] py-4 shadow-xs">
                <div className="flex items-center justify-between gap-2 text-[15px] text-muted-foreground">
                  <span>{t("servers.openOf", { severity: t(`severity.${severity}`) })}</span>
                  {severity === "critical" ? (
                    <Flame aria-hidden="true" className="size-4 text-destructive-text" />
                  ) : null}
                </div>
                <div className="mt-1.5 text-[28px] leading-tight font-semibold tracking-[-0.02em]">
                  {formatNumber(data.open[severity] ?? 0)}
                </div>
              </div>
            ))}
          </div>
          {/* From the wide step on, the facts sit beside the vulnerabilities instead of above them. */}
          <div className="grid items-start gap-4 @wide:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
            <Facts host={data} />
            <Findings id={id} data={data} search={search} setSearch={setSearch} />
          </div>
          <div className="grid gap-4 @wide:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <Packages id={id} search={search} setSearch={setSearch} />
            <History id={id} search={search} setSearch={setSearch} />
          </div>
        </div>
      )}
      {data && canEdit ? (
        <>
          {search.key === "1" && data.hostKey.candidate ? (
            <HostKeyDialog
              host={data}
              email={me.user.email}
              open
              onClose={() => setSearch({ key: undefined })}
            />
          ) : null}
          <ConfirmDialog
            open={confirmRemove}
            title={t("servers.removeTitle", { name: data.name })}
            description={t("servers.removeDescription")}
            confirmLabel={t("servers.remove")}
            pending={remove.isPending}
            error={removeFailed ? t("errors.actionFailed") : null}
            onConfirm={() => remove.mutate()}
            onClose={() => setConfirmRemove(false)}
          />
        </>
      ) : null}
      {stepUp.dialog}
    </>
  );
}

function HostKeyNotice({
  host,
  canEdit,
  onCheck,
  onLookAgain,
}: {
  host: HostDetail;
  canEdit: boolean;
  onCheck: () => void;
  onLookAgain: () => void;
}) {
  const { t } = useTranslation();
  if (host.hostKey.status === "confirmed") return null;
  const changed = host.hostKey.status === "changed";
  if (!host.hostKey.candidate) {
    // First contact in progress: the worker reads the key in a moment (or failed, which is shown as the error).
    if (changed || host.lastError) return null;
    return (
      <p role="status" className="text-muted-foreground">
        {t("servers.keyWaiting")}
      </p>
    );
  }
  return (
    <Banner
      title={t(changed ? "servers.keyChangedTitle" : "servers.keyPendingTitle")}
      action={
        canEdit ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={onLookAgain}>
              {t("servers.lookAgain")}
            </Button>
            <Button onClick={onCheck}>
              <Fingerprint aria-hidden="true" className="size-4" />
              {t("servers.keyCheck")}
            </Button>
          </div>
        ) : null
      }
    >
      {t(changed ? "servers.keyChangedText" : "servers.keyPendingText")}
    </Banner>
  );
}

function Facts({ host }: { host: HostDetail }) {
  const { t } = useTranslation();
  const state = serverState(host);
  return (
    <Card>
      <CardHeader title={t("servers.facts")} />
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 px-5 py-4">
        <dt className="text-muted-foreground">{t("servers.columnStatus")}</dt>
        <dd>
          <Badge tone={state.tone}>
            {state.key === "hostKeyChanged" ? <ShieldAlert aria-hidden="true" /> : null}
            {t(`servers.state.${state.key}`)}
          </Badge>
        </dd>
        <dt className="text-muted-foreground">{t("servers.factAddress")}</dt>
        <dd className="font-mono break-all">
          {host.address}:{host.port}
        </dd>
        {host.proxmox ? (
          <>
            <dt className="text-muted-foreground">{t("servers.factProxmox")}</dt>
            <dd>
              <Link
                to="/servers"
                search={{ view: "proxmox", guest: host.proxmox.guestId }}
                className="hover:underline"
              >
                {host.proxmox.name}
              </Link>
              <span className="text-muted-foreground">
                {" "}
                · {t(`proxmox.typeShort.${host.proxmox.type}`)} {host.proxmox.vmid} ·{" "}
                {host.proxmox.clusterName}
              </span>
            </dd>
          </>
        ) : null}
        {host.wazuh ? (
          <>
            <dt className="text-muted-foreground">{t("servers.factWazuh")}</dt>
            <dd>
              <Link to="/xdr" search={{ q: host.wazuh.agentName }} className="hover:underline">
                {host.wazuh.agentName}
              </Link>
              <span className="text-muted-foreground">
                {" "}
                · {t(`xdr.status.${host.wazuh.status}` as never)} · {host.wazuh.connectionName}
              </span>
            </dd>
          </>
        ) : null}
        <dt className="text-muted-foreground">{t("servers.factAccount")}</dt>
        <dd className="font-mono">{host.sshUser}</dd>
        <dt className="text-muted-foreground">{t("servers.factSystem")}</dt>
        <dd>{host.os.name ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("servers.factKernel")}</dt>
        <dd className="font-mono">{host.kernel ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("servers.factArch")}</dt>
        <dd className="font-mono">{host.arch ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("servers.factPackages")}</dt>
        <dd>{host.packageCount === null ? "–" : formatNumber(host.packageCount)}</dd>
        <dt className="text-muted-foreground">{t("servers.factUpdates")}</dt>
        <dd>
          {host.pendingUpdates === null ? (
            "–"
          ) : (
            <>
              {t("servers.updatesCount", { count: host.pendingUpdates })}
              {host.securityUpdates ? (
                <span className="text-muted-foreground">
                  {" "}
                  · {t("servers.securityUpdates", { count: host.securityUpdates })}
                </span>
              ) : null}
            </>
          )}
        </dd>
        <dt className="text-muted-foreground">{t("servers.factHostKey")}</dt>
        <dd className="min-w-0">
          {host.hostKey.fingerprint ? (
            <>
              <span className="font-mono text-sm break-all">
                {host.hostKey.type} {host.hostKey.fingerprint}
              </span>
              {host.hostKey.confirmedAt ? (
                <div className="text-sm text-muted-foreground">{formatDate(host.hostKey.confirmedAt)}</div>
              ) : null}
            </>
          ) : (
            <span className="text-muted-foreground">{t(`servers.hostKeyState.${host.hostKey.status}`)}</span>
          )}
        </dd>
        <dt className="text-muted-foreground">{t("servers.factInventory")}</dt>
        <dd>
          {host.lastInventoryAt ? (
            <time dateTime={host.lastInventoryAt} title={formatDateTime(host.lastInventoryAt)}>
              {formatRelative(host.lastInventoryAt)}
            </time>
          ) : (
            t("servers.neverInventoried")
          )}
        </dd>
        <dt className="text-muted-foreground">{t("servers.factAdded")}</dt>
        <dd>
          {formatDate(host.createdAt)} ·{" "}
          {host.source === "csv" ? t("servers.sourceCsv") : t("servers.sourceManual")}
        </dd>
      </dl>
    </Card>
  );
}

type Props = {
  id: string;
  search: ServerDetailSearch;
  setSearch: (patch: Partial<ServerDetailSearch>) => void;
};

function Findings({ id, data, search, setSearch }: Props & { data: HostDetail }) {
  const { t } = useTranslation();
  const state = search.findingState ?? "open";
  const list = useQuery({
    queryKey: [
      "host-findings",
      id,
      search.findings,
      search.findingsPageSize,
      state,
      search.findingSeverity,
      search.findingFixable,
      search.findingKev,
      search.findingSort,
      search.findingDir,
    ],
    queryFn: () =>
      api<Page<HostFindingRow>>(
        `/hosts/${id}/findings${toQuery({
          cursor: search.findings,
          pageSize: search.findingsPageSize,
          state,
          severity: search.findingSeverity,
          fixable: search.findingFixable,
          kev: search.findingKev,
          sort: search.findingSort,
          dir: search.findingDir,
        })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const sortProps = {
    current: search.findingSort,
    dir: search.findingDir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({
        findingSort: sort as ServerDetailSearch["findingSort"],
        findingDir: dir,
        findings: undefined,
      }),
  };
  return (
    // The grade links here (ADR 0018), so the card is an anchor target.
    <Card className="scroll-mt-4" id="findings">
      <CardHeader
        title={t("servers.findingsTitle")}
        description={t("servers.findingsDescription")}
        actions={
          <Segmented
            label={t("servers.findingsTitle")}
            value={state}
            options={(["open", "resolved", "all"] as const).map((s) => ({
              value: s,
              label: t(`findingState.${s}`),
            }))}
            onChange={(next) =>
              setSearch({ findingState: next === "open" ? undefined : next, findings: undefined })
            }
          />
        }
      />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 pb-3">
        <Select
          aria-label={t("findings.severityFilter")}
          value={search.findingSeverity ?? ""}
          onChange={(e) =>
            setSearch({
              findingSeverity: (e.target.value || undefined) as ServerDetailSearch["findingSeverity"],
              findings: undefined,
            })
          }
          className="h-9 max-w-48"
        >
          <option value="">{t("servers.findingsAllSeverities")}</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {t(`severity.${severity}`)}
            </option>
          ))}
        </Select>
        <label className="flex items-center gap-2 text-sm whitespace-nowrap">
          <Checkbox
            checked={search.findingKev === "1"}
            onChange={(e) =>
              setSearch({ findingKev: e.target.checked ? "1" : undefined, findings: undefined })
            }
          />
          {t("findings.knownExploitedOnly")}
        </label>
        <label className="flex items-center gap-2 text-sm whitespace-nowrap">
          <Checkbox
            checked={search.findingFixable === "1"}
            onChange={(e) =>
              setSearch({ findingFixable: e.target.checked ? "1" : undefined, findings: undefined })
            }
          />
          {t("findings.fixableOnly")}
        </label>
      </div>
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="vulnerability"
              label={t("findings.columnFinding")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            <SortHeader
              column="cvss"
              label={t("findings.columnCvss")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="epss"
              label={
                <abbr title={t("findings.epssHint")} className="no-underline">
                  {t("findings.epss")}
                </abbr>
              }
              natural="desc"
              align="right"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="package"
              label={t("findings.columnPackage")}
              natural="asc"
              className="px-3"
              {...sortProps}
            />
            <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("findings.columnFixedIn")}</th>
            <SortHeader
              column="firstSeen"
              label={t("findings.columnFirstSeen")}
              natural="desc"
              className="hidden px-5 @wide:table-cell"
              {...sortProps}
            />
          </tr>
        </thead>
        <tbody>
          {list.data?.items.map((f) => (
            <tr key={f.id} className="border-b align-top last:border-0">
              <td className="px-5 py-2.5">
                <div className="mb-1">
                  <SeverityBadge severity={f.severity} />
                </div>
                <span className="font-medium break-all">{f.vulnerabilityId}</span>
                {f.knownExploited ? (
                  <div className="text-sm text-destructive-text">{t("findings.kev")}</div>
                ) : null}
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums">
                {f.cvssScore === null ? (
                  <span className="text-muted-foreground">–</span>
                ) : (
                  f.cvssScore.toFixed(1)
                )}
              </td>
              <td className="hidden px-3 py-2.5 text-right tabular-nums @xwide:table-cell">
                {f.epss === null ? <span className="text-muted-foreground">–</span> : formatPercent(f.epss)}
              </td>
              <td className="px-3 py-2.5 font-mono text-sm break-all">
                {f.packageName}
                <div className="font-sans text-muted-foreground">{f.packageVersion}</div>
              </td>
              <td className="hidden px-3 py-2.5 font-mono text-sm break-all @3xl:table-cell">
                {f.fixedIn?.length ? (
                  f.fixedIn.join(", ")
                ) : (
                  <span className="font-sans text-muted-foreground">–</span>
                )}
              </td>
              <td className="hidden px-5 py-2.5 text-sm text-muted-foreground @wide:table-cell">
                <time dateTime={f.firstSeenAt} title={formatDateTime(f.firstSeenAt)}>
                  {formatDate(f.firstSeenAt)}
                </time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <QueryStatus query={list} />
      {list.data && list.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">
          {data.lastInventoryAt
            ? state === "open"
              ? t("servers.findingsNone")
              : t("servers.findingsEmpty")
            : t("servers.findingsBeforeInventory")}
        </p>
      ) : null}
      {list.data ? (
        <Pagination
          page={list.data}
          onCursor={(findings) => setSearch({ findings })}
          onPageSize={(findingsPageSize) => setSearch({ findingsPageSize, findings: undefined })}
        />
      ) : null}
    </Card>
  );
}

function Packages({ id, search, setSearch }: Props) {
  const { t } = useTranslation();
  const list = useQuery({
    queryKey: [
      "host-packages",
      id,
      search.packages,
      search.packagesPageSize,
      search.packageQ,
      search.updates,
    ],
    queryFn: () =>
      api<Page<HostPackageRow>>(
        `/hosts/${id}/packages${toQuery({
          cursor: search.packages,
          pageSize: search.packagesPageSize,
          q: search.packageQ,
          updatable: search.updates,
        })}`,
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader title={t("servers.packagesTitle")} description={t("servers.packagesDescription")} />
      <div className="flex flex-wrap items-center gap-3 px-5 pb-3">
        <label className="flex items-center gap-2 text-sm whitespace-nowrap">
          <Checkbox
            checked={search.updates === "1"}
            onChange={(e) => setSearch({ updates: e.target.checked ? "1" : undefined, packages: undefined })}
          />
          {t("servers.updatesOnly")}
        </label>
        <SearchInput
          className="ml-auto"
          label={t("servers.packagesSearch")}
          value={search.packageQ ?? ""}
          onChange={(q) => setSearch({ packageQ: q || undefined, packages: undefined })}
        />
      </div>
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("servers.columnPackage")}</th>
            <th className="px-3 py-2.5 font-medium">{t("servers.columnVersion")}</th>
            <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("servers.columnArch")}</th>
            <th className="px-5 py-2.5 font-medium">{t("servers.columnUpdate")}</th>
          </tr>
        </thead>
        <tbody>
          {list.data?.items.map((p) => (
            <tr key={p.id} className="border-b align-top last:border-0">
              <td className="px-5 py-2.5 font-mono text-sm break-all">
                {p.name}
                <div className="font-sans text-muted-foreground">{p.type}</div>
              </td>
              <td className="px-3 py-2.5 font-mono text-sm break-all">{p.version}</td>
              <td className="hidden px-3 py-2.5 font-mono text-sm @3xl:table-cell">{p.arch ?? "–"}</td>
              <td className="px-5 py-2.5 font-mono text-sm break-all">
                {p.upgradableTo ? (
                  <>
                    → {p.upgradableTo}
                    {p.securityUpdate ? (
                      <div>
                        <Badge tone="high">{t("servers.security")}</Badge>
                      </div>
                    ) : null}
                  </>
                ) : (
                  <span className="font-sans text-muted-foreground">–</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <QueryStatus query={list} />
      {list.data && list.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("servers.packagesEmpty")}</p>
      ) : null}
      {list.data ? (
        <Pagination
          page={list.data}
          onCursor={(packages) => setSearch({ packages })}
          onPageSize={(packagesPageSize) => setSearch({ packagesPageSize, packages: undefined })}
        />
      ) : null}
    </Card>
  );
}

function History({ id, search, setSearch }: Props) {
  const { t } = useTranslation();
  const hostError = useHostErrorText();
  const list = useQuery({
    queryKey: ["host-runs", id, search.runs, search.runsPageSize],
    queryFn: () =>
      api<Page<HostRunRow>>(
        `/hosts/${id}/runs${toQuery({ cursor: search.runs, pageSize: search.runsPageSize })}`,
      ),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader title={t("servers.historyTitle")} description={t("servers.historyDescription")} />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("servers.columnWhen")}</th>
            <th className="px-3 py-2.5 font-medium">{t("servers.columnResult")}</th>
            <th className="hidden px-5 py-2.5 text-right font-medium @3xl:table-cell">
              {t("servers.columnPackagesShort")}
            </th>
          </tr>
        </thead>
        <tbody>
          {list.data?.items.map((r) => {
            const at = r.finishedAt ?? r.createdAt;
            return (
              <tr key={r.id} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5 text-sm whitespace-nowrap">
                  <time dateTime={at} title={formatDateTime(at)}>
                    {formatDateTime(at)}
                  </time>
                  <div className="text-muted-foreground">{t(`servers.trigger.${r.trigger}`)}</div>
                </td>
                <td className="px-3 py-2.5">
                  <Badge
                    tone={r.state === "failed" ? "critical" : r.state === "succeeded" ? "neutral" : "info"}
                  >
                    {t(`servers.runState.${r.state}`)}
                  </Badge>
                  {r.state === "succeeded" ? (
                    <div className="mt-1 text-sm text-muted-foreground">
                      {t("servers.runSummary", {
                        added: r.newFindings ?? 0,
                        resolved: r.resolvedFindings ?? 0,
                      })}
                    </div>
                  ) : r.error ? (
                    <div className={cn("mt-1 text-sm", r.state === "failed" && "text-destructive-text")}>
                      {hostError(r.error)}
                    </div>
                  ) : null}
                </td>
                <td className="hidden px-5 py-2.5 text-right tabular-nums @3xl:table-cell">
                  {r.packageCount === null ? "–" : formatNumber(r.packageCount)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <QueryStatus query={list} />
      {list.data && list.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">{t("servers.noRuns")}</p>
      ) : null}
      {list.data ? (
        <Pagination
          page={list.data}
          onCursor={(runs) => setSearch({ runs })}
          onPageSize={(runsPageSize) => setSearch({ runsPageSize, runs: undefined })}
        />
      ) : null}
    </Card>
  );
}
