import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Boxes,
  Fingerprint,
  Play,
  Plus,
  Server,
  Settings,
  ShieldAlert,
  Trash2,
  Upload,
  Wrench,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AddServerWizard } from "../../components/add-server-wizard.tsx";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { HostKeyDialog } from "../../components/host-key-dialog.tsx";
import { ImportServersDialog } from "../../components/import-servers-dialog.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { ProxmoxView } from "../../components/proxmox-view.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { ActionMenu, type MenuAction } from "../../components/ui/action-menu.tsx";
import { BADGE_TONE, Badge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { useStepUp } from "../../components/use-step-up.tsx";
import { type AgentListState, agentPrefill, XdrAgents } from "../../components/xdr-agents.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { useHostErrorText } from "../../lib/host-error.ts";
import { rowClick } from "../../lib/row-link.ts";
import { type ServerSearch, serverSearch, toQuery } from "../../lib/search.ts";
import { serverIsBusy, serverState } from "../../lib/servers.ts";
import type { HostRow, Page, Severity, XdrAgent, XdrConnectionResponse } from "../../lib/types.ts";
import { xdrStatusQuery } from "../../lib/xdr.ts";

export const Route = createFileRoute("/_app/servers")({
  validateSearch: serverSearch,
  component: Servers,
});

const STATUSES = ["all", "vulnerable", "attention"] as const;
/** Search params that belong to the screen, not to the list of servers the API returns. */
const UI_ONLY = [
  "add",
  "import",
  "key",
  "view",
  "pxQ",
  "pxCluster",
  "pxType",
  "pxStatus",
  "pxNode",
  "pxFlag",
  "pxSort",
  "pxDir",
  "pxCursor",
  "pxPageSize",
  "guest",
  "addGuest",
  "wzQ",
  "wzStatus",
  "wzLink",
  "wzSort",
  "wzDir",
  "wzCursor",
  "wzPageSize",
];
/** Open findings per severity get a column each; low lives on the server's page. */
const SEVERITY_COLUMNS = ["critical", "high", "medium"] as const satisfies readonly Severity[];
const COUNT_PILL = "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold";

function Servers() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const canEdit = me.role === "owner" || me.role === "admin";
  const proxmox = search.view === "proxmox";
  const wazuh = search.view === "wazuh";
  const xdr = useQuery(xdrStatusQuery);
  const [addingAgent, setAddingAgent] = useState<XdrAgent | null>(null);
  const wazuhConnection = useQuery({
    queryKey: ["xdr-connection"],
    queryFn: () => api<XdrConnectionResponse>("/xdr/connection"),
    enabled: wazuh,
  });

  const query = useQuery({
    queryKey: ["hosts", search],
    queryFn: () => api<Page<HostRow>>(`/hosts${toQuery(search, UI_ONLY)}`),
    enabled: !proxmox && !wazuh,
    placeholderData: keepPreviousData,
    // Follow the worker until it has read the host key or finished the inventory.
    refetchInterval: (q) => (q.state.data?.items.some(serverIsBusy) ? 3000 : false),
  });
  const counts = useQuery({
    queryKey: ["host-counts", search.q ?? ""],
    queryFn: () => api<Record<(typeof STATUSES)[number], number>>(`/hosts/counts${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
    enabled: !proxmox && !wazuh,
  });

  const setSearch = (patch: Partial<ServerSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });
  const sortProps = {
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as ServerSearch["sort"], dir }),
  };
  const wazuhState: AgentListState = {
    q: search.wzQ,
    status: search.wzStatus,
    link: search.wzLink,
    sort: search.wzSort,
    dir: search.wzDir,
    cursor: search.wzCursor,
    pageSize: search.wzPageSize,
  };
  const onWazuhList = (patch: AgentListState, replace = false) =>
    setSearch(
      {
        ...("q" in patch ? { wzQ: patch.q, wzCursor: undefined } : {}),
        ...("status" in patch ? { wzStatus: patch.status, wzCursor: undefined } : {}),
        ...("link" in patch ? { wzLink: patch.link, wzCursor: undefined } : {}),
        ...("sort" in patch ? { wzSort: patch.sort as ServerSearch["wzSort"], wzCursor: undefined } : {}),
        ...("dir" in patch ? { wzDir: patch.dir } : {}),
        ...("cursor" in patch ? { wzCursor: patch.cursor } : {}),
        ...("pageSize" in patch ? { wzPageSize: patch.pageSize, wzCursor: undefined } : {}),
      },
      replace,
    );
  const keyHost = search.key ? query.data?.items.find((h) => h.id === search.key) : undefined;

  return (
    <>
      <PageHeader
        icon={Server}
        title={t("servers.title")}
        description={t("servers.description")}
        actions={
          canEdit && (proxmox || wazuh) ? (
            <Link
              to="/settings"
              search={{ section: proxmox ? "proxmox" : "xdr" }}
              className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
            >
              <Settings aria-hidden="true" className="size-4" />
              {t(proxmox ? "proxmox.manage" : "xdr.manage")}
            </Link>
          ) : canEdit ? (
            <>
              <Button variant="outline" onClick={() => setSearch({ import: "1" })}>
                <Upload aria-hidden="true" className="size-4" />
                {t("servers.importCsv")}
              </Button>
              <Button onClick={() => setSearch({ add: "1" })}>
                <Plus aria-hidden="true" className="size-4" />
                {t("servers.add")}
              </Button>
            </>
          ) : null
        }
      />

      <div className="mb-4">
        <Segmented
          label={t("proxmox.viewLabel")}
          value={proxmox ? "proxmox" : wazuh ? "wazuh" : "servers"}
          options={[
            { value: "servers", label: t("proxmox.viewServers") },
            { value: "proxmox", label: t("proxmox.viewProxmox") },
            // Wazuh agents are a source of servers once a Wazuh is connected (ADR 0015).
            ...(xdr.data?.connected || wazuh ? [{ value: "wazuh" as const, label: t("xdr.viewWazuh") }] : []),
          ]}
          onChange={(view) => navigate({ search: view === "servers" ? {} : { view } })}
        />
      </div>

      {proxmox ? (
        <ProxmoxView search={search} setSearch={setSearch} me={me} />
      ) : wazuh ? (
        <>
          <XdrAgents
            state={wazuhState}
            onChange={onWazuhList}
            canEdit={canEdit}
            onAddAsServer={setAddingAgent}
            title={t("xdr.agentsTitle")}
            description={t("xdr.viewWazuhDescription")}
          />
          {canEdit ? (
            <AddServerWizard
              open={addingAgent !== null}
              me={me}
              prefill={
                addingAgent
                  ? agentPrefill(addingAgent, wazuhConnection.data?.connection?.name ?? "")
                  : undefined
              }
              onClose={() => setAddingAgent(null)}
            />
          ) : null}
        </>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Segmented
              label={t("servers.statusFilter")}
              value={search.status ?? "all"}
              options={STATUSES.map((s) => ({
                value: s,
                label: t(`servers.status.${s}`),
                count: counts.data ? counts.data[s] : null,
              }))}
              onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
            />
            <SearchInput
              className="ml-auto"
              label={t("servers.search")}
              value={search.q ?? ""}
              onChange={(q) => setSearch({ q: q || undefined }, true)}
            />
          </div>

          <Card>
            <table className="w-full text-left">
              <thead className="text-sm text-muted-foreground">
                <tr className="border-b">
                  <SortHeader
                    column="name"
                    label={t("servers.columnServer")}
                    natural="asc"
                    className="px-5"
                    {...sortProps}
                  />
                  <SortHeader
                    column="os"
                    label={t("servers.columnSystem")}
                    natural="asc"
                    className="hidden px-3 @wide:table-cell"
                    {...sortProps}
                  />
                  {SEVERITY_COLUMNS.map((severity) => (
                    <SortHeader
                      key={severity}
                      column={severity}
                      label={t(`severity.${severity}`)}
                      natural="desc"
                      align="right"
                      className="px-3"
                      {...sortProps}
                    />
                  ))}
                  <SortHeader
                    column="updates"
                    label={t("servers.columnUpdates")}
                    natural="desc"
                    align="right"
                    className="px-3"
                    {...sortProps}
                  />
                  <SortHeader
                    column="packages"
                    label={t("servers.columnPackages")}
                    natural="desc"
                    align="right"
                    className="hidden px-3 @xwide:table-cell"
                    {...sortProps}
                  />
                  <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">
                    {t("servers.columnHostKey")}
                  </th>
                  <SortHeader
                    column="lastInventory"
                    label={t("servers.columnLastInventory")}
                    natural="desc"
                    className="hidden px-3 @3xl:table-cell"
                    {...sortProps}
                  />
                  <th className="px-3 py-2.5 font-medium">{t("servers.columnStatus")}</th>
                  {canEdit ? (
                    <th className="w-14 px-5 py-2.5 text-right font-medium">
                      <span className="sr-only">{t("servers.columnActions")}</span>
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((host) => (
                  <ServerRowView key={host.id} host={host} canEdit={canEdit} email={me.user.email} />
                ))}
              </tbody>
            </table>
            <QueryStatus query={query} />
            {query.data && query.data.items.length === 0 ? (
              <p className="px-5 py-6 text-muted-foreground">
                {search.q || search.status ? t("servers.noMatch") : t("servers.empty")}
              </p>
            ) : null}
            {query.data ? (
              <Pagination
                page={query.data}
                onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
                onPageSize={(pageSize) => setSearch({ pageSize })}
              />
            ) : null}
          </Card>

          {canEdit ? (
            <>
              <AddServerWizard
                open={search.add !== undefined}
                hostId={search.add && search.add !== "1" ? search.add : null}
                me={me}
                onClose={() => setSearch({ add: undefined }, true)}
              />
              <ImportServersDialog
                open={search.import === "1"}
                me={me}
                onClose={() => setSearch({ import: undefined }, true)}
              />
              {keyHost ? (
                <HostKeyDialog
                  host={keyHost}
                  email={me.user.email}
                  open
                  onClose={() => setSearch({ key: undefined }, true)}
                />
              ) : null}
            </>
          ) : null}
        </>
      )}
    </>
  );
}

function ServerRowView({ host, canEdit, email }: { host: HostRow; canEdit: boolean; email: string }) {
  const { t } = useTranslation();
  const hostError = useHostErrorText();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const stepUp = useStepUp(email);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removeFailed, setRemoveFailed] = useState(false);
  const refresh = () => queryClient.invalidateQueries();

  const inventory = useMutation({
    mutationFn: () => api(`/hosts/${host.id}/inventory`, { method: "POST" }),
    onSuccess: refresh,
  });
  const lookAgain = useMutation({
    mutationFn: () => api(`/hosts/${host.id}/host-key/scan`, { method: "POST" }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: () => api(`/hosts/${host.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setConfirmRemove(false);
      await refresh();
    },
    onError: (e) => {
      if (stepUp.handled(e, () => remove.mutate())) return setConfirmRemove(false);
      setRemoveFailed(true);
    },
  });

  const state = serverState(host);
  const busy = state.key === "queued" || state.key === "running";
  const when = host.lastInventoryAt;
  const hasCandidate = Boolean(host.hostKey.candidate);

  const actions: MenuAction[] = [];
  if (canEdit) {
    if (host.hostKey.status === "confirmed") {
      actions.push({
        label: t("servers.runInventory"),
        icon: Play,
        disabled: busy || inventory.isPending,
        onSelect: () => inventory.mutate(),
      });
    }
    if (hasCandidate) {
      actions.push({
        label: t("servers.confirmKey"),
        icon: Fingerprint,
        onSelect: () => void navigate({ to: "/servers", search: (prev) => ({ ...prev, key: host.id }) }),
      });
    }
    if (host.hostKey.status !== "confirmed") {
      actions.push({
        label: t("servers.setUp"),
        icon: Wrench,
        onSelect: () => void navigate({ to: "/servers", search: (prev) => ({ ...prev, add: host.id }) }),
      });
    }
    actions.push({
      label: t("servers.lookAgain"),
      icon: ShieldAlert,
      disabled: lookAgain.isPending,
      onSelect: () => lookAgain.mutate(),
    });
    actions.push({
      label: t("servers.remove"),
      icon: Trash2,
      destructive: true,
      onSelect: () => {
        setRemoveFailed(false);
        setConfirmRemove(true);
      },
    });
  }

  return (
    <tr
      className="row-link border-b align-top last:border-0"
      onClick={rowClick(() => void navigate({ to: "/servers/$id", params: { id: host.id } }))}
    >
      {/* The name column takes what the others leave and truncates, so a long address never pushes the table past its card. */}
      <td className="w-full max-w-0 px-5 py-3 @wide:w-auto @wide:max-w-none">
        <div className="flex min-w-0 items-start gap-2.5">
          <Server aria-hidden="true" className="mt-1 size-4 flex-none text-muted-foreground" />
          <div className="min-w-0">
            <Link
              to="/servers/$id"
              params={{ id: host.id }}
              className="font-medium break-all hover:underline"
            >
              {host.name}
            </Link>
            <div
              className="max-w-[32ch] truncate font-mono text-sm text-muted-foreground @xwide:max-w-[52ch]"
              title={host.address}
            >
              {host.address}
              {host.port === 22 ? "" : `:${host.port}`}
            </div>
            {host.proxmox ? (
              <div className="mt-0.5">
                <Link
                  to="/servers"
                  search={{ view: "proxmox", guest: host.proxmox.guestId }}
                  className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
                  title={t("proxmox.linkedTitle", {
                    guest: host.proxmox.name,
                    cluster: host.proxmox.clusterName,
                  })}
                >
                  <Boxes aria-hidden="true" className="size-3.5" />
                  {t("proxmox.linkedBadge", {
                    type: t(`proxmox.typeShort.${host.proxmox.type}`),
                    vmid: host.proxmox.vmid,
                  })}
                </Link>
              </div>
            ) : null}
            {/* Narrow content has no system column; the system moves under the name instead of disappearing. */}
            <div className="text-sm text-muted-foreground @wide:hidden">{host.os.name ?? ""}</div>
          </div>
        </div>
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        {host.os.name ?? <span className="text-muted-foreground">–</span>}
      </td>
      {SEVERITY_COLUMNS.map((severity) => {
        const n = host.open[severity] ?? 0;
        return (
          <td key={severity} className="px-3 py-3 text-right tabular-nums">
            <span
              title={t("servers.openOfSeverity", { count: n, severity: t(`severity.${severity}`) })}
              className={cn(COUNT_PILL, n > 0 ? BADGE_TONE[severity] : "font-normal text-muted-foreground")}
            >
              {formatNumber(n)}
            </span>
          </td>
        );
      })}
      <td className="px-3 py-3 text-right tabular-nums">
        {host.pendingUpdates === null ? (
          <span className="text-muted-foreground">–</span>
        ) : host.pendingUpdates === 0 ? (
          <span className="text-muted-foreground">0</span>
        ) : (
          <>
            {formatNumber(host.pendingUpdates)}
            {host.securityUpdates ? (
              <div className="text-sm text-muted-foreground">
                {t("servers.securityUpdates", { count: host.securityUpdates })}
              </div>
            ) : null}
          </>
        )}
      </td>
      <td className="hidden px-3 py-3 text-right tabular-nums @xwide:table-cell">
        {host.packageCount === null ? (
          <span className="text-muted-foreground">–</span>
        ) : (
          formatNumber(host.packageCount)
        )}
      </td>
      <td className="hidden px-3 py-3 @xwide:table-cell">
        {host.hostKey.status === "changed" ? (
          <Badge tone="critical">{t("servers.hostKeyState.changed")}</Badge>
        ) : (
          <span className="text-muted-foreground">{t(`servers.hostKeyState.${host.hostKey.status}`)}</span>
        )}
      </td>
      <td className="hidden px-3 py-3 @3xl:table-cell">
        {when ? (
          <time dateTime={when} title={formatDateTime(when)} className="dash-time text-sm">
            {formatRelative(when)}
          </time>
        ) : (
          <span className="text-muted-foreground">–</span>
        )}
      </td>
      <td className="px-3 py-3">
        <Badge tone={state.tone}>
          {state.key === "hostKeyChanged" ? <ShieldAlert aria-hidden="true" /> : null}
          {t(`servers.state.${state.key}`)}
        </Badge>
        {(state.key === "failed" || state.key === "hostKeyChanged") && host.lastError ? (
          <div className="mt-1 max-w-[36ch] text-sm text-destructive-text">{hostError(host.lastError)}</div>
        ) : null}
        {/* Narrow content has no last-inventory column; the time moves here. */}
        {when && !busy ? (
          <time dateTime={when} className="mt-1 block text-sm text-muted-foreground @3xl:hidden">
            {formatRelative(when)}
          </time>
        ) : null}
      </td>
      {canEdit ? (
        <td className="px-5 py-2 text-right">
          <ActionMenu label={t("servers.moreActions", { name: host.name })} actions={actions} />
          {inventory.isError || lookAgain.isError ? (
            <p role="alert" className="mt-1.5 text-right text-sm text-destructive-text">
              {t("errors.actionFailed")}
            </p>
          ) : null}
          <ConfirmDialog
            open={confirmRemove}
            title={t("servers.removeTitle", { name: host.name })}
            description={t("servers.removeDescription")}
            confirmLabel={t("servers.remove")}
            pending={remove.isPending}
            error={removeFailed ? t("errors.actionFailed") : null}
            onConfirm={() => remove.mutate()}
            onClose={() => setConfirmRemove(false)}
          />
          {stepUp.dialog}
        </td>
      ) : null}
    </tr>
  );
}
