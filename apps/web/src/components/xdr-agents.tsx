import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { TFunction } from "i18next";
import { Check, Link2, Link2Off, Server } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { toQuery } from "../lib/search.ts";
import type { HostRow, Page, XdrAgent, XdrAgentStatus } from "../lib/types.ts";
import { AGENT_STATUS_TONE, XDR_SEVERITIES } from "../lib/xdr.ts";
import type { ServerPrefill } from "./add-server-wizard.tsx";
import { SearchInput, Segmented } from "./filters.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { Pagination } from "./pagination.tsx";
import { QueryStatus } from "./query-state.tsx";
import { type SortDir, SortHeader } from "./sort-header.tsx";
import { ActionMenu, type MenuAction } from "./ui/action-menu.tsx";
import { Alert } from "./ui/alert.tsx";
import { BADGE_TONE, Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Select } from "./ui/select.tsx";

/** What the agent list is filtered and sorted by; the pages keep it in their own URL parameters. */
export interface AgentListState {
  q?: string | undefined;
  status?: XdrAgentStatus | undefined;
  link?: "linked" | "unlinked" | "suggested" | undefined;
  group?: string | undefined;
  sort?: string | undefined;
  dir?: SortDir | undefined;
  cursor?: string | undefined;
  pageSize?: number | undefined;
}

const COUNT_PILL = "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold";
const STATUSES = ["all", "active", "disconnected", "never_connected", "pending"] as const;
const LINKS = ["all", "linked", "unlinked", "suggested"] as const;

/** The text for a refused link request. */
function linkError(t: TFunction, e: unknown): string {
  if (e instanceof ApiError && e.code === "already-linked") return t("xdr.linkErrors.alreadyLinked");
  if (e instanceof ApiError && e.code === "manager-agent") return t("xdr.linkErrors.manager");
  return t("xdr.linkErrors.generic");
}

/** The add-server flow, started from a Wazuh agent: its name and address, linked to the agent on creation (ADR 0015). */
export function agentPrefill(agent: XdrAgent, connectionName: string): ServerPrefill {
  return {
    name: agent.name,
    address: agent.ip ?? "",
    addresses: agent.ip ? [agent.ip] : [],
    source: "wazuh",
    sourceRef: `${agent.connectionId}:${agent.agentId}`,
    origin: { agent: agent.name, connection: connectionName },
  };
}

const Dash = () => <span className="text-muted-foreground">–</span>;

/**
 * The agents of the connected Wazuh (ADR 0015), sortable and filterable. Used on the XDR page and
 * in the Wazuh view of the Servers page. Owners and admins link an agent to a server here: a
 * suggestion (same address or name) is only ever confirmed by a person.
 */
export function XdrAgents({
  state,
  onChange,
  canEdit,
  onAddAsServer,
  title,
  description,
}: {
  state: AgentListState;
  onChange: (patch: AgentListState, replace?: boolean) => void;
  canEdit: boolean;
  /** Opens the add-server flow for this agent. */
  onAddAsServer: (agent: XdrAgent) => void;
  title: string;
  description: string;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [linking, setLinking] = useState<XdrAgent | null>(null);
  const [unlinking, setUnlinking] = useState<XdrAgent | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  const filters = { q: state.q, link: state.link, group: state.group };
  const agents = useQuery({
    queryKey: ["xdr-agents", state],
    queryFn: () =>
      api<Page<XdrAgent>>(
        `/xdr/agents${toQuery({
          ...filters,
          status: state.status,
          sort: state.sort,
          dir: state.dir,
          cursor: state.cursor,
          pageSize: state.pageSize,
        })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const counts = useQuery({
    queryKey: ["xdr-agent-counts", filters],
    queryFn: () => api<Record<string, number>>(`/xdr/agents/counts${toQuery(filters)}`),
    placeholderData: keepPreviousData,
  });
  const refresh = () =>
    queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("xdr-") });
  const confirm = useMutation({
    mutationFn: (input: { id: string; hostId: string }) =>
      api(`/xdr/agents/${input.id}/link`, { method: "POST", body: { hostId: input.hostId } }),
    onMutate: () => setFailed(null),
    onSuccess: refresh,
    onError: (e) => setFailed(linkError(t, e)),
  });
  const unlink = useMutation({
    mutationFn: (id: string) => api(`/xdr/agents/${id}/link`, { method: "DELETE" }),
    onSuccess: async () => {
      setUnlinking(null);
      await refresh();
    },
  });

  const sortProps = {
    current: state.sort,
    dir: state.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      onChange({ sort, dir, cursor: undefined }),
  };
  const filter = (patch: AgentListState, replace = false) =>
    onChange({ cursor: undefined, ...patch }, replace);
  const hasFilter = Boolean(state.q || state.status || state.link || state.group);
  const columns = canEdit ? 9 : 8;

  return (
    <Card>
      <CardHeader title={title} description={description} />
      <div className="flex flex-wrap items-center gap-3 px-5 pb-4">
        <Segmented
          label={t("xdr.statusFilter")}
          value={state.status ?? "all"}
          options={STATUSES.map((s) => ({
            value: s,
            label: t(`xdr.status.${s}`),
            count: counts.data ? (counts.data[s] ?? 0) : null,
          }))}
          onChange={(status) => filter({ status: status === "all" ? undefined : status })}
        />
        <label className="inline-flex items-center gap-2 text-sm text-muted-foreground">
          {t("xdr.linkFilter")}
          <Select
            aria-label={t("xdr.linkFilter")}
            className="h-9 text-sm"
            value={state.link ?? "all"}
            onChange={(e) => {
              const v = e.currentTarget.value;
              filter({ link: v === "all" ? undefined : (v as AgentListState["link"]) });
            }}
          >
            {LINKS.map((l) => (
              <option key={l} value={l}>
                {t(`xdr.link.${l}`)}
              </option>
            ))}
          </Select>
        </label>
        <SearchInput
          className="ml-auto"
          label={t("xdr.search")}
          value={state.q ?? ""}
          onChange={(q) => filter({ q: q || undefined }, true)}
        />
      </div>
      {failed ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{failed}</Alert>
        </div>
      ) : null}
      <table className="w-full border-t text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="name"
              label={t("xdr.columnName")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("xdr.columnIp")}</th>
            <SortHeader
              column="os"
              label={t("xdr.columnSystem")}
              natural="asc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="version"
              label={t("xdr.columnVersion")}
              natural="desc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="status"
              label={t("xdr.columnStatus")}
              natural="asc"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="keepAlive"
              label={t("xdr.columnKeepAlive")}
              natural="desc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">{t("xdr.columnGroups")}</th>
            <SortHeader
              column="vulnerabilities"
              label={t("xdr.columnVulnerabilities")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <th className="px-3 py-2.5 font-medium">{t("xdr.columnServer")}</th>
            {canEdit ? (
              <th className="w-14 px-5 py-2.5 text-right font-medium">
                <span className="sr-only">{t("xdr.columnActions")}</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {agents.data?.items.map((agent) => (
            <AgentRow
              key={agent.id}
              agent={agent}
              canEdit={canEdit}
              onConfirm={() =>
                agent.suggestion && confirm.mutate({ id: agent.id, hostId: agent.suggestion.hostId })
              }
              confirming={confirm.isPending}
              onLink={() => setLinking(agent)}
              onUnlink={() => setUnlinking(agent)}
              onAddAsServer={() => onAddAsServer(agent)}
            />
          ))}
        </tbody>
        {agents.data && agents.data.items.length === 0 ? (
          <tbody>
            <tr>
              <td colSpan={columns} className="px-5 py-6 text-muted-foreground">
                {hasFilter ? t("xdr.noMatch") : t("xdr.noAgents")}
              </td>
            </tr>
          </tbody>
        ) : null}
      </table>
      <QueryStatus query={agents} />
      {agents.data ? (
        <Pagination
          page={agents.data}
          onCursor={(cursor) => onChange({ cursor })}
          onPageSize={(pageSize) => onChange({ pageSize, cursor: undefined })}
        />
      ) : null}
      {linking ? <LinkDialog agent={linking} onClose={() => setLinking(null)} onLinked={refresh} /> : null}
      <ConfirmDialog
        open={unlinking !== null}
        title={t("xdr.unlinkTitle", { name: unlinking?.name ?? "" })}
        description={t("xdr.unlinkDescription")}
        confirmLabel={t("xdr.unlink")}
        pending={unlink.isPending}
        error={unlink.isError ? t("errors.actionFailed") : null}
        onConfirm={() => unlinking && unlink.mutate(unlinking.id)}
        onClose={() => setUnlinking(null)}
      />
    </Card>
  );
}

function AgentRow({
  agent,
  canEdit,
  onConfirm,
  confirming,
  onLink,
  onUnlink,
  onAddAsServer,
}: {
  agent: XdrAgent;
  canEdit: boolean;
  onConfirm: () => void;
  confirming: boolean;
  onLink: () => void;
  onUnlink: () => void;
  onAddAsServer: () => void;
}) {
  const { t } = useTranslation();
  const v = agent.vulnerabilities;
  const actions: MenuAction[] = [];
  if (canEdit && !agent.isManager) {
    if (agent.server) {
      actions.push({ label: t("xdr.unlink"), icon: Link2Off, onSelect: onUnlink });
    } else {
      actions.push({ label: t("xdr.linkTo"), icon: Link2, onSelect: onLink });
      actions.push({ label: t("xdr.addAsServer"), icon: Server, onSelect: onAddAsServer });
    }
  }
  const system = [agent.os.name, agent.os.version].filter(Boolean).join(" ");
  return (
    <tr className="border-b align-top last:border-0" data-testid={`agent-${agent.agentId}`}>
      <td className="px-5 py-3">
        <div className="font-medium break-all">{agent.name}</div>
        <div className="flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
          <span className="font-mono">{agent.agentId}</span>
          {agent.isManager ? <Badge tone="neutral">{t("xdr.managerAgent")}</Badge> : null}
          {/* Narrow content has no address column; it moves under the name. */}
          {agent.ip ? <span className="font-mono @3xl:hidden">{agent.ip}</span> : null}
        </div>
      </td>
      <td className="hidden px-3 py-3 font-mono text-sm @3xl:table-cell">{agent.ip ?? <Dash />}</td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        {system || <Dash />}
        {agent.arch ? <div className="text-sm text-muted-foreground">{agent.arch}</div> : null}
      </td>
      <td className="hidden px-3 py-3 font-mono text-sm @xwide:table-cell">{agent.version ?? <Dash />}</td>
      <td className="px-3 py-3">
        <Badge tone={AGENT_STATUS_TONE[agent.status]}>{t(`xdr.status.${agent.status}`)}</Badge>
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        {agent.lastKeepAliveAt ? (
          <time
            dateTime={agent.lastKeepAliveAt}
            title={formatDateTime(agent.lastKeepAliveAt)}
            className="text-sm"
          >
            {formatRelative(agent.lastKeepAliveAt)}
          </time>
        ) : (
          <span className="text-sm text-muted-foreground">{t("xdr.noKeepAlive")}</span>
        )}
      </td>
      <td className="hidden px-3 py-3 @xwide:table-cell">
        {agent.groups.length > 0 ? (
          <span className="text-sm break-words">{agent.groups.join(", ")}</span>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-3 py-3 text-right">
        {v ? (
          <span className="inline-flex gap-1">
            {XDR_SEVERITIES.slice(0, 3).map((s) => (
              <span
                key={s}
                title={`${formatNumber(v[s])} ${t(`severity.${s}`)}`}
                className={cn(
                  COUNT_PILL,
                  "tabular-nums",
                  v[s] > 0 ? BADGE_TONE[s] : "font-normal text-muted-foreground",
                )}
              >
                <span className="sr-only">{t(`severity.${s}`)} </span>
                {formatNumber(v[s])}
              </span>
            ))}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground" title={t("xdr.noVulnerabilityData")}>
            –
          </span>
        )}
      </td>
      <td className="px-3 py-3">
        {agent.server ? (
          <Link
            to="/servers/$id"
            params={{ id: agent.server.id }}
            className="inline-flex items-center gap-1.5 break-all hover:underline"
            title={t("xdr.serverLinked", { name: agent.server.name })}
          >
            <Server aria-hidden="true" className="size-3.5 flex-none text-muted-foreground" />
            {agent.server.name}
          </Link>
        ) : agent.suggestion ? (
          <div className="grid justify-items-start gap-1">
            <span className="text-sm">
              {t("xdr.serverSuggested", { name: agent.suggestion.hostName })}
              {agent.suggestion.reason ? (
                <span className="text-muted-foreground">
                  {" "}
                  ({t(`xdr.suggestionReason.${agent.suggestion.reason}`)})
                </span>
              ) : null}
            </span>
            {canEdit ? (
              <Button
                variant="outline"
                className="h-8 px-2.5 text-sm"
                disabled={confirming}
                onClick={onConfirm}
              >
                <Check aria-hidden="true" className="size-3.5" />
                {t("xdr.confirmLink")}
              </Button>
            ) : null}
          </div>
        ) : (
          <Dash />
        )}
      </td>
      {canEdit ? (
        <td className="px-5 py-2 text-right">
          <ActionMenu label={t("servers.moreActions", { name: agent.name })} actions={actions} />
        </td>
      ) : null}
    </tr>
  );
}

/** Pick the server that is the machine behind an agent. The admin decides; nothing is linked by itself. */
function LinkDialog({
  agent,
  onClose,
  onLinked,
}: {
  agent: XdrAgent;
  onClose: () => void;
  onLinked: () => Promise<unknown>;
}) {
  const { t } = useTranslation();
  const [hostId, setHostId] = useState(agent.suggestion?.hostId ?? "");
  const [error, setError] = useState<string | null>(null);
  const hosts = useQuery({
    queryKey: ["xdr-link-hosts"],
    queryFn: () => api<Page<HostRow>>("/hosts?pageSize=100&sort=name"),
  });
  const save = useMutation({
    mutationFn: () => api(`/xdr/agents/${agent.id}/link`, { method: "POST", body: { hostId } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await onLinked();
      onClose();
    },
    onError: (e) => setError(linkError(t, e)),
  });
  return (
    <Dialog
      open
      onClose={onClose}
      title={t("xdr.linkTitle", { name: agent.name })}
      description={t("xdr.linkDescription")}
    >
      <div className="grid gap-4">
        {error ? <Alert tone="error">{error}</Alert> : null}
        <label className="grid gap-1.5">
          <span className="text-sm font-medium">{t("xdr.linkChoose")}</span>
          <Select className="w-full" value={hostId} onChange={(e) => setHostId(e.currentTarget.value)}>
            <option value="">{t("xdr.linkNone")}</option>
            {hosts.data?.items.map((h) => (
              <option key={h.id} value={h.id}>
                {h.name} ({h.address})
              </option>
            ))}
          </Select>
        </label>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button disabled={!hostId || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? t("common.loading") : t("xdr.linkSave")}
          </Button>
        </DialogFooter>
      </div>
    </Dialog>
  );
}
