import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ArchiveX,
  Boxes,
  Clock,
  EyeOff,
  type LucideIcon,
  PowerOff,
  RefreshCw,
  Settings,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatBytes, formatDateTime, formatDuration, formatNumber, formatRelative } from "../lib/format.ts";
import { FLAG_ORDER, FLAG_TONE, usage, useProxmoxErrorText } from "../lib/proxmox.ts";
import { rowClick } from "../lib/row-link.ts";
import { type ServerSearch, toQuery } from "../lib/search.ts";
import type { Me } from "../lib/session.ts";
import type {
  Page,
  ProxmoxCluster,
  ProxmoxClusters,
  ProxmoxFlag,
  ProxmoxGuest,
  ProxmoxNode,
  ProxmoxStorage,
} from "../lib/types.ts";
import { AddServerWizard } from "./add-server-wizard.tsx";
import { SearchInput, Segmented } from "./filters.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { Pagination } from "./pagination.tsx";
import { QueryStatus } from "./query-state.tsx";
import { type SortDir, SortHeader } from "./sort-header.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge, type BadgeTone } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Select } from "./ui/select.tsx";

const FLAG_ICON: Record<ProxmoxFlag, LucideIcon> = {
  stoppedLong: PowerOff,
  noRecentBackup: ArchiveX,
  oldSnapshot: Clock,
  untracked: EyeOff,
};

const STATUS_TONE: Record<ProxmoxGuest["status"], BadgeTone> = {
  running: "neutral",
  stopped: "neutral",
  paused: "info",
  other: "neutral",
};

const FILTER_KEYS = ["pxQ", "pxCluster", "pxType", "pxStatus", "pxNode", "pxFlag"] as const;

/** Query of the guest list and its counts, from the URL. */
function guestFilters(search: ServerSearch) {
  return {
    q: search.pxQ,
    cluster: search.pxCluster,
    type: search.pxType,
    status: search.pxStatus,
    node: search.pxNode,
  };
}

/** A figure that may be unknown. */
const Dash = () => <span className="text-muted-foreground">–</span>;

/** "1.2 GiB" with the share in percent beneath, for a used/total pair. */
function Usage({ used, total }: { used: number | null; total: number | null }) {
  const share = usage(used, total);
  if (used === null && total === null) return <Dash />;
  return (
    <div className="tabular-nums">
      <div>{used !== null ? formatBytes(used) : "–"}</div>
      {total !== null ? (
        <div className="text-sm text-muted-foreground">
          {share !== null ? `${Math.round(share * 100)} % · ` : ""}
          {formatBytes(total)}
        </div>
      ) : null}
    </div>
  );
}

/** The Proxmox tab of the Servers page (ADR 0012): clusters, nodes, storage and guests, all read-only. */
export function ProxmoxView({
  search,
  setSearch,
  me,
}: {
  search: ServerSearch;
  setSearch: (patch: Partial<ServerSearch>, replace?: boolean) => void;
  me: Me;
}) {
  const { t } = useTranslation();
  const canEdit = me.role === "owner" || me.role === "admin";
  const clusters = useQuery({
    queryKey: ["px-clusters"],
    queryFn: () => api<ProxmoxClusters>("/proxmox/clusters"),
    // Follow the worker while a sync is waiting or running.
    refetchInterval: (q) =>
      q.state.data?.items.some((c) => c.run?.state === "queued" || c.run?.state === "running")
        ? 3000
        : 60_000,
  });

  if (clusters.data && clusters.data.items.length === 0) {
    return (
      <Card>
        <div className="grid justify-items-start gap-3 px-5 py-6">
          <p className="max-w-[60ch] text-muted-foreground">
            {canEdit ? t("proxmox.emptyAdmin") : t("proxmox.emptyMember")}
          </p>
          {canEdit ? (
            <Link
              to="/settings"
              search={{ section: "proxmox" }}
              className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground hover:bg-primary/90"
            >
              <Boxes aria-hidden="true" className="size-4" />
              {t("proxmox.connect")}
            </Link>
          ) : null}
        </div>
      </Card>
    );
  }
  if (!clusters.data) {
    return (
      <Card>
        <QueryStatus query={clusters} />
      </Card>
    );
  }
  const data = clusters.data;
  const multiple = data.items.length > 1;
  return (
    <div className="grid gap-4">
      <ClusterCards clusters={data.items} canEdit={canEdit} />
      <div className="grid items-start gap-4 @wide:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <NodesCard multiple={multiple} />
        <StorageCard multiple={multiple} />
      </div>
      <GuestsCard data={data} search={search} setSearch={setSearch} me={me} canEdit={canEdit} />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Clusters                                                                    */
/* -------------------------------------------------------------------------- */

function ClusterCards({ clusters, canEdit }: { clusters: ProxmoxCluster[]; canEdit: boolean }) {
  return (
    <div className="grid gap-4 @wide:grid-cols-2 @xwide:grid-cols-3">
      {clusters.map((cluster) => (
        <ClusterCard key={cluster.id} cluster={cluster} canEdit={canEdit} />
      ))}
    </div>
  );
}

function ClusterCard({ cluster, canEdit }: { cluster: ProxmoxCluster; canEdit: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useProxmoxErrorText();
  const sync = useMutation({
    mutationFn: () => api(`/proxmox/clusters/${cluster.id}/sync`, { method: "POST" }),
    onSuccess: () =>
      queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("px-") }),
  });
  const busy = cluster.run?.state === "queued" || cluster.run?.state === "running";
  const c = cluster.counts;
  const failed = cluster.lastError ?? (cluster.run?.state === "failed" ? cluster.run.error : null);
  const needsAttention = cluster.certificate.status !== "confirmed" || !cluster.privileges.acknowledged;
  return (
    <Card>
      <CardHeader
        title={cluster.name}
        description={
          cluster.version
            ? `${t("proxmox.clusterVersion", { version: cluster.version })} · ${
                cluster.clusterName ? cluster.clusterName : t("proxmox.standalone")
              }`
            : cluster.host
        }
        actions={
          canEdit && cluster.certificate.status === "confirmed" ? (
            <Button
              variant="outline"
              className="h-9"
              disabled={busy || sync.isPending}
              onClick={() => sync.mutate()}
            >
              <RefreshCw aria-hidden="true" className={cn("size-4", busy && "motion-safe:animate-spin")} />
              {busy ? t("proxmox.syncing") : t("proxmox.syncNow")}
            </Button>
          ) : null
        }
      />
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 px-5 pb-4 @xwide:grid-cols-2">
        <Figure label={t("proxmox.figureNodes")} value={`${c.online} / ${c.nodes}`} />
        <Figure
          label={t("proxmox.figureGuests")}
          value={`${c.running} / ${c.guests}`}
          hint={t("proxmox.figureRunning")}
        />
        <Figure label={t("proxmox.figureStale")} value={formatNumber(c.stale)} />
        <Figure label={t("proxmox.figureUntracked")} value={formatNumber(c.untracked)} />
        <Figure
          label={t("proxmox.figureUpdates")}
          value={formatNumber(c.withUpdates)}
          hint={c.updates > 0 ? t("proxmox.updatesCount", { count: c.updates }) : undefined}
        />
        <div>
          <dt className="text-sm text-muted-foreground">{t("proxmox.figureSync")}</dt>
          <dd className="font-medium">
            {cluster.lastSyncAt ? (
              <time dateTime={cluster.lastSyncAt} title={formatDateTime(cluster.lastSyncAt)}>
                {formatRelative(cluster.lastSyncAt)}
              </time>
            ) : (
              t("proxmox.neverSynced")
            )}
          </dd>
        </div>
      </dl>
      <div className="grid gap-2 border-t px-5 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <CertificateBadge status={cluster.certificate.status} />
          {cluster.quorate === false ? <Badge tone="critical">{t("proxmox.noQuorum")}</Badge> : null}
          {!cluster.privileges.acknowledged ? (
            <Badge tone="critical">
              <ShieldAlert aria-hidden="true" />
              {t("proxmox.privilegesBadge")}
            </Badge>
          ) : null}
          {!cluster.enabled ? <Badge tone="neutral">{t("proxmox.disabled")}</Badge> : null}
        </div>
        {failed ? <p className="text-sm text-destructive-text">{errorText(failed)}</p> : null}
        {needsAttention && canEdit ? (
          <Link
            to="/settings"
            search={{ section: "proxmox" }}
            className="inline-flex w-fit items-center gap-1.5 text-sm hover:underline"
          >
            <Settings aria-hidden="true" className="size-3.5" />
            {t("proxmox.finishSetup")}
          </Link>
        ) : null}
        {sync.isError ? <Alert tone="error">{t("errors.actionFailed")}</Alert> : null}
      </div>
    </Card>
  );
}

function Figure({ label, value, hint }: { label: string; value: string; hint?: string | undefined }) {
  return (
    <div>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-xl font-semibold tabular-nums">
        {value}
        {hint ? <span className="ml-1.5 text-sm font-normal text-muted-foreground">{hint}</span> : null}
      </dd>
    </div>
  );
}

/** Pinned is the normal state and neutral: a pinned certificate is not proof of anything (AGENTS.md rule 6). */
export function CertificateBadge({ status }: { status: ProxmoxCluster["certificate"]["status"] }) {
  const { t } = useTranslation();
  const tone: BadgeTone = status === "changed" ? "critical" : status === "pending" ? "info" : "neutral";
  const Icon = status === "changed" ? ShieldAlert : ShieldCheck;
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {t(`proxmox.certificate.${status}`)}
    </Badge>
  );
}

/* -------------------------------------------------------------------------- */
/* Nodes and storage                                                           */
/* -------------------------------------------------------------------------- */

type NodeSort = "name" | "cluster" | "cpu" | "mem" | "disk" | "uptime" | "guests" | "updates";

function NodesCard({ multiple }: { multiple: boolean }) {
  const { t } = useTranslation();
  const nodes = useQuery({
    queryKey: ["px-nodes"],
    queryFn: () => api<ProxmoxNode[]>("/proxmox/nodes"),
    placeholderData: keepPreviousData,
  });
  const [sort, setSort] = useState<{ column: NodeSort | undefined; dir: SortDir | undefined }>({
    column: undefined,
    dir: undefined,
  });
  const value = (n: ProxmoxNode, column: NodeSort): string | number => {
    switch (column) {
      case "name":
        return n.name.toLowerCase();
      case "cluster":
        return n.clusterName.toLowerCase();
      case "cpu":
        return n.cpu ?? -1;
      case "mem":
        return usage(n.mem, n.maxMem) ?? -1;
      case "disk":
        return usage(n.disk, n.maxDisk) ?? -1;
      case "uptime":
        return n.uptime ?? -1;
      case "guests":
        return n.guests;
      case "updates":
        return n.pendingUpdates ?? -1;
    }
  };
  const natural = (column: NodeSort): SortDir => (column === "name" || column === "cluster" ? "asc" : "desc");
  const rows = [...(nodes.data ?? [])];
  if (sort.column) {
    const column = sort.column;
    const direction = (sort.dir ?? natural(column)) === "asc" ? 1 : -1;
    rows.sort((a, b) => {
      const x = value(a, column);
      const y = value(b, column);
      return (x < y ? -1 : x > y ? 1 : 0) * direction;
    });
  }
  const sortProps = {
    current: sort.column,
    dir: sort.dir,
    onSort: (column: string | undefined, dir: SortDir | undefined) =>
      setSort({ column: column as NodeSort | undefined, dir }),
  };
  return (
    <Card>
      <CardHeader title={t("proxmox.nodesTitle")} description={t("proxmox.nodesDescription")} />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="name"
              label={t("proxmox.columnNode")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            {multiple ? (
              <SortHeader
                column="cluster"
                label={t("proxmox.columnCluster")}
                natural="asc"
                className="hidden px-3 @wide:table-cell"
                {...sortProps}
              />
            ) : null}
            <SortHeader
              column="cpu"
              label={t("proxmox.columnCpu")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="mem"
              label={t("proxmox.columnMemory")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="disk"
              label={t("proxmox.columnDisk")}
              natural="desc"
              align="right"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="uptime"
              label={t("proxmox.columnUptime")}
              natural="desc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="guests"
              label={t("proxmox.columnGuests")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="updates"
              label={t("proxmox.columnUpdates")}
              natural="desc"
              align="right"
              className="px-5"
              {...sortProps}
            />
          </tr>
        </thead>
        <tbody>
          {rows.map((node) => (
            <tr key={node.id} className="border-b align-top last:border-0">
              <td className="px-5 py-3">
                <div className="font-medium break-all">{node.name}</div>
                <div className="text-sm text-muted-foreground">
                  {node.online ? (
                    <>
                      {node.pveVersion ? `PVE ${node.pveVersion}` : t("proxmox.nodeOnline")}
                      {node.kernel ? <span className="hidden @xwide:inline"> · {node.kernel}</span> : null}
                    </>
                  ) : (
                    <Badge tone="critical">{t("proxmox.nodeOffline")}</Badge>
                  )}
                </div>
                {/* Columns that appear on wider screens move under the name instead of disappearing. */}
                {node.online ? (
                  <div className="text-sm text-muted-foreground @xwide:hidden">
                    <span className="@wide:hidden">
                      {t("proxmox.columnDisk")}: {node.disk !== null ? formatBytes(node.disk) : "–"} ·{" "}
                    </span>
                    {t("proxmox.columnUptime")}: {node.uptime !== null ? formatDuration(node.uptime) : "–"}
                  </div>
                ) : null}
              </td>
              {multiple ? <td className="hidden px-3 py-3 @wide:table-cell">{node.clusterName}</td> : null}
              <td className="px-3 py-3 text-right tabular-nums">
                {node.online && node.cpu !== null ? (
                  <>
                    {Math.round(node.cpu * 100)} %
                    {node.cpus ? <div className="text-sm text-muted-foreground">{node.cpus} vCPU</div> : null}
                  </>
                ) : (
                  <Dash />
                )}
              </td>
              <td className="px-3 py-3 text-right">
                {node.online ? <Usage used={node.mem} total={node.maxMem} /> : <Dash />}
              </td>
              <td className="hidden px-3 py-3 text-right @wide:table-cell">
                {node.online ? <Usage used={node.disk} total={node.maxDisk} /> : <Dash />}
              </td>
              <td className="hidden px-3 py-3 tabular-nums @xwide:table-cell">
                {node.online && node.uptime !== null ? formatDuration(node.uptime) : <Dash />}
              </td>
              <td className="px-3 py-3 text-right tabular-nums">{formatNumber(node.guests)}</td>
              <td className="px-5 py-3 text-right tabular-nums">
                {node.pendingUpdates === null ? (
                  <span className="text-muted-foreground" title={t("proxmox.updatesUnknown")}>
                    –
                  </span>
                ) : node.pendingUpdates === 0 ? (
                  <span className="text-muted-foreground">0</span>
                ) : (
                  <Badge tone="info">{t("proxmox.updatesCount", { count: node.pendingUpdates })}</Badge>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <QueryStatus query={nodes} />
    </Card>
  );
}

function StorageCard({ multiple }: { multiple: boolean }) {
  const { t } = useTranslation();
  const storage = useQuery({
    queryKey: ["px-storage"],
    queryFn: () => api<ProxmoxStorage[]>("/proxmox/storage"),
    placeholderData: keepPreviousData,
  });
  return (
    <Card>
      <CardHeader title={t("proxmox.storageTitle")} description={t("proxmox.storageDescription")} />
      <table className="w-full text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("proxmox.columnStorage")}</th>
            <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">{t("proxmox.columnType")}</th>
            <th className="px-5 py-2.5 text-right font-medium">{t("proxmox.columnUsed")}</th>
          </tr>
        </thead>
        <tbody>
          {storage.data?.map((s) => (
            <tr key={s.id} className="border-b align-top last:border-0">
              <td className="px-5 py-3">
                <div className="font-medium break-all">{s.name}</div>
                <div className="text-sm text-muted-foreground">
                  {s.type ? <span className="@xwide:hidden">{s.type} · </span> : null}
                  {s.shared ? t("proxmox.storageShared") : s.node}
                  {multiple ? ` · ${s.clusterName}` : ""}
                  {s.status && s.status !== "available" ? ` · ${s.status}` : ""}
                </div>
              </td>
              <td className="hidden px-3 py-3 @xwide:table-cell">
                {s.type ?? <Dash />}
                {s.content.length > 0 ? (
                  <div className="text-sm text-muted-foreground">{s.content.join(", ")}</div>
                ) : null}
              </td>
              <td className="px-5 py-3 text-right">
                <Usage used={s.used} total={s.total} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <QueryStatus query={storage} />
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Guests                                                                      */
/* -------------------------------------------------------------------------- */

function GuestsCard({
  data,
  search,
  setSearch,
  me,
  canEdit,
}: {
  data: ProxmoxClusters;
  search: ServerSearch;
  setSearch: (patch: Partial<ServerSearch>, replace?: boolean) => void;
  me: Me;
  canEdit: boolean;
}) {
  const { t } = useTranslation();
  const filters = guestFilters(search);
  const multiple = data.items.length > 1;
  const guests = useQuery({
    queryKey: ["px-guests", search],
    queryFn: () =>
      api<Page<ProxmoxGuest>>(
        `/proxmox/guests${toQuery({
          ...filters,
          flag: search.pxFlag === "all" ? undefined : search.pxFlag,
          sort: search.pxSort,
          dir: search.pxDir,
          cursor: search.pxCursor,
          pageSize: search.pxPageSize,
        })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const counts = useQuery({
    queryKey: ["px-guest-counts", filters],
    queryFn: () =>
      api<Record<"all" | "stale" | "untracked", number>>(`/proxmox/guests/counts${toQuery(filters)}`),
    placeholderData: keepPreviousData,
  });
  const nodes = useQuery({ queryKey: ["px-nodes"], queryFn: () => api<ProxmoxNode[]>("/proxmox/nodes") });
  const nodeNames = [...new Set((nodes.data ?? []).map((n) => n.name))].sort();

  const sortProps = {
    current: search.pxSort,
    dir: search.pxDir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ pxSort: sort as ServerSearch["pxSort"], pxDir: dir, pxCursor: undefined }),
  };
  const filter = (patch: Partial<ServerSearch>, replace = false) =>
    setSearch({ pxCursor: undefined, ...patch }, replace);
  const selected = search.guest ? guests.data?.items.find((g) => g.id === search.guest) : undefined;
  const hasFilter = FILTER_KEYS.some(
    (k) => search[k] !== undefined && !(k === "pxFlag" && search[k] === "all"),
  );

  return (
    <Card>
      <CardHeader
        title={t("proxmox.guestsTitle")}
        description={t("proxmox.guestsDescription", {
          stoppedDays: data.thresholds.stoppedDays,
          backupDays: data.thresholds.backupDays,
          snapshotDays: data.thresholds.snapshotDays,
        })}
      />
      <div className="flex flex-wrap items-center gap-3 px-5 pb-4">
        <Segmented
          label={t("proxmox.flagFilter")}
          value={search.pxFlag ?? "all"}
          options={(["all", "stale", "untracked"] as const).map((f) => ({
            value: f,
            label: t(`proxmox.flag.${f}`),
            count: counts.data ? counts.data[f] : null,
          }))}
          onChange={(pxFlag) => filter({ pxFlag: pxFlag === "all" ? undefined : pxFlag })}
        />
        {multiple ? (
          <FilterSelect
            label={t("proxmox.clusterFilter")}
            value={search.pxCluster ?? ""}
            allLabel={t("proxmox.allClusters")}
            options={data.items.map((c) => ({ value: c.id, label: c.name }))}
            onChange={(pxCluster) => filter({ pxCluster: pxCluster || undefined })}
          />
        ) : null}
        <FilterSelect
          label={t("proxmox.typeFilter")}
          value={search.pxType ?? ""}
          allLabel={t("proxmox.allTypes")}
          options={(["qemu", "lxc"] as const).map((v) => ({ value: v, label: t(`proxmox.type.${v}`) }))}
          onChange={(pxType) => filter({ pxType: (pxType || undefined) as ServerSearch["pxType"] })}
        />
        <FilterSelect
          label={t("proxmox.statusFilter")}
          value={search.pxStatus ?? ""}
          allLabel={t("proxmox.allStatuses")}
          options={(["running", "stopped", "paused", "other"] as const).map((v) => ({
            value: v,
            label: t(`proxmox.status.${v}`),
          }))}
          onChange={(pxStatus) => filter({ pxStatus: (pxStatus || undefined) as ServerSearch["pxStatus"] })}
        />
        <FilterSelect
          label={t("proxmox.nodeFilter")}
          value={search.pxNode ?? ""}
          allLabel={t("proxmox.allNodes")}
          options={nodeNames.map((n) => ({ value: n, label: n }))}
          onChange={(pxNode) => filter({ pxNode: pxNode || undefined })}
        />
        <SearchInput
          className="ml-auto"
          label={t("proxmox.search")}
          value={search.pxQ ?? ""}
          onChange={(pxQ) => filter({ pxQ: pxQ || undefined }, true)}
        />
      </div>
      <table className="w-full border-t text-left">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="name"
              label={t("proxmox.columnGuest")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            <SortHeader
              column="node"
              label={t("proxmox.columnNode")}
              natural="asc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="status"
              label={t("proxmox.columnStatus")}
              natural="asc"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="cpu"
              label={t("proxmox.columnCpu")}
              natural="desc"
              align="right"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="mem"
              label={t("proxmox.columnMemory")}
              natural="desc"
              align="right"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="disk"
              label={t("proxmox.columnDisk")}
              natural="desc"
              align="right"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="uptime"
              label={t("proxmox.columnUptime")}
              natural="desc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="lastBackup"
              label={t("proxmox.columnBackup")}
              natural="asc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="snapshot"
              label={t("proxmox.columnSnapshots")}
              natural="asc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <th className="px-3 py-2.5 font-medium">{t("proxmox.columnFlags")}</th>
            {canEdit ? (
              <th className="w-px px-5 py-2.5 text-right font-medium">
                <span className="sr-only">{t("servers.columnActions")}</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {guests.data?.items.map((guest) => (
            <GuestRow
              key={guest.id}
              guest={guest}
              canEdit={canEdit}
              onOpen={() => setSearch({ guest: guest.id }, true)}
              onAdd={() => setSearch({ addGuest: guest.id }, true)}
            />
          ))}
        </tbody>
      </table>
      <QueryStatus query={guests} />
      {guests.data && guests.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">
          {hasFilter ? t("proxmox.noMatch") : t("proxmox.noGuests")}
        </p>
      ) : null}
      {guests.data ? (
        <Pagination
          page={guests.data}
          onCursor={(pxCursor) => setSearch({ pxCursor }, false)}
          onPageSize={(pxPageSize) => setSearch({ pxPageSize, pxCursor: undefined })}
        />
      ) : null}
      {search.guest ? (
        <GuestDialog
          guestId={search.guest}
          prefetched={selected}
          canEdit={canEdit}
          onClose={() => setSearch({ guest: undefined }, true)}
          onAdd={(id) => setSearch({ guest: undefined, addGuest: id }, true)}
        />
      ) : null}
      {canEdit ? (
        <AddGuestWizard
          guestId={search.addGuest}
          me={me}
          onClose={() => setSearch({ addGuest: undefined }, true)}
        />
      ) : null}
    </Card>
  );
}

function FilterSelect({
  label,
  value,
  allLabel,
  options,
  onChange,
}: {
  label: string;
  value: string;
  allLabel: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
}) {
  return (
    <Select
      aria-label={label}
      className="h-9 text-sm"
      value={value}
      onChange={(e) => onChange(e.currentTarget.value)}
    >
      <option value="">{allLabel}</option>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </Select>
  );
}

function FlagBadge({ flag }: { flag: ProxmoxFlag }) {
  const { t } = useTranslation();
  const Icon = FLAG_ICON[flag];
  return (
    <Badge tone={FLAG_TONE[flag]}>
      <Icon aria-hidden="true" />
      {t(`proxmox.flags.${flag}`)}
    </Badge>
  );
}

function GuestRow({
  guest,
  canEdit,
  onOpen,
  onAdd,
}: {
  guest: ProxmoxGuest;
  canEdit: boolean;
  onOpen: () => void;
  onAdd: () => void;
}) {
  const { t } = useTranslation();
  const flags = FLAG_ORDER.filter((f) => guest.flags.includes(f));
  return (
    <tr className="row-link border-b align-top last:border-0" onClick={rowClick(onOpen)}>
      <td className="px-5 py-3">
        <button
          type="button"
          onClick={onOpen}
          aria-label={t("proxmox.openGuest", { name: guest.name })}
          className="max-w-full text-left font-medium break-all hover:underline"
        >
          {guest.name}
        </button>
        <div className="text-sm text-muted-foreground">
          {t(`proxmox.typeShort.${guest.type}`)} {guest.vmid}
          {guest.template ? ` · ${t("proxmox.template")}` : ""}
          <span className="@wide:hidden"> · {guest.node}</span>
          {guest.ostype ? <span className="hidden @wide:inline"> · {guest.ostype}</span> : null}
        </div>
        {guest.server ? (
          <div className="text-sm">
            <Link to="/servers/$id" params={{ id: guest.server.id }} className="hover:underline">
              {t("proxmox.trackedAs", { name: guest.server.name })}
            </Link>
          </div>
        ) : null}
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">{guest.node}</td>
      <td className="px-3 py-3">
        <Badge tone={STATUS_TONE[guest.status]}>{t(`proxmox.status.${guest.status}`)}</Badge>
        {guest.haState ? (
          <div className="mt-1 hidden text-sm text-muted-foreground @wide:block">
            {t("proxmox.haState", { state: guest.haState })}
          </div>
        ) : null}
      </td>
      <td className="hidden px-3 py-3 text-right tabular-nums @wide:table-cell">
        {guest.status === "running" && guest.cpu !== null ? (
          <>
            {Math.round(guest.cpu * 100)} %
            {guest.cpus ? <div className="text-sm text-muted-foreground">{guest.cpus} vCPU</div> : null}
          </>
        ) : (
          <Dash />
        )}
      </td>
      <td className="hidden px-3 py-3 text-right @wide:table-cell">
        {guest.status === "running" ? <Usage used={guest.mem} total={guest.maxMem} /> : <Dash />}
      </td>
      <td className="hidden px-3 py-3 text-right tabular-nums @xwide:table-cell">
        {guest.maxDisk !== null ? formatBytes(guest.maxDisk) : <Dash />}
      </td>
      <td className="hidden px-3 py-3 tabular-nums @xwide:table-cell">
        {guest.status === "running" && guest.uptime ? formatDuration(guest.uptime) : <Dash />}
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        <BackupCell guest={guest} />
      </td>
      <td className="hidden px-3 py-3 @xwide:table-cell">
        <SnapshotCell guest={guest} />
      </td>
      <td className="px-3 py-3">
        {flags.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {flags.map((f) => (
              <FlagBadge key={f} flag={f} />
            ))}
          </div>
        ) : (
          <Dash />
        )}
      </td>
      {canEdit ? (
        <td className="px-5 py-2.5 text-right whitespace-nowrap">
          {!guest.server && !guest.template ? (
            <Button
              variant="outline"
              className="h-8 px-3 text-sm"
              aria-label={t("proxmox.addAsServerFor", { name: guest.name })}
              onClick={onAdd}
            >
              {t("proxmox.addAsServer")}
            </Button>
          ) : null}
        </td>
      ) : null}
    </tr>
  );
}

function BackupCell({ guest }: { guest: ProxmoxGuest }) {
  const { t } = useTranslation();
  if (guest.template) return <Dash />;
  if (guest.backup.lastAt) {
    return (
      <time dateTime={guest.backup.lastAt} title={formatDateTime(guest.backup.lastAt)} className="text-sm">
        {formatRelative(guest.backup.lastAt)}
      </time>
    );
  }
  if (!guest.backup.readable) {
    return (
      <span className="text-sm text-muted-foreground" title={t("proxmox.backupUnknown")}>
        –
      </span>
    );
  }
  return (
    <span className="text-sm">
      {t("proxmox.noBackup")}
      {guest.backup.inJob === false ? (
        <div className="text-muted-foreground">{t("proxmox.notInJob")}</div>
      ) : null}
    </span>
  );
}

function SnapshotCell({ guest }: { guest: ProxmoxGuest }) {
  const { t } = useTranslation();
  const s = guest.snapshots;
  if (s.count === null) return <Dash />;
  if (s.count === 0) return <span className="text-muted-foreground">0</span>;
  return (
    <div className="text-sm">
      {t("proxmox.snapshotCount", { count: s.count })}
      {s.oldestAt ? (
        <div className="text-muted-foreground">
          {t("proxmox.oldest")}: {formatRelative(s.oldestAt)}
        </div>
      ) : null}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Guest dialog and "Add as server"                                            */
/* -------------------------------------------------------------------------- */

function GuestDialog({
  guestId,
  prefetched,
  canEdit,
  onClose,
  onAdd,
}: {
  guestId: string;
  prefetched: ProxmoxGuest | undefined;
  canEdit: boolean;
  onClose: () => void;
  onAdd: (id: string) => void;
}) {
  const { t } = useTranslation();
  const thresholds = useQuery({
    queryKey: ["px-clusters"],
    queryFn: () => api<ProxmoxClusters>("/proxmox/clusters"),
  });
  const guest = useQuery({
    queryKey: ["px-guest", guestId],
    queryFn: () => api<ProxmoxGuest>(`/proxmox/guests/${guestId}`),
    initialData: prefetched,
  });
  const g = guest.data;
  const th = thresholds.data?.thresholds;
  const days = (flag: ProxmoxFlag) =>
    flag === "stoppedLong" ? th?.stoppedDays : flag === "noRecentBackup" ? th?.backupDays : th?.snapshotDays;
  return (
    <Dialog
      open
      onClose={onClose}
      title={g?.name ?? t("common.loading")}
      description={
        g
          ? t("proxmox.guestDescription", {
              type: t(`proxmox.type.${g.type}`),
              vmid: g.vmid,
              node: g.node,
              cluster: g.clusterName,
            })
          : undefined
      }
    >
      {!g ? (
        guest.isError ? (
          <Alert tone="error">{t("errors.loadFailed")}</Alert>
        ) : (
          <p role="status" className="text-muted-foreground">
            {t("common.loading")}
          </p>
        )
      ) : (
        <div className="grid gap-4">
          {g.flags.length > 0 ? (
            <ul className="grid gap-1.5">
              {FLAG_ORDER.filter((f) => g.flags.includes(f)).map((f) => (
                <li key={f} className="flex items-start gap-2 text-sm">
                  <FlagBadge flag={f} />
                  <span className="text-muted-foreground">
                    {t(`proxmox.flagHelp.${f}`, { days: days(f) ?? 0 })}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
            <Fact label={t("proxmox.columnStatus")}>
              {t(`proxmox.status.${g.status}`)}
              {g.statusSince ? (
                <span className="text-muted-foreground">
                  {" "}
                  · {t("proxmox.statusSince", { when: formatRelative(g.statusSince) })}
                </span>
              ) : null}
            </Fact>
            <Fact label={t("proxmox.columnSystem")}>{g.ostype ?? <Dash />}</Fact>
            <Fact label={t("proxmox.columnCpu")}>
              {g.status === "running" && g.cpu !== null ? `${Math.round(g.cpu * 100)} %` : "–"}
              {g.cpus ? ` · ${g.cpus} vCPU` : ""}
            </Fact>
            <Fact label={t("proxmox.columnMemory")}>
              {g.mem !== null && g.status === "running" ? `${formatBytes(g.mem)} / ` : ""}
              {g.maxMem !== null ? formatBytes(g.maxMem) : "–"}
            </Fact>
            <Fact label={t("proxmox.columnDisk")}>{g.maxDisk !== null ? formatBytes(g.maxDisk) : "–"}</Fact>
            <Fact label={t("proxmox.columnUptime")}>
              {g.status === "running" && g.uptime ? formatDuration(g.uptime) : "–"}
            </Fact>
            <Fact label={t("proxmox.columnBackup")}>
              {g.template ? (
                "–"
              ) : g.backup.lastAt ? (
                <>
                  <time dateTime={g.backup.lastAt}>{formatDateTime(g.backup.lastAt)}</time>
                  <span className="text-muted-foreground"> · {formatRelative(g.backup.lastAt)}</span>
                </>
              ) : g.backup.readable ? (
                t("proxmox.noBackup")
              ) : (
                t("proxmox.backupUnknown")
              )}
              {g.backup.inJob !== null && !g.template ? (
                <div className="text-muted-foreground">
                  {g.backup.inJob ? t("proxmox.inJob") : t("proxmox.notInJob")}
                </div>
              ) : null}
            </Fact>
            <Fact label={t("proxmox.columnSnapshots")}>
              {g.snapshots.count === null ? (
                "–"
              ) : (
                <>
                  {t("proxmox.snapshotCount", { count: g.snapshots.count })}
                  {g.snapshots.oldestAt ? (
                    <div className="text-muted-foreground">
                      {t("proxmox.oldest")}: {formatDateTime(g.snapshots.oldestAt)}
                      {g.snapshots.newestAt && g.snapshots.newestAt !== g.snapshots.oldestAt
                        ? ` · ${t("proxmox.newest")}: ${formatDateTime(g.snapshots.newestAt)}`
                        : ""}
                    </div>
                  ) : null}
                </>
              )}
            </Fact>
            <Fact label={t("proxmox.columnHa")}>{g.haState ?? t("proxmox.haNone")}</Fact>
            <Fact label={t("proxmox.columnAddresses")}>
              {g.ips.length > 0 ? (
                <span className="font-mono break-all">{g.ips.join(", ")}</span>
              ) : (
                <span className="text-muted-foreground">{t("proxmox.addressesUnknown")}</span>
              )}
            </Fact>
            <Fact label={t("proxmox.columnTags")}>{g.tags.length > 0 ? g.tags.join(", ") : "–"}</Fact>
            <Fact label={t("proxmox.columnServer")}>
              {g.server ? (
                <Link to="/servers/$id" params={{ id: g.server.id }} className="hover:underline">
                  {g.server.name}
                </Link>
              ) : (
                <span className="text-muted-foreground">{t("proxmox.notTracked")}</span>
              )}
            </Fact>
          </dl>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.close")}
            </Button>
            {canEdit && !g.server && !g.template ? (
              <Button onClick={() => onAdd(g.id)}>{t("proxmox.addAsServer")}</Button>
            ) : null}
          </DialogFooter>
        </div>
      )}
    </Dialog>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </>
  );
}

/** "Add as server" for one guest: the usual wizard (agentless SSH), prefilled from the guest. */
function AddGuestWizard({
  guestId,
  me,
  onClose,
}: {
  guestId: string | undefined;
  me: Me;
  onClose: () => void;
}) {
  const guest = useQuery({
    queryKey: ["px-guest", guestId],
    queryFn: () => api<ProxmoxGuest>(`/proxmox/guests/${guestId}`),
    enabled: Boolean(guestId),
  });
  const g = guest.data;
  return (
    <AddServerWizard
      open={Boolean(guestId) && Boolean(g)}
      me={me}
      onClose={onClose}
      prefill={
        g
          ? {
              name: g.name,
              address: g.ips[0] ?? "",
              addresses: g.ips,
              source: "proxmox",
              sourceRef: `${g.clusterId}:${g.vmid}`,
              origin: { guest: g.name, cluster: g.clusterName, vmid: g.vmid },
            }
          : undefined
      }
    />
  );
}
