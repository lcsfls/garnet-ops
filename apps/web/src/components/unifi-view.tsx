import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  ArrowUpCircle,
  FlaskConical,
  Network,
  RefreshCw,
  Settings,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatDateTime, formatDuration, formatNumber, formatRelative } from "../lib/format.ts";
import { rowClick } from "../lib/row-link.ts";
import { type ServerSearch, toQuery } from "../lib/search.ts";
import type {
  Page,
  UnifiConnection,
  UnifiConnections,
  UnifiDevice,
  UnifiDeviceFlag,
  UnifiSite,
} from "../lib/types.ts";
import { FLAG_ORDER, FLAG_TONE, useUnifiErrorText } from "../lib/unifi.ts";
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

const FILTER_KEYS = ["ufQ", "ufConnection", "ufSite", "ufState", "ufFlag"] as const;

/** Query of the device list and its counts, from the URL. */
function deviceFilters(search: ServerSearch) {
  return {
    q: search.ufQ,
    connection: search.ufConnection,
    site: search.ufSite,
    state: search.ufState,
  };
}

const FLAG_ICON: Record<UnifiDeviceFlag, typeof WifiOff> = {
  offline: WifiOff,
  updateAvailable: ArrowUpCircle,
};

const Dash = () => <span className="text-muted-foreground">–</span>;

/** Pinned is the normal state and neutral: a pinned certificate is not proof of anything (AGENTS.md rule 6). */
export function UnifiCertificateBadge({ status }: { status: UnifiConnection["certificate"]["status"] }) {
  const { t } = useTranslation();
  const tone: BadgeTone = status === "changed" ? "critical" : status === "pending" ? "info" : "neutral";
  const Icon = status === "changed" ? ShieldAlert : ShieldCheck;
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {t(`unifi.certificate.${status}`)}
    </Badge>
  );
}

/** The Network devices tab of the Servers page (ADR 0022): consoles and their devices, all read-only. */
export function UnifiView({
  search,
  setSearch,
  canEdit,
}: {
  search: ServerSearch;
  setSearch: (patch: Partial<ServerSearch>, replace?: boolean) => void;
  canEdit: boolean;
}) {
  const { t } = useTranslation();
  const connections = useQuery({
    queryKey: ["uf-connections"],
    queryFn: () => api<UnifiConnections>("/unifi/connections"),
    // Follow the worker while a sync is waiting or running.
    refetchInterval: (q) =>
      q.state.data?.items.some((c) => c.run?.state === "queued" || c.run?.state === "running")
        ? 3000
        : 60_000,
  });

  if (connections.data && connections.data.items.length === 0) {
    return (
      <Card>
        <div className="grid justify-items-start gap-3 px-5 py-6">
          <p className="max-w-[60ch] text-muted-foreground">
            {canEdit ? t("unifi.emptyAdmin") : t("unifi.emptyMember")}
          </p>
          {canEdit ? (
            <Link
              to="/settings"
              search={{ section: "unifi" }}
              className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground hover:bg-primary/90"
            >
              <Network aria-hidden="true" className="size-4" />
              {t("unifi.connect")}
            </Link>
          ) : null}
        </div>
      </Card>
    );
  }
  if (!connections.data) {
    return (
      <Card>
        <QueryStatus query={connections} />
      </Card>
    );
  }
  const data = connections.data;
  return (
    <div className="grid gap-4">
      <div className="grid gap-4 @wide:grid-cols-2 @xwide:grid-cols-3">
        {data.items.map((connection) => (
          <ConnectionCard key={connection.id} connection={connection} canEdit={canEdit} />
        ))}
      </div>
      <DevicesCard data={data} search={search} setSearch={setSearch} />
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Consoles                                                                    */
/* -------------------------------------------------------------------------- */

function ConnectionCard({ connection, canEdit }: { connection: UnifiConnection; canEdit: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useUnifiErrorText();
  const sync = useMutation({
    mutationFn: () => api(`/unifi/connections/${connection.id}/sync`, { method: "POST" }),
    onSuccess: () =>
      queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("uf-") }),
  });
  const busy = connection.run?.state === "queued" || connection.run?.state === "running";
  const c = connection.counts;
  const failed = connection.lastError ?? (connection.run?.state === "failed" ? connection.run.error : null);
  const needsAttention = connection.certificate.status !== "confirmed";
  return (
    <Card>
      <CardHeader
        title={connection.name}
        description={
          connection.version ? t("unifi.consoleVersion", { version: connection.version }) : connection.host
        }
        actions={
          canEdit && connection.certificate.status === "confirmed" ? (
            <Button
              variant="outline"
              className="h-9"
              disabled={busy || sync.isPending}
              onClick={() => sync.mutate()}
            >
              <RefreshCw aria-hidden="true" className={cn("size-4", busy && "motion-safe:animate-spin")} />
              {busy ? t("unifi.syncing") : t("unifi.syncNow")}
            </Button>
          ) : null
        }
      />
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 px-5 pb-4">
        <Figure label={t("unifi.figureDevices")} value={`${c.online} / ${c.devices}`} />
        <Figure label={t("unifi.figureOffline")} value={formatNumber(c.offline)} />
        <Figure label={t("unifi.figureUpdates")} value={formatNumber(c.updatable)} />
        <Figure label={t("unifi.figureSites")} value={formatNumber(c.sites)} />
        <Figure
          label={t("unifi.figureClients")}
          value={c.clients === null ? "–" : formatNumber(c.clients)}
          title={t("unifi.clientsHint")}
        />
        <div>
          <dt className="text-sm text-muted-foreground">{t("unifi.figureSync")}</dt>
          <dd className="font-medium">
            {connection.lastSyncAt ? (
              <time dateTime={connection.lastSyncAt} title={formatDateTime(connection.lastSyncAt)}>
                {formatRelative(connection.lastSyncAt)}
              </time>
            ) : (
              t("unifi.neverSynced")
            )}
          </dd>
        </div>
      </dl>
      <div className="grid gap-2 border-t px-5 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <UnifiCertificateBadge status={connection.certificate.status} />
          {connection.ips.enabled ? (
            <Badge tone="info">
              <FlaskConical aria-hidden="true" />
              {t("unifi.previewBadge")}
            </Badge>
          ) : null}
          {connection.ips.rights.reported.length > 0 ? (
            <Badge tone={connection.ips.rights.acknowledged ? "neutral" : "critical"}>
              <ShieldAlert aria-hidden="true" />
              {t(connection.ips.rights.acknowledged ? "unifi.rightsAcknowledgedBadge" : "unifi.rightsBadge")}
            </Badge>
          ) : null}
          {!connection.enabled ? <Badge tone="neutral">{t("unifi.disabled")}</Badge> : null}
        </div>
        {failed ? <p className="text-sm text-destructive-text">{errorText(failed)}</p> : null}
        {connection.run?.warnings.length ? (
          <ul className="grid gap-0.5 text-sm text-muted-foreground">
            {connection.run.warnings.map((w) => (
              <li key={w}>{t(`unifi.warnings.${w}` as never)}</li>
            ))}
          </ul>
        ) : null}
        {needsAttention && canEdit ? (
          <Link
            to="/settings"
            search={{ section: "unifi" }}
            className="inline-flex w-fit items-center gap-1.5 text-sm hover:underline"
          >
            <Settings aria-hidden="true" className="size-3.5" />
            {t("unifi.finishSetup")}
          </Link>
        ) : null}
        {sync.isError ? <Alert tone="error">{t("errors.actionFailed")}</Alert> : null}
      </div>
    </Card>
  );
}

function Figure({ label, value, title }: { label: string; value: string; title?: string | undefined }) {
  return (
    <div title={title}>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-xl font-semibold tabular-nums">{value}</dd>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Devices                                                                     */
/* -------------------------------------------------------------------------- */

function DevicesCard({
  data,
  search,
  setSearch,
}: {
  data: UnifiConnections;
  search: ServerSearch;
  setSearch: (patch: Partial<ServerSearch>, replace?: boolean) => void;
}) {
  const { t } = useTranslation();
  const filters = deviceFilters(search);
  const multiple = data.items.length > 1;
  const devices = useQuery({
    queryKey: ["uf-devices", search],
    queryFn: () =>
      api<Page<UnifiDevice>>(
        `/unifi/devices${toQuery({
          ...filters,
          flag: search.ufFlag === "all" ? undefined : search.ufFlag,
          sort: search.ufSort,
          dir: search.ufDir,
          cursor: search.ufCursor,
          pageSize: search.ufPageSize,
        })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const counts = useQuery({
    queryKey: ["uf-device-counts", filters],
    queryFn: () =>
      api<Record<"all" | "offline" | "update", number>>(`/unifi/devices/counts${toQuery(filters)}`),
    placeholderData: keepPreviousData,
  });
  const sites = useQuery({ queryKey: ["uf-sites"], queryFn: () => api<UnifiSite[]>("/unifi/sites") });
  const siteOptions = (sites.data ?? []).filter(
    (s) => !search.ufConnection || s.connectionId === search.ufConnection,
  );

  const sortProps = {
    current: search.ufSort,
    dir: search.ufDir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ ufSort: sort as ServerSearch["ufSort"], ufDir: dir, ufCursor: undefined }),
  };
  const filter = (patch: Partial<ServerSearch>, replace = false) =>
    setSearch({ ufCursor: undefined, ...patch }, replace);
  const selected = search.device ? devices.data?.items.find((d) => d.id === search.device) : undefined;
  const hasFilter = FILTER_KEYS.some(
    (k) => search[k] !== undefined && !(k === "ufFlag" && search[k] === "all"),
  );

  return (
    <Card>
      <CardHeader
        title={t("unifi.devicesTitle")}
        description={t("unifi.devicesDescription", { minutes: data.syncIntervalMinutes })}
      />
      <div className="flex flex-wrap items-center gap-3 px-5 pb-4">
        <Segmented
          label={t("unifi.flagFilter")}
          value={search.ufFlag ?? "all"}
          options={(["all", "offline", "update"] as const).map((f) => ({
            value: f,
            label: t(`unifi.flag.${f}`),
            count: counts.data ? counts.data[f] : null,
          }))}
          onChange={(ufFlag) => filter({ ufFlag: ufFlag === "all" ? undefined : ufFlag })}
        />
        {multiple ? (
          <FilterSelect
            label={t("unifi.consoleFilter")}
            value={search.ufConnection ?? ""}
            allLabel={t("unifi.allConsoles")}
            options={data.items.map((c) => ({ value: c.id, label: c.name }))}
            onChange={(ufConnection) =>
              filter({ ufConnection: ufConnection || undefined, ufSite: undefined })
            }
          />
        ) : null}
        {siteOptions.length > 1 ? (
          <FilterSelect
            label={t("unifi.siteFilter")}
            value={search.ufSite ?? ""}
            allLabel={t("unifi.allSites")}
            options={siteOptions.map((s) => ({ value: s.id, label: s.name }))}
            onChange={(ufSite) => filter({ ufSite: ufSite || undefined })}
          />
        ) : null}
        <FilterSelect
          label={t("unifi.stateFilter")}
          value={search.ufState ?? ""}
          allLabel={t("unifi.allStates")}
          options={(["online", "offline", "other"] as const).map((v) => ({
            value: v,
            label: t(`unifi.state.${v}`),
          }))}
          onChange={(ufState) => filter({ ufState: (ufState || undefined) as ServerSearch["ufState"] })}
        />
        <SearchInput
          className="ml-auto"
          label={t("unifi.search")}
          value={search.ufQ ?? ""}
          onChange={(ufQ) => filter({ ufQ: ufQ || undefined }, true)}
        />
      </div>
      <table className="w-full border-t text-left" data-testid="uf-devices">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="name"
              label={t("unifi.columnDevice")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            <SortHeader
              column="site"
              label={t("unifi.columnSite")}
              natural="asc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="ip"
              label={t("unifi.columnAddress")}
              natural="asc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="state"
              label={t("unifi.columnStatus")}
              natural="asc"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="firmware"
              label={t("unifi.columnFirmware")}
              natural="asc"
              className="px-3"
              {...sortProps}
            />
            <SortHeader
              column="uptime"
              label={t("unifi.columnUptime")}
              natural="desc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            {multiple ? (
              <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">{t("unifi.columnConsole")}</th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {devices.data?.items.map((device) => (
            <DeviceRow
              key={device.id}
              device={device}
              multiple={multiple}
              onOpen={() => setSearch({ device: device.id }, true)}
            />
          ))}
        </tbody>
      </table>
      <QueryStatus query={devices} />
      {devices.data && devices.data.items.length === 0 ? (
        <p className="px-5 py-6 text-muted-foreground">
          {hasFilter ? t("unifi.noMatch") : t("unifi.noDevices")}
        </p>
      ) : null}
      {devices.data ? (
        <Pagination
          page={devices.data}
          onCursor={(ufCursor) => setSearch({ ufCursor }, false)}
          onPageSize={(ufPageSize) => setSearch({ ufPageSize, ufCursor: undefined })}
        />
      ) : null}
      {search.device ? (
        <DeviceDialog
          deviceId={search.device}
          prefetched={selected}
          onClose={() => setSearch({ device: undefined }, true)}
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

function FlagBadge({ flag }: { flag: UnifiDeviceFlag }) {
  const { t } = useTranslation();
  const Icon = FLAG_ICON[flag];
  return (
    <Badge tone={FLAG_TONE[flag]}>
      <Icon aria-hidden="true" />
      {t(`unifi.flags.${flag}`)}
    </Badge>
  );
}

/** The status cell: offline is flagged, online and other states are plain words. */
function StatusCell({ device }: { device: UnifiDevice }) {
  const { t } = useTranslation();
  if (device.state === "offline") return <FlagBadge flag="offline" />;
  return (
    <div>
      <span>
        {device.state === "online"
          ? t("unifi.state.online")
          : device.rawState.toLowerCase().replaceAll("_", " ")}
      </span>
      {device.stateSince ? (
        <div className="hidden text-sm text-muted-foreground @wide:block">
          {t("unifi.stateSince", { when: formatRelative(device.stateSince) })}
        </div>
      ) : null}
    </div>
  );
}

function DeviceRow({
  device,
  multiple,
  onOpen,
}: {
  device: UnifiDevice;
  multiple: boolean;
  onOpen: () => void;
}) {
  const { t } = useTranslation();
  return (
    <tr
      className="row-link border-b align-top last:border-0"
      onClick={rowClick(onOpen)}
      data-testid="uf-device"
    >
      <td className="px-5 py-3">
        <button
          type="button"
          onClick={onOpen}
          aria-label={t("unifi.openDevice", { name: device.name })}
          className="max-w-full text-left font-medium break-all hover:underline"
        >
          {device.name}
        </button>
        <div className="text-sm text-muted-foreground">
          {device.model ?? "–"}
          <span className="@wide:hidden">{device.siteName ? ` · ${device.siteName}` : ""}</span>
        </div>
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">{device.siteName}</td>
      <td className="hidden px-3 py-3 font-mono text-sm @wide:table-cell">{device.ip ?? <Dash />}</td>
      <td className="px-3 py-3">
        <StatusCell device={device} />
      </td>
      <td className="px-3 py-3">
        <div className="tabular-nums">{device.firmwareVersion ?? <Dash />}</div>
        {device.flags.includes("updateAvailable") ? (
          <div className="mt-1">
            <FlagBadge flag="updateAvailable" />
          </div>
        ) : null}
      </td>
      <td className="hidden px-3 py-3 tabular-nums @xwide:table-cell">
        {device.state === "online" && device.uptimeSec ? formatDuration(device.uptimeSec) : <Dash />}
      </td>
      {multiple ? <td className="hidden px-3 py-3 @xwide:table-cell">{device.connectionName}</td> : null}
    </tr>
  );
}

/* -------------------------------------------------------------------------- */
/* Device dialog                                                               */
/* -------------------------------------------------------------------------- */

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="break-all">{children}</dd>
    </>
  );
}

function DeviceDialog({
  deviceId,
  prefetched,
  onClose,
}: {
  deviceId: string;
  prefetched: UnifiDevice | undefined;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const query = useQuery({
    queryKey: ["uf-device", deviceId],
    queryFn: () => api<UnifiDevice>(`/unifi/devices/${deviceId}`),
    ...(prefetched ? { initialData: prefetched } : {}),
  });
  const device = query.data;
  const none = <span className="text-muted-foreground">{t("unifi.factNone")}</span>;
  return (
    <Dialog
      open
      onClose={onClose}
      title={device?.name ?? t("unifi.devicesTitle")}
      {...(device
        ? {
            description: t("unifi.deviceDescription", {
              model: device.model ?? "–",
              site: device.siteName,
              console: device.connectionName,
            }),
          }
        : {})}
    >
      {device ? (
        <div className="grid gap-4">
          {device.flags.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {FLAG_ORDER.filter((f) => device.flags.includes(f)).map((f) => (
                <FlagBadge key={f} flag={f} />
              ))}
            </div>
          ) : null}
          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
            <Fact label={t("unifi.factModel")}>{device.model ?? none}</Fact>
            <Fact label={t("unifi.factMac")}>
              <span className="font-mono">{device.mac ?? none}</span>
            </Fact>
            <Fact label={t("unifi.factAddress")}>
              <span className="font-mono">{device.ip ?? none}</span>
            </Fact>
            <Fact label={t("unifi.factFirmware")}>
              {device.firmwareVersion ?? none}
              <span className="ml-2 text-muted-foreground">{t(`unifi.firmware.${device.firmware}`)}</span>
            </Fact>
            {device.latestFirmware ? (
              <Fact label={t("unifi.factLatest")}>{device.latestFirmware}</Fact>
            ) : null}
            <Fact label={t("unifi.factState")}>{t(`unifi.state.${device.state}`)}</Fact>
            <Fact label={t("unifi.factSince")}>
              {device.stateSince ? (
                <time dateTime={device.stateSince}>{formatDateTime(device.stateSince)}</time>
              ) : (
                none
              )}
            </Fact>
            <Fact label={t("unifi.factUptime")}>
              {device.state === "online" && device.uptimeSec ? formatDuration(device.uptimeSec) : none}
            </Fact>
            <Fact label={t("unifi.factSite")}>{device.siteName}</Fact>
            <Fact label={t("unifi.factConsole")}>{device.connectionName}</Fact>
            <Fact label={t("unifi.factSeen")}>
              {device.lastSeenAt ? (
                <time dateTime={device.lastSeenAt}>{formatDateTime(device.lastSeenAt)}</time>
              ) : (
                none
              )}
            </Fact>
          </dl>
          <p className="text-sm text-muted-foreground">{t("unifi.firmwareNote")}</p>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.close")}
            </Button>
          </DialogFooter>
        </div>
      ) : (
        <QueryStatus query={query} />
      )}
    </Dialog>
  );
}
