import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { ScrollText } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Segmented } from "../../components/filters.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Badge } from "../../components/ui/badge.tsx";
import { api } from "../../lib/api.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { AUDIT_FILTERS, type AuditSearch, auditSearch, toQuery } from "../../lib/search.ts";
import type { Page } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/audit-log")({
  validateSearch: auditSearch,
  // Owners and admins only; the API enforces the same rule.
  beforeLoad: ({ context }) => {
    if (context.me.role !== "owner" && context.me.role !== "admin")
      throw redirect({ to: "/", replace: true });
  },
  component: AuditLog,
});

interface Entry {
  id: number;
  createdAt: string;
  action: string;
  target: { type: string; id: string | null } | null;
  actor: { id: string; name: string | null; email: string | null } | null;
  ip: string | null;
  data: Record<string, unknown> | null;
}

function AuditLog() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const query = useQuery({
    queryKey: ["audit-log", search],
    queryFn: () =>
      api<Page<Entry>>(
        `/audit-log${toQuery({ cursor: search.cursor, pageSize: search.pageSize, action: search.group ? `${search.group}.` : undefined })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const setSearch = (patch: Partial<AuditSearch>) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }) });

  return (
    <>
      <PageHeader icon={ScrollText} title={t("audit.title")} description={t("audit.description")} />
      <div className="mb-4">
        <Segmented
          label={t("audit.filterLabel")}
          value={search.group ?? "all"}
          options={(["all", ...AUDIT_FILTERS] as const).map((f) => ({
            value: f,
            label: t(`audit.filter.${f}`),
          }))}
          onChange={(group) => setSearch({ group: group === "all" ? undefined : group })}
        />
      </div>
      <Card>
        <table className="w-full text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("audit.columnTime")}</th>
              <th className="px-3 py-2.5 font-medium">{t("audit.columnActor")}</th>
              <th className="px-3 py-2.5 font-medium">{t("audit.columnAction")}</th>
              <th className="hidden px-3 py-2.5 font-medium @4xl:table-cell">{t("audit.columnDetails")}</th>
              <th className="hidden px-5 py-2.5 font-medium @6xl:table-cell">{t("audit.columnIp")}</th>
            </tr>
          </thead>
          <tbody>
            {query.data?.items.map((entry) => (
              <EntryRow key={entry.id} entry={entry} />
            ))}
          </tbody>
        </table>
        <QueryStatus query={query} />
        {query.data && query.data.items.length === 0 ? (
          <p className="px-5 py-6 text-muted-foreground">{t("audit.empty")}</p>
        ) : null}
        {query.data ? (
          <Pagination
            page={query.data}
            onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
            onPageSize={(pageSize) => setSearch({ pageSize })}
          />
        ) : null}
      </Card>
    </>
  );
}

function EntryRow({ entry }: { entry: Entry }) {
  const { t, i18n } = useTranslation();
  const actionName = entry.action.replace(/\./g, "_");
  const actionKey = `audit.actions.${actionName}`;
  // Entries of modules removed in 0.0.4 (ADR 0025) keep their labels in a small legacy block.
  const legacyKey = `audit.legacy.actions.${actionName}`;
  // Unknown actions (e.g. from a newer version) still show, with their raw name.
  const actionLabel = i18n.exists(actionKey)
    ? t(actionKey as never)
    : i18n.exists(legacyKey)
      ? t(legacyKey as never)
      : entry.action;
  const { outcome, ...details } = entry.data ?? {};
  const outcomeKey = typeof outcome === "string" ? `audit.outcome.${outcome}` : null;

  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-5 py-2.5 text-sm whitespace-nowrap">
        <time dateTime={entry.createdAt} title={formatDateTime(entry.createdAt)}>
          {formatDateTime(entry.createdAt)}
        </time>
        <div className="text-muted-foreground">{formatRelative(entry.createdAt)}</div>
      </td>
      <td className="px-3 py-2.5">
        {entry.actor ? (
          <>
            <div className="font-medium">{entry.actor.name}</div>
            <div className="text-sm text-muted-foreground">{entry.actor.email}</div>
          </>
        ) : (
          <span className="text-muted-foreground">{t("audit.system")}</span>
        )}
      </td>
      <td className="px-3 py-2.5">
        <div>{actionLabel}</div>
        {outcomeKey && i18n.exists(outcomeKey) ? (
          <Badge
            className={
              outcome === "failure"
                ? "mt-1 bg-destructive/15 text-destructive-text"
                : "mt-1 bg-muted text-muted-foreground"
            }
          >
            {t(outcomeKey as never)}
          </Badge>
        ) : null}
      </td>
      <td className="hidden px-3 py-2.5 @4xl:table-cell">
        <Details data={details} />
      </td>
      <td className="hidden px-5 py-2.5 font-mono text-sm text-muted-foreground @6xl:table-cell">
        {entry.ip ?? "–"}
      </td>
    </tr>
  );
}

/** Entry details as plain text key/value pairs; nested values are shown compactly. */
function Details({ data }: { data: Record<string, unknown> }) {
  const { t, i18n } = useTranslation();
  const entries = Object.entries(data);
  if (entries.length === 0) return <span className="text-muted-foreground">–</span>;
  return (
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm">
      {entries.map(([key, value]) => {
        const labelKey = i18n.exists(`audit.details.${key}`)
          ? `audit.details.${key}`
          : `audit.legacy.details.${key}`;
        return (
          <div key={key} className="contents">
            {/* Keys written by a newer version still show, under their raw name. */}
            <dt className="text-muted-foreground">{i18n.exists(labelKey) ? t(labelKey as never) : key}</dt>
            <dd className="font-mono break-all">{formatValue(value)}</dd>
          </div>
        );
      })}
    </dl>
  );
}

/** Plain text for a stored value: lists joined, objects as `key: value` pairs. */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "–";
  if (Array.isArray(value)) return value.map(formatValue).join(", ") || "–";
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k}: ${formatValue(v)}`)
      .join(", ");
  }
  return String(value);
}
