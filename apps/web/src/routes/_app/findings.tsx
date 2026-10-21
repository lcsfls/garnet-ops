import { SEVERITIES } from "@garnetops/core";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Bug } from "lucide-react";
import { useTranslation } from "react-i18next";
import { findingCountsQuery } from "../../components/app-shell.tsx";
import { ExportMenu } from "../../components/export-menu.tsx";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { FindingDetail } from "../../components/finding-detail.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { SeverityBadge } from "../../components/ui/badge.tsx";
import { Checkbox } from "../../components/ui/checkbox.tsx";
import { Select } from "../../components/ui/select.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDate, formatDateTime, formatPercent, formatRelative } from "../../lib/format.ts";
import { type FindingSearch, findingSearch, toQuery } from "../../lib/search.ts";
import type { FindingRow, Page, RepositoryRow, Severity } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/findings")({
  validateSearch: findingSearch,
  component: Findings,
});

const STATES = ["open", "accepted", "resolved", "all"] as const;
const FILTER_SEVERITIES = SEVERITIES.filter((s) => s !== "negligible" && s !== "unknown") as Severity[];

function Findings() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });

  const list = useQuery({
    queryKey: ["findings", { ...search, id: undefined }],
    queryFn: () => api<Page<FindingRow>>(`/findings${toQuery(search, ["id"])}`),
    placeholderData: keepPreviousData,
  });
  // Counts per state for the tabs, under every other filter.
  const counts = useQuery({
    ...findingCountsQuery(toQuery(search, ["id", "cursor", "pageSize", "state"])),
    placeholderData: keepPreviousData,
  });
  const repositories = useQuery({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  });

  const setSearch = (patch: Partial<FindingSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });

  const selected = new Set((search.severity ?? "").split(",").filter(Boolean));
  const toggleSeverity = (s: Severity) => {
    const next = new Set(selected);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSearch({ severity: next.size ? [...next].join(",") : undefined });
  };
  const hasFilters = Boolean(
    search.severity ||
      search.repositoryId ||
      search.scanId ||
      search.kev ||
      search.fixable ||
      search.q ||
      search.state,
  );

  return (
    <>
      <PageHeader
        icon={Bug}
        title={t("findings.title")}
        description={t("findings.description")}
        actions={
          <ExportMenu filters={{ ...search, id: undefined, cursor: undefined, pageSize: undefined }} />
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented
          label={t("findings.stateFilter")}
          value={search.state ?? "open"}
          options={STATES.map((s) => ({
            value: s,
            label: t(`findingState.${s}`),
            count: counts.data
              ? s === "all"
                ? counts.data.states.open + counts.data.states.accepted + counts.data.states.resolved
                : counts.data.states[s]
              : null,
          }))}
          onChange={(state) => setSearch({ state: state === "open" ? undefined : state })}
        />
        <fieldset className="flex flex-wrap gap-1.5">
          <legend className="sr-only">{t("findings.severityFilter")}</legend>
          {FILTER_SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={selected.has(s)}
              onClick={() => toggleSeverity(s)}
              className={cn(
                "rounded-md border p-0.5",
                selected.has(s) ? "border-ring" : "border-transparent opacity-70 hover:opacity-100",
              )}
            >
              <SeverityBadge severity={s} />
            </button>
          ))}
        </fieldset>
        <Select
          aria-label={t("findings.repository")}
          value={search.repositoryId ?? ""}
          onChange={(e) => setSearch({ repositoryId: e.target.value || undefined })}
          className="max-w-56"
        >
          <option value="">{t("findings.allRepositories")}</option>
          {repositories.data?.items.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </Select>
        <FilterCheckbox
          label={t("findings.knownExploitedOnly")}
          checked={search.kev === "1"}
          onChange={(on) => setSearch({ kev: on ? "1" : undefined })}
        />
        <FilterCheckbox
          label={t("findings.fixableOnly")}
          checked={search.fixable === "1"}
          onChange={(on) => setSearch({ fixable: on ? "1" : undefined })}
        />
        <SearchInput
          className="ml-auto"
          label={t("findings.search")}
          value={search.q ?? ""}
          onChange={(q) => setSearch({ q: q || undefined }, true)}
        />
        {/* Always rendered so the toolbar never shifts when a filter is set; hidden while nothing is filtered. */}
        <button
          type="button"
          onClick={() => navigate({ search: {} })}
          disabled={!hasFilters}
          aria-hidden={!hasFilters}
          tabIndex={hasFilters ? undefined : -1}
          className={cn("text-sm font-medium text-primary-text hover:underline", !hasFilters && "invisible")}
        >
          {t("findings.clearFilters")}
        </button>
      </div>

      <div
        className={cn(
          "grid gap-4",
          search.id && "@wide:grid-cols-[minmax(0,1fr)_28rem] @xwide:grid-cols-[minmax(0,1fr)_36rem]",
        )}
      >
        <Card className="self-start">
          <table className="w-full text-left">
            <thead className="text-sm text-muted-foreground">
              <tr className="border-b">
                <th className="px-5 py-2.5 font-medium">{t("findings.columnFinding")}</th>
                <th className="px-3 py-2.5 text-right font-medium">{t("findings.columnCvss")}</th>
                <th className="hidden px-3 py-2.5 text-right font-medium @6xl:table-cell">
                  <abbr title={t("findings.epssHint")} className="no-underline">
                    {t("findings.epss")}
                  </abbr>
                </th>
                <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
                  {t("findings.columnPublished")}
                </th>
                <th className="px-3 py-2.5 font-medium">{t("findings.columnPackage")}</th>
                <th className="hidden px-3 py-2.5 font-medium @4xl:table-cell">
                  {t("findings.columnFixedIn")}
                </th>
                <th className="px-3 py-2.5 font-medium">{t("findings.columnRepository")}</th>
                <th className="hidden px-5 py-2.5 font-medium @5xl:table-cell">
                  {t("findings.columnFirstSeen")}
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data?.items.map((f) => (
                <tr
                  key={f.id}
                  className={cn("border-b align-top last:border-0", f.id === search.id && "bg-primary/5")}
                >
                  <td className="px-5 py-2.5">
                    <div className="mb-1">
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <button
                      type="button"
                      onClick={() => setSearch({ id: f.id, cursor: search.cursor })}
                      aria-current={f.id === search.id ? "true" : undefined}
                      className="text-left font-medium break-all hover:underline"
                    >
                      {f.vulnerabilityId}
                    </button>
                    {f.knownExploited ? (
                      <div className="text-sm text-destructive-text">{t("findings.kev")}</div>
                    ) : null}
                  </td>
                  <td className="px-3 py-2.5 text-right font-mono text-sm tabular-nums">
                    {f.cvssScore !== null ? f.cvssScore.toFixed(1) : <Missing />}
                  </td>
                  <td className="hidden px-3 py-2.5 text-right font-mono text-sm tabular-nums @6xl:table-cell">
                    {f.epss !== null ? formatPercent(f.epss) : <Missing />}
                  </td>
                  <td className="hidden px-3 py-2.5 text-sm whitespace-nowrap @3xl:table-cell">
                    {f.publishedAt ? (
                      <time dateTime={f.publishedAt} title={formatDateTime(f.publishedAt)}>
                        {formatDate(f.publishedAt)}
                      </time>
                    ) : (
                      <Missing />
                    )}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-sm break-all">
                    {f.packageName}
                    <div className="text-muted-foreground">{f.packageVersion}</div>
                  </td>
                  <td className="hidden px-3 py-2.5 font-mono text-sm break-all @4xl:table-cell">
                    {f.fixedIn?.length ? (
                      f.fixedIn.join(", ")
                    ) : (
                      <span className="font-sans text-muted-foreground">{t("findings.noFix")}</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <RepositoryLink id={f.repositoryId} name={f.repositoryName} />
                  </td>
                  <td className="hidden px-5 py-2.5 text-sm whitespace-nowrap @5xl:table-cell">
                    <time dateTime={f.firstSeenAt}>{formatDateTime(f.firstSeenAt)}</time>
                    <div className="text-muted-foreground">{formatRelative(f.firstSeenAt)}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <QueryStatus query={list} />
          {list.data && list.data.items.length === 0 ? (
            <p className="px-5 py-6 text-muted-foreground">{t("findings.empty")}</p>
          ) : null}
          {list.data ? (
            <Pagination
              page={list.data}
              onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
              onPageSize={(pageSize) => setSearch({ pageSize })}
            />
          ) : null}
        </Card>

        {search.id ? (
          <FindingDetail
            key={search.id}
            id={search.id}
            canEdit={me.role !== "viewer"}
            onClose={() => setSearch({ id: undefined, cursor: search.cursor }, true)}
          />
        ) : null}
      </div>
    </>
  );
}

/** A value the vulnerability database does not have, announced as such to screen readers. */
function Missing() {
  const { t } = useTranslation();
  return (
    <span className="font-sans text-muted-foreground" title={t("findings.notAvailable")}>
      <span aria-hidden="true">–</span>
      <span className="sr-only">{t("findings.notAvailable")}</span>
    </span>
  );
}

function FilterCheckbox({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm whitespace-nowrap">
      <Checkbox checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}
