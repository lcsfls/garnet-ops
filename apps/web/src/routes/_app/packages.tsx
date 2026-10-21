import { SEVERITIES, SEVERITY_RANK, type Severity } from "@garnetops/core";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Package } from "lucide-react";
import { useTranslation } from "react-i18next";
import { SearchInput } from "../../components/filters.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { SeverityBadge } from "../../components/ui/badge.tsx";
import { Checkbox } from "../../components/ui/checkbox.tsx";
import { Select } from "../../components/ui/select.tsx";
import { api } from "../../lib/api.ts";
import { type PackageSearch, packageSearch, toQuery } from "../../lib/search.ts";
import type { Page, RepositoryRow } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/packages")({
  validateSearch: packageSearch,
  component: Packages,
});

interface PackageRow {
  id: string;
  name: string;
  version: string;
  type: string;
  purl: string | null;
  licenses: string[] | null;
  repositoryId: string;
  repositoryName: string;
  openFindings: number;
  worstSeverityRank: number | null;
}

const severityOfRank = (rank: number): Severity =>
  SEVERITIES.find((s) => SEVERITY_RANK[s] === rank) ?? "unknown";

function Packages() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const list = useQuery({
    queryKey: ["packages", search],
    queryFn: () => api<Page<PackageRow>>(`/packages${toQuery(search)}`),
    placeholderData: keepPreviousData,
  });
  const repositories = useQuery({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  });
  const setSearch = (patch: Partial<PackageSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });
  const sortProps = {
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as PackageSearch["sort"], dir }),
  };

  return (
    <>
      <PageHeader icon={Package} title={t("packages.title")} description={t("packages.description")} />
      <div className="mb-4 flex flex-wrap items-center gap-3">
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
        <label className="flex items-center gap-2 text-sm whitespace-nowrap">
          <Checkbox
            checked={search.vulnerable === "1"}
            onChange={(e) => setSearch({ vulnerable: e.target.checked ? "1" : undefined })}
          />
          {t("packages.vulnerableOnly")}
        </label>
        <SearchInput
          className="ml-auto"
          label={t("packages.search")}
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
                label={t("packages.columnName")}
                natural="asc"
                className="px-5"
                {...sortProps}
              />
              <th className="px-3 py-2.5 font-medium">{t("packages.columnVersion")}</th>
              <SortHeader
                column="type"
                label={t("packages.columnType")}
                natural="asc"
                className="hidden px-3 @3xl:table-cell"
                {...sortProps}
              />
              <SortHeader
                column="repository"
                label={t("findings.columnRepository")}
                natural="asc"
                className="px-3"
                {...sortProps}
              />
              <th className="hidden px-3 py-2.5 font-medium @5xl:table-cell">
                {t("packages.columnLicenses")}
              </th>
              <SortHeader
                column="findings"
                label={t("packages.columnOpen")}
                natural="desc"
                className="px-5"
                {...sortProps}
              />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((p) => (
              <tr key={p.id} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5 font-mono text-sm break-all">{p.name}</td>
                <td className="px-3 py-2.5 font-mono text-sm break-all">{p.version || "–"}</td>
                <td className="hidden px-3 py-2.5 text-sm @3xl:table-cell">{p.type}</td>
                <td className="px-3 py-2.5">
                  <RepositoryLink id={p.repositoryId} name={p.repositoryName} />
                </td>
                <td className="hidden px-3 py-2.5 font-mono text-sm break-all text-muted-foreground @5xl:table-cell">
                  {p.licenses?.length ? p.licenses.join(", ") : "–"}
                </td>
                <td className="px-5 py-2.5">
                  {p.openFindings > 0 && p.worstSeverityRank !== null ? (
                    <Link
                      to="/findings"
                      search={{ repositoryId: p.repositoryId, q: p.name }}
                      className="hover:opacity-80"
                    >
                      <SeverityBadge severity={severityOfRank(p.worstSeverityRank)} count={p.openFindings} />
                    </Link>
                  ) : (
                    <span className="text-sm text-muted-foreground">{t("packages.noOpen")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <QueryStatus query={list} />
        {list.data && list.data.items.length === 0 ? (
          <p className="px-5 py-6 text-muted-foreground">{t("packages.empty")}</p>
        ) : null}
        {list.data ? (
          <Pagination
            page={list.data}
            onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
            onPageSize={(pageSize) => setSearch({ pageSize })}
          />
        ) : null}
      </Card>
    </>
  );
}
