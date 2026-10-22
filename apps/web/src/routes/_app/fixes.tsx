import { SEVERITIES } from "@garnetops/core";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ExternalLink, GitPullRequest, RefreshCw, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { CreatePrDialog } from "../../components/create-pr-dialog.tsx";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { FixDetail } from "../../components/fix-detail.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { Badge, SeverityBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Drawer } from "../../components/ui/drawer.tsx";
import { Select } from "../../components/ui/select.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { camelCode, isBusy, PR_TONE, safeHttpsUrl } from "../../lib/fixes.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import type { MessageKey } from "../../lib/i18n.ts";
import { useLayoutStep } from "../../lib/layout-step.ts";
import { rowClick } from "../../lib/row-link.ts";
import { type FixSearch, fixSearch, toQuery } from "../../lib/search.ts";
import type {
  FixProposalPage,
  FixProposalRow,
  FixPrRow,
  Page,
  RepositoryRow,
  Severity,
} from "../../lib/types.ts";

export const Route = createFileRoute("/_app/fixes")({
  validateSearch: fixSearch,
  component: Fixes,
});

const ACTIONS = ["all", "edit", "manual"] as const;
const ACTION_LABELS = {
  all: "fixes.actionAll",
  edit: "fixes.actionEdit",
  manual: "fixes.actionManual",
} as const;
const PR_FILTERS = ["all", "none", "open", "merged", "closed", "failed"] as const;
const ECOSYSTEMS = ["npm", "pypi", "go", "cargo", "composer", "other"] as const;
const FILTER_SEVERITIES = SEVERITIES.filter((s) => s !== "negligible" && s !== "unknown") as Severity[];

/** Fix proposals (mockup): version updates for open findings, and the pull requests GarnetOps opened (ADR 0014). */
function Fixes() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const setSearch = (patch: Partial<FixSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });
  const view = search.view ?? "proposals";
  const [queued, setQueued] = useState(false);

  const queryClient = useQueryClient();
  const refresh = useMutation({
    mutationFn: () => api("/fixes/refresh", { method: "POST", body: {} }),
    onSuccess: () => {
      setQueued(true);
      // The worker answers in the background: look again a few times while it asks the forge.
      for (const ms of [1500, 4000, 9000]) {
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["fixes"] }), ms);
      }
    },
  });

  return (
    <>
      <PageHeader
        icon={GitPullRequest}
        title={t("fixes.title")}
        description={t("fixes.description")}
        actions={
          <>
            {refresh.isError ? (
              <span role="alert" className="text-sm text-destructive-text">
                {t("errors.actionFailed")}
              </span>
            ) : queued ? (
              <span role="status" className="text-sm text-muted-foreground">
                {t("fixes.refreshQueued")}
              </span>
            ) : null}
            {me.role !== "viewer" ? (
              <Button variant="outline" disabled={refresh.isPending} onClick={() => refresh.mutate()}>
                <RefreshCw
                  aria-hidden="true"
                  className={cn("size-4", refresh.isPending && "motion-safe:animate-spin")}
                />
                {refresh.isPending ? t("fixes.refreshing") : t("fixes.refresh")}
              </Button>
            ) : null}
          </>
        }
      />
      <div className="mb-4">
        <Segmented
          label={t("fixes.viewLabel")}
          value={view}
          options={[
            { value: "proposals", label: t("fixes.viewProposals") },
            { value: "prs", label: t("fixes.viewPrs") },
          ]}
          onChange={(next) => navigate({ search: { view: next === "prs" ? "prs" : undefined } })}
        />
      </div>
      {view === "prs" ? (
        <PullRequests search={search} setSearch={setSearch} />
      ) : (
        <Proposals search={search} setSearch={setSearch} role={me.role} />
      )}
    </>
  );
}

type SetSearch = (patch: Partial<FixSearch>, replace?: boolean) => unknown;

function Proposals({
  search,
  setSearch,
  role,
}: {
  search: FixSearch;
  setSearch: SetSearch;
  role: "owner" | "admin" | "member" | "viewer";
}) {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const step = useLayoutStep();
  const apiQuery = toQuery(search, ["id", "view", "prState"]);
  const list = useQuery({
    queryKey: ["fixes", "proposals", apiQuery],
    queryFn: () => api<FixProposalPage>(`/fixes${apiQuery}`),
    placeholderData: keepPreviousData,
    // A pull request that is being created shows up by itself.
    refetchInterval: (q) => (q.state.data?.items.some((i) => isBusy(i.pr?.state)) ? 3000 : false),
  });
  const repositories = useQuery({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  });
  const [creating, setCreating] = useState<FixProposalRow | null>(null);

  const sortProps = {
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as FixSearch["sort"], dir }),
  };
  const items = list.data?.items ?? [];
  // From the wide step there is room for list and detail side by side; below it the detail is a drawer.
  const sidePane = step !== "base";
  const shown = items.find((i) => i.key === search.id) ?? (step === "xwide" ? items[0] : undefined);
  const select = (key: string | undefined) => setSearch({ id: key, cursor: search.cursor }, true);

  const selectedSeverities = new Set((search.severity ?? "").split(",").filter(Boolean));
  const toggleSeverity = (s: Severity) => {
    const next = new Set(selectedSeverities);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSearch({ severity: next.size ? [...next].join(",") : undefined });
  };
  const hasFilters = Boolean(
    search.action || search.severity || search.ecosystem || search.pr || search.repositoryId || search.q,
  );

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented
          label={t("fixes.actionLabel")}
          value={search.action ?? "all"}
          options={ACTIONS.map((a) => ({
            value: a,
            label: t(ACTION_LABELS[a]),
            count: list.data ? list.data.counts[a] : null,
          }))}
          onChange={(action) => setSearch({ action: action === "all" ? undefined : action })}
        />
        <fieldset className="flex flex-wrap gap-1.5">
          <legend className="sr-only">{t("fixes.severityFilter")}</legend>
          {FILTER_SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={selectedSeverities.has(s)}
              onClick={() => toggleSeverity(s)}
              className={cn(
                "rounded-md border p-0.5",
                selectedSeverities.has(s) ? "border-ring" : "border-transparent opacity-70 hover:opacity-100",
              )}
            >
              <SeverityBadge severity={s} />
            </button>
          ))}
        </fieldset>
        <Select
          aria-label={t("fixes.repository")}
          value={search.repositoryId ?? ""}
          onChange={(e) => setSearch({ repositoryId: e.target.value || undefined })}
          className="max-w-56"
        >
          <option value="">{t("fixes.allRepositories")}</option>
          {repositories.data?.items.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </Select>
        <Select
          aria-label={t("fixes.ecosystem")}
          value={search.ecosystem ?? ""}
          onChange={(e) => setSearch({ ecosystem: (e.target.value || undefined) as FixSearch["ecosystem"] })}
          className="max-w-44"
        >
          <option value="">{t("fixes.allEcosystems")}</option>
          {ECOSYSTEMS.map((e) => (
            <option key={e} value={e}>
              {e === "other" ? t("fixes.ecosystemOther") : e}
            </option>
          ))}
        </Select>
        <Select
          aria-label={t("fixes.prFilter")}
          value={search.pr ?? "all"}
          onChange={(e) =>
            setSearch({ pr: e.target.value === "all" ? undefined : (e.target.value as FixSearch["pr"]) })
          }
          className="max-w-56"
        >
          {PR_FILTERS.map((f) => (
            <option key={f} value={f}>
              {f === "all" ? t("fixes.prAll") : f === "none" ? t("fixes.prNone") : t(`fixes.prState.${f}`)}
            </option>
          ))}
        </Select>
        <SearchInput
          className="ml-auto"
          label={t("fixes.search")}
          value={search.q ?? ""}
          onChange={(q) => setSearch({ q: q || undefined }, true)}
        />
        <button
          type="button"
          onClick={() => navigate({ search: {} })}
          disabled={!hasFilters}
          aria-hidden={!hasFilters}
          tabIndex={hasFilters ? undefined : -1}
          className={cn("text-sm font-medium text-primary-text hover:underline", !hasFilters && "invisible")}
        >
          {t("fixes.clearFilters")}
        </button>
      </div>

      <div
        className={cn(
          "grid gap-4",
          sidePane && shown && "@wide:grid-cols-[minmax(0,1fr)_28rem] @xwide:grid-cols-[minmax(0,1fr)_32rem]",
        )}
      >
        <Card className="@container/list self-start">
          <table className="w-full text-left">
            <thead className="text-sm text-muted-foreground">
              <tr className="border-b">
                <SortHeader
                  column="package"
                  label={t("fixes.columnPackage")}
                  natural="asc"
                  className="px-5"
                  {...sortProps}
                />
                <SortHeader
                  column="severity"
                  label={t("fixes.columnSeverity")}
                  natural="asc"
                  className="px-3"
                  {...sortProps}
                />
                <SortHeader
                  column="repository"
                  label={t("fixes.columnRepository")}
                  natural="asc"
                  className="hidden px-3 @2xl/list:table-cell"
                  {...sortProps}
                />
                <th className="hidden px-3 py-2.5 font-medium @4xl/list:table-cell">
                  {t("fixes.columnFile")}
                </th>
                <th className="hidden px-3 py-2.5 font-medium @5xl/list:table-cell">
                  {t("fixes.columnDependency")}
                </th>
                <th className="hidden px-3 py-2.5 font-medium @7xl/list:table-cell">
                  {t("fixes.columnSuggestion")}
                </th>
                <SortHeader
                  column="status"
                  label={t("fixes.columnStatus")}
                  natural="asc"
                  className="px-5"
                  {...sortProps}
                />
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr
                  key={p.key}
                  aria-selected={p.key === shown?.key}
                  className="row-link border-b align-top last:border-0"
                  onClick={rowClick(() => select(p.key))}
                >
                  <td className="px-5 py-2.5">
                    <button
                      type="button"
                      onClick={() => select(p.key)}
                      aria-current={p.key === shown?.key ? "true" : undefined}
                      className="text-left font-mono font-medium break-all hover:underline"
                    >
                      {p.packageName}
                    </button>
                    <div className="font-mono text-sm whitespace-nowrap text-muted-foreground">
                      {p.targetVersion
                        ? t("fixes.versionChange", { from: p.installedVersion, to: p.targetVersion })
                        : `${p.installedVersion} · ${t("fixes.noVersion")}`}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <span className="text-sm text-muted-foreground">{p.packageType}</span>
                      {p.majorUpgrade ? (
                        <Badge tone="outline">
                          <TriangleAlert aria-hidden="true" />
                          {t("fixes.majorUpgrade")}
                        </Badge>
                      ) : null}
                      {p.dev ? <Badge tone="neutral">{t("fixes.dev")}</Badge> : null}
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="mb-1">
                      <SeverityBadge severity={p.severity} />
                    </div>
                    <Link
                      to="/findings"
                      search={{ repositoryId: p.repositoryId, q: p.packageName }}
                      className="text-sm whitespace-nowrap hover:underline"
                    >
                      {t("fixes.vulnerabilities", { count: p.vulnerabilityIds.length })}
                    </Link>
                  </td>
                  <td className="hidden px-3 py-2.5 @2xl/list:table-cell">
                    <RepositoryLink id={p.repositoryId} name={p.repositoryName} />
                  </td>
                  <td className="hidden px-3 py-2.5 font-mono text-sm break-words @4xl/list:table-cell">
                    {p.manifestPath ?? <span className="font-sans text-muted-foreground">–</span>}
                  </td>
                  <td className="hidden px-3 py-2.5 text-sm @5xl/list:table-cell">
                    {p.dependency === "direct"
                      ? t("fixes.direct")
                      : p.dependency === "transitive"
                        ? t("fixes.transitive")
                        : t("fixes.unknownDependency")}
                  </td>
                  <td className="hidden max-w-80 px-3 py-2.5 text-sm @7xl/list:table-cell">
                    {p.aiSuggestion ? (
                      <>
                        <Badge tone="outline" className="mb-1">
                          {t("fixes.aiLabel")}
                        </Badge>
                        <p className="line-clamp-3">{p.aiSuggestion.summary}</p>
                      </>
                    ) : (
                      <span className="text-muted-foreground">–</span>
                    )}
                  </td>
                  <td className="px-5 py-2.5">
                    <Status
                      row={p}
                      canCreate={role !== "viewer"}
                      admin={role === "owner" || role === "admin"}
                      onCreate={() => setCreating(p)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <QueryStatus query={list} />
          {list.data && list.data.items.length === 0 ? (
            <p className="px-5 py-6 text-muted-foreground">
              {hasFilters ? t("fixes.emptyFiltered") : t("fixes.empty")}
            </p>
          ) : null}
          {list.data ? (
            <Pagination
              page={list.data}
              onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
              onPageSize={(pageSize) => setSearch({ pageSize })}
            />
          ) : null}
        </Card>

        {sidePane && shown ? (
          <FixDetail
            key={shown.key}
            proposal={shown}
            canCreate={role !== "viewer"}
            onCreate={() => setCreating(shown)}
            onClose={search.id ? () => select(undefined) : undefined}
          />
        ) : null}
      </div>
      <Drawer
        open={!sidePane && Boolean(search.id && shown)}
        onClose={() => select(undefined)}
        title={t("fixes.detailTitle")}
      >
        {!sidePane && shown ? (
          <div className="p-4">
            <FixDetail
              key={shown.key}
              proposal={shown}
              canCreate={role !== "viewer"}
              onCreate={() => setCreating(shown)}
            />
          </div>
        ) : null}
      </Drawer>
      {creating ? (
        <CreatePrDialog
          proposal={creating}
          me={me}
          onClose={() => setCreating(null)}
          onCreated={() => setCreating(null)}
        />
      ) : null}
    </>
  );
}

/** What can be done with a proposal, in one cell: its pull request, the button, or why not. */
function Status({
  row: p,
  canCreate,
  admin,
  onCreate,
}: {
  row: FixProposalRow;
  canCreate: boolean;
  admin: boolean;
  onCreate: () => void;
}) {
  const { t } = useTranslation();
  const url = safeHttpsUrl(p.pr?.url ?? null);
  if (p.pr && p.pr.state !== "failed" && p.pr.state !== "closed") {
    return (
      <div className="grid gap-1">
        <Badge tone={PR_TONE[p.pr.state]}>{t(`fixes.prState.${p.pr.state}`)}</Badge>
        {url && p.pr.number !== null ? (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sm font-medium text-primary-text hover:underline"
          >
            {t("fixes.prNumber", { number: p.pr.number })}
            <ExternalLink aria-hidden="true" className="size-3.5" />
            <span className="sr-only">{t("fixes.openOnForge")}</span>
          </a>
        ) : null}
      </div>
    );
  }
  if (p.action === "manual") {
    return (
      <div className="grid gap-1">
        <Badge tone="neutral">{t("fixes.manualBadge")}</Badge>
        {p.reason ? (
          <span className="text-sm text-muted-foreground">
            {t(`fixes.reason.${camelCode(p.reason)}` as MessageKey)}
          </span>
        ) : null}
      </div>
    );
  }
  return (
    <div className="grid justify-items-start gap-1.5">
      {p.pr?.state === "failed" ? (
        <span className="text-sm text-destructive-text">
          {t(`fixes.prState.failed`)}
          {p.pr.reason ? `: ${t(`fixes.failure.${camelCode(p.pr.reason)}` as MessageKey)}` : ""}
        </span>
      ) : null}
      {p.writeAccess === "on" && canCreate ? (
        <Button variant="outline" className="h-8 px-3 text-sm" onClick={onCreate}>
          <GitPullRequest aria-hidden="true" className="size-4" />
          {t("fixes.createPr")}
        </Button>
      ) : p.writeAccess === "failed" ? (
        <span className="text-sm text-muted-foreground">{t("fixes.writeFailed")}</span>
      ) : p.writeAccess === "off" ? (
        <span className="text-sm text-muted-foreground">
          {t("fixes.writeOff")}
          {admin ? (
            <>
              {" · "}
              <Link
                to="/repositories/$id"
                params={{ id: p.repositoryId }}
                className="font-medium text-primary-text hover:underline"
              >
                {t("fixes.turnOnWriteAccess")}
              </Link>
            </>
          ) : null}
        </span>
      ) : null}
    </div>
  );
}

function PullRequests({ search, setSearch }: { search: FixSearch; setSearch: SetSearch }) {
  const { t } = useTranslation();
  const navigate = useNavigate({ from: Route.fullPath });
  const query = toQuery({ ...search, state: search.prState }, [
    "view",
    "prState",
    "id",
    "sort",
    "dir",
    "action",
    "severity",
    "ecosystem",
    "pr",
    "q",
  ]);
  const list = useQuery({
    queryKey: ["fixes", "prs", query],
    queryFn: () => api<Page<FixPrRow>>(`/fixes/prs${query}`),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data?.items.some((i) => isBusy(i.state)) ? 3000 : false),
  });
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Select
          aria-label={t("fixes.prStateFilter")}
          value={search.prState ?? ""}
          onChange={(e) => setSearch({ prState: (e.target.value || undefined) as FixSearch["prState"] })}
          className="max-w-56"
        >
          <option value="">{t("fixes.allStates")}</option>
          {(["open", "merged", "closed", "failed"] as const).map((s) => (
            <option key={s} value={s}>
              {t(`fixes.prState.${s}`)}
            </option>
          ))}
        </Select>
      </div>
      <Card className="@container/list">
        <table className="w-full text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("fixes.columnChange")}</th>
              <th className="hidden px-3 py-2.5 font-medium @2xl/list:table-cell">
                {t("fixes.columnRepository")}
              </th>
              <th className="px-3 py-2.5 font-medium">{t("fixes.columnStatus")}</th>
              <th className="hidden px-3 py-2.5 font-medium @4xl/list:table-cell">
                {t("fixes.columnRequestedBy")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @5xl/list:table-cell">
                {t("fixes.columnCreated")}
              </th>
              <th className="hidden px-5 py-2.5 font-medium @7xl/list:table-cell">
                {t("fixes.columnChecked")}
              </th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((pr) => {
              const url = safeHttpsUrl(pr.url);
              return (
                <tr key={pr.id} className="border-b align-top last:border-0">
                  <td className="px-5 py-2.5">
                    <div className="font-mono font-medium break-all">{pr.packageName}</div>
                    <div className="font-mono text-sm text-muted-foreground">
                      {t("fixes.versionChange", { from: pr.from, to: pr.to })}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
                      <span className="break-all">{pr.manifestPath}</span>
                      {pr.majorUpgrade ? (
                        <Badge tone="outline">
                          <TriangleAlert aria-hidden="true" />
                          {t("fixes.majorUpgrade")}
                        </Badge>
                      ) : null}
                    </div>
                  </td>
                  <td className="hidden px-3 py-2.5 @2xl/list:table-cell">
                    <RepositoryLink id={pr.repositoryId} name={pr.repositoryName} />
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="grid gap-1">
                      <Badge tone={PR_TONE[pr.state]}>{t(`fixes.prState.${pr.state}`)}</Badge>
                      {url && pr.number !== null ? (
                        <a
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-sm font-medium text-primary-text hover:underline"
                        >
                          {t("fixes.prNumber", { number: pr.number })}
                          <ExternalLink aria-hidden="true" className="size-3.5" />
                          <span className="sr-only">{t("fixes.openOnForge")}</span>
                        </a>
                      ) : null}
                      {pr.state === "failed" && pr.reason ? (
                        <span className="text-sm text-destructive-text">
                          {t(`fixes.failure.${camelCode(pr.reason)}` as MessageKey)}
                        </span>
                      ) : null}
                      {pr.state === "open" && pr.reason ? (
                        <span className="text-sm text-muted-foreground">
                          {t("fixes.prCheckProblem", {
                            reason: t(`fixes.failure.${camelCode(pr.reason)}` as MessageKey),
                          })}
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="hidden px-3 py-2.5 text-sm @4xl/list:table-cell">{pr.requestedBy ?? "–"}</td>
                  <td className="hidden px-3 py-2.5 text-sm whitespace-nowrap @5xl/list:table-cell">
                    <time dateTime={pr.createdAt}>{formatDateTime(pr.createdAt)}</time>
                    <div className="text-muted-foreground">{formatRelative(pr.createdAt)}</div>
                  </td>
                  <td className="hidden px-5 py-2.5 text-sm @7xl/list:table-cell">
                    {pr.lastCheckedAt ? (
                      formatRelative(pr.lastCheckedAt)
                    ) : (
                      <span className="text-muted-foreground">–</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <QueryStatus query={list} />
        {list.data && list.data.items.length === 0 ? (
          <p className="px-5 py-6 text-muted-foreground">{t("fixes.emptyPrs")}</p>
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
