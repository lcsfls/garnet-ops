import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Globe, KeyRound, Network, Play, Plus, ShieldCheck, Telescope, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AddAssetDialog } from "../../components/exposure-dialogs.tsx";
import {
  CertificateExpiry,
  CountPill,
  countryName,
  Stage1Badge,
  Stage2Badge,
  VerificationBadge,
} from "../../components/exposure-parts.tsx";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { ActionMenu, type MenuAction } from "../../components/ui/action-menu.tsx";
import { Button } from "../../components/ui/button.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { api } from "../../lib/api.ts";
import { type ExposureAsset, type ExposureCounts, isBusy } from "../../lib/exposure.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { rowClick } from "../../lib/row-link.ts";
import { EXPOSURE_STATUSES, type ExposureSearch, exposureSearch, toQuery } from "../../lib/search.ts";
import type { Page } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/exposure")({
  validateSearch: exposureSearch,
  component: Exposure,
});

/** Search params that belong to the screen, not to the list the API returns. */
const UI_ONLY = ["add"];

function Exposure() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const canEdit = me.role === "owner" || me.role === "admin";

  const query = useQuery({
    queryKey: ["exposure", "list", search],
    queryFn: () => api<Page<ExposureAsset>>(`/exposure${toQuery(search, UI_ONLY)}`),
    placeholderData: keepPreviousData,
    // Follow the worker until the first look at a new asset is done.
    refetchInterval: (q) => (q.state.data?.items.some(isBusy) ? 3000 : false),
  });
  const counts = useQuery({
    queryKey: ["exposure", "counts", search.q ?? ""],
    queryFn: () => api<ExposureCounts>(`/exposure/counts${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
  });

  const setSearch = (patch: Partial<ExposureSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });
  const sortProps = {
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as ExposureSearch["sort"], dir }),
  };
  const c = counts.data;

  return (
    <>
      <PageHeader
        icon={Telescope}
        title={t("exposure.title")}
        description={t("exposure.description")}
        actions={
          canEdit ? (
            <Button onClick={() => setSearch({ add: "1" })}>
              <Plus aria-hidden="true" className="size-4" />
              {t("exposure.add")}
            </Button>
          ) : null
        }
      />

      <details
        className="mb-4 rounded-xl border bg-card px-5 py-3 text-sm shadow-xs"
        data-testid="exposure-help"
      >
        <summary className="cursor-pointer font-medium">{t("exposure.helpSummary")}</summary>
        <div className="mt-3 grid gap-3 text-muted-foreground @wide:grid-cols-3">
          <section>
            <h2 className="font-medium text-foreground">{t("exposure.helpStage1Title")}</h2>
            <p>{t("exposure.helpStage1Text")}</p>
          </section>
          <section>
            <h2 className="font-medium text-foreground">{t("exposure.helpStage2Title")}</h2>
            <p>{t("exposure.helpStage2Text")}</p>
          </section>
          <section>
            <h2 className="font-medium text-foreground">{t("exposure.helpNeverTitle")}</h2>
            <p>{t("exposure.helpNeverText")}</p>
          </section>
          <p className="@wide:col-span-3">{t("exposure.notLegalAdvice")}</p>
        </div>
      </details>

      {/* Key figures: every one leads to the list it counts. More of them from the wide step on. */}
      <div
        className="mb-4 hidden gap-3 @wide:grid @wide:grid-cols-4 @xwide:grid-cols-6"
        data-testid="exposure-figures"
      >
        <Figure label={t("exposure.figureAssets")} value={c?.all} icon={Globe} to={{}} />
        <Figure
          label={t("exposure.figureAttention")}
          value={c?.attention}
          icon={ShieldCheck}
          to={{ status: "attention" }}
        />
        <Figure
          label={t("exposure.figureUnverified")}
          value={c?.unverified}
          icon={KeyRound}
          to={{ status: "unverified" }}
        />
        <Figure
          label={t("exposure.figureStage2")}
          value={c?.stage2}
          icon={Network}
          to={{ status: "stage2" }}
        />
        <div className="hidden @xwide:contents">
          <Figure label={t("exposure.figureCritical")} value={c?.open.critical} to={{ sort: "critical" }} />
          <Figure label={t("exposure.figureHigh")} value={c?.open.high} to={{ sort: "high" }} />
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented
          label={t("exposure.statusFilter")}
          value={search.status ?? "all"}
          options={EXPOSURE_STATUSES.map((s) => ({
            value: s,
            label: t(`exposure.status.${s}`),
            count: c ? c[s] : null,
          }))}
          onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
        />
        <SearchInput
          className="ml-auto"
          label={t("exposure.search")}
          value={search.q ?? ""}
          onChange={(q) => setSearch({ q: q || undefined }, true)}
        />
      </div>

      <Card>
        <table className="w-full text-left" data-testid="exposure-table">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <SortHeader
                column="value"
                label={t("exposure.columnAsset")}
                natural="asc"
                className="px-5"
                {...sortProps}
              />
              <SortHeader
                column="verification"
                label={t("exposure.columnVerification")}
                natural="asc"
                className="hidden px-3 @3xl:table-cell"
                {...sortProps}
              />
              <SortHeader
                column="critical"
                label={t("severity.critical")}
                natural="desc"
                align="right"
                className="px-3"
                {...sortProps}
              />
              <SortHeader
                column="high"
                label={t("severity.high")}
                natural="desc"
                align="right"
                className="px-3"
                {...sortProps}
              />
              <SortHeader
                column="medium"
                label={t("severity.medium")}
                natural="desc"
                align="right"
                className="px-3"
                {...sortProps}
              />
              <SortHeader
                column="low"
                label={t("severity.low")}
                natural="desc"
                align="right"
                className="hidden px-3 @wide:table-cell"
                {...sortProps}
              />
              <SortHeader
                column="certificate"
                label={t("exposure.columnCertificate")}
                natural="asc"
                className="hidden px-3 @wide:table-cell"
                {...sortProps}
              />
              <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">
                {t("exposure.columnStage1")}
              </th>
              <SortHeader
                column="stage2"
                label={t("exposure.columnStage2")}
                natural="asc"
                className="hidden px-3 @3xl:table-cell"
                {...sortProps}
              />
              <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">
                {t("exposure.columnLocation")}
              </th>
              <SortHeader
                column="lastPassive"
                label={t("exposure.columnLastCheck")}
                natural="desc"
                className="hidden px-3 @3xl:table-cell"
                {...sortProps}
              />
              {canEdit ? (
                <th className="w-14 px-3 py-2.5 text-right font-medium @wide:px-5">
                  <span className="sr-only">{t("exposure.columnActions")}</span>
                </th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {query.data?.items.map((asset) => (
              <AssetRow key={asset.id} asset={asset} canEdit={canEdit} />
            ))}
          </tbody>
        </table>
        <QueryStatus query={query} />
        {query.data && query.data.items.length === 0 ? (
          <p className="px-5 py-6 text-muted-foreground">
            {search.q || search.status ? t("exposure.noMatch") : t("exposure.empty")}
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
      {c ? (
        <p className="mt-3 text-sm text-muted-foreground">
          {t("exposure.limitNote", { count: c.all, limit: c.limit })}
        </p>
      ) : null}

      {canEdit ? (
        <AddAssetDialog open={search.add === "1"} onClose={() => setSearch({ add: undefined }, true)} />
      ) : null}
    </>
  );
}

function Figure({
  label,
  value,
  icon: Icon,
  to,
}: {
  label: string;
  value: number | undefined;
  icon?: typeof Globe;
  to: Partial<ExposureSearch>;
}) {
  return (
    <Link
      to="/exposure"
      search={to}
      className="block rounded-xl border bg-card px-[18px] py-3.5 shadow-xs transition-colors hover:border-primary/40"
    >
      <div className="flex items-center justify-between gap-2 text-[15px] text-muted-foreground">
        <span>{label}</span>
        {Icon ? <Icon aria-hidden="true" className="size-4" /> : null}
      </div>
      <div className="mt-1 text-[26px] leading-tight font-semibold tracking-[-0.02em]">
        {value === undefined ? "–" : formatNumber(value)}
      </div>
    </Link>
  );
}

function AssetRow({ asset, canEdit }: { asset: ExposureAsset; canEdit: boolean }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removeFailed, setRemoveFailed] = useState(false);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["exposure"] });

  const check = useMutation({
    mutationFn: () => api(`/exposure/${asset.id}/run`, { method: "POST" }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: () => api(`/exposure/${asset.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setConfirmRemove(false);
      await refresh();
    },
    onError: () => setRemoveFailed(true),
  });

  const summary = asset.stage1.summary;
  const when = asset.stage1.lastAt;
  const busy = isBusy(asset);
  const actions: MenuAction[] = canEdit
    ? [
        {
          label: t("exposure.checkNow"),
          icon: Play,
          disabled: busy || check.isPending,
          onSelect: () => check.mutate(),
        },
        {
          label: t("exposure.verifyOpen"),
          icon: KeyRound,
          onSelect: () =>
            void navigate({ to: "/exposure/$id", params: { id: asset.id }, search: { verify: "1" } }),
        },
        {
          label: t("exposure.remove"),
          icon: Trash2,
          destructive: true,
          onSelect: () => {
            setRemoveFailed(false);
            setConfirmRemove(true);
          },
        },
      ]
    : [];

  return (
    <tr
      className="row-link border-b align-top last:border-0"
      data-asset={asset.value}
      onClick={rowClick(() => void navigate({ to: "/exposure/$id", params: { id: asset.id }, search: {} }))}
    >
      <td className="w-full max-w-0 px-5 py-3 @wide:w-auto @wide:max-w-none">
        <div className="flex min-w-0 items-start gap-2.5">
          <Globe aria-hidden="true" className="mt-1 size-4 flex-none text-muted-foreground" />
          <div className="min-w-0">
            <Link
              to="/exposure/$id"
              params={{ id: asset.id }}
              search={{}}
              className="font-medium break-all hover:underline"
            >
              {asset.value}
            </Link>
            <div className="text-sm text-muted-foreground">
              {t(`exposure.kind.${asset.kind}`)}
              {summary && summary.addresses.length > 0 ? (
                <span className="font-mono">
                  {" · "}
                  {summary.addresses.slice(0, 2).join(", ")}
                </span>
              ) : null}
            </div>
            {/* Below the wide step the certificate and stage 1 have no columns, and below 3xl neither have the verification and stage 2; they move under the name instead of disappearing. */}
            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground @wide:hidden">
              <span className="@3xl:hidden">
                <VerificationBadge asset={asset} />
              </span>
              <Stage1Badge asset={asset} />
              <span className="@3xl:hidden">
                <Stage2Badge asset={asset} />
              </span>
              {summary?.certificateExpires ? (
                <span>
                  {t("exposure.columnCertificate")}:{" "}
                  <CertificateExpiry expires={summary.certificateExpires} />
                </span>
              ) : null}
              {when ? (
                <time dateTime={when} className="@3xl:hidden">
                  {formatRelative(when)}
                </time>
              ) : null}
            </div>
          </div>
        </div>
      </td>
      <td className="hidden px-3 py-3 @3xl:table-cell">
        <VerificationBadge asset={asset} />
      </td>
      <td className="px-3 py-3 text-right tabular-nums">
        <CountPill severity="critical" n={asset.open.critical} />
      </td>
      <td className="px-3 py-3 text-right tabular-nums">
        <CountPill severity="high" n={asset.open.high} />
      </td>
      <td className="px-3 py-3 text-right tabular-nums">
        <CountPill severity="medium" n={asset.open.medium} />
      </td>
      <td className="hidden px-3 py-3 text-right tabular-nums @wide:table-cell">
        <CountPill severity="low" n={asset.open.low} />
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        <CertificateExpiry expires={summary?.certificateExpires ?? null} />
      </td>
      <td className="hidden px-3 py-3 @wide:table-cell">
        <Stage1Badge asset={asset} />
      </td>
      <td className="hidden px-3 py-3 @3xl:table-cell">
        <Stage2Badge asset={asset} />
        {asset.stage2.summary && asset.stage2.enabled ? (
          <div className="mt-1 text-sm text-muted-foreground">
            {t("exposure.openPortsCount", { count: asset.stage2.summary.open })}
          </div>
        ) : null}
      </td>
      <td className="hidden px-3 py-3 text-sm @xwide:table-cell">
        {summary?.country ? (
          <>
            {countryName(summary.country, i18n.language)}
            {summary.asn ? <div className="text-muted-foreground">AS{summary.asn}</div> : null}
          </>
        ) : (
          <span className="text-muted-foreground">–</span>
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
      {canEdit ? (
        <td className="px-3 py-2 text-right @wide:px-5">
          <ActionMenu label={t("exposure.moreActions", { name: asset.value })} actions={actions} />
          {check.isError ? (
            <p role="alert" className="mt-1.5 text-right text-sm text-destructive-text">
              {t("errors.actionFailed")}
            </p>
          ) : null}
          <ConfirmDialog
            open={confirmRemove}
            title={t("exposure.removeTitle", { asset: asset.value })}
            description={t("exposure.removeDescription")}
            confirmLabel={t("exposure.remove")}
            pending={remove.isPending}
            error={removeFailed ? t("errors.actionFailed") : null}
            onConfirm={() => remove.mutate()}
            onClose={() => setConfirmRemove(false)}
          />
        </td>
      ) : null}
    </tr>
  );
}
