import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Play, Telescope, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  DnsCard,
  dash,
  Facts,
  FindingsCard,
  HistoryCard,
  HttpCard,
  PortsCard,
  TlsCard,
} from "../../components/exposure-detail.tsx";
import { Stage2Dialog, VerifyDialog } from "../../components/exposure-dialogs.tsx";
import {
  countryName,
  Stage1Badge,
  Stage2Badge,
  useExposureError,
  VerificationBadge,
} from "../../components/exposure-parts.tsx";
import { Segmented } from "../../components/filters.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Checkbox } from "../../components/ui/checkbox.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { api } from "../../lib/api.ts";
import { type ExposureDetail, isBusy, verificationKey } from "../../lib/exposure.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { useLayoutStep } from "../../lib/layout-step.ts";
import {
  EXPOSURE_TABS,
  type ExposureDetailSearch,
  type ExposureTab,
  exposureDetailSearch,
} from "../../lib/search.ts";

export const Route = createFileRoute("/_app/exposure_/$id")({
  validateSearch: exposureDetailSearch,
  component: ExposureAssetPage,
});

/**
 * One asset (ADR 0023): where it stands, what stage 1 and stage 2 saw, and what is wrong. Below the wide step the sections are tabs
 * and the findings are one of them; from wide on the findings are a pane of their own beside the tab, and from xwide on the DNS,
 * TLS, HTTP and port details are shown side by side with no tabs.
 */
function ExposureAssetPage() {
  const { t, i18n } = useTranslation();
  const { id } = Route.useParams();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();
  const step = useLayoutStep();
  const canEdit = me.role === "owner" || me.role === "admin";
  const errorText = useExposureError();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removeFailed, setRemoveFailed] = useState(false);

  const query = useQuery({
    queryKey: ["exposure", "asset", id],
    queryFn: () => api<ExposureDetail>(`/exposure/${id}`),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data && isBusy(q.state.data) ? 2500 : false),
  });
  const data = query.data;
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["exposure"] });

  const run = useMutation({
    mutationFn: () => api(`/exposure/${id}/run`, { method: "POST" }),
    onSuccess: refresh,
  });
  const patch = useMutation({
    mutationFn: (body: { includeSubdomains?: boolean; passiveEnabled?: boolean }) =>
      api(`/exposure/${id}`, { method: "PATCH", body }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: () => api(`/exposure/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await refresh();
      await navigate({ to: "/exposure", search: {} });
    },
    onError: () => setRemoveFailed(true),
  });

  const setSearch = (next: Partial<ExposureDetailSearch>) =>
    navigate({ search: (prev) => ({ ...prev, ...next }), replace: true });
  const tab: ExposureTab = search.tab ?? "findings";
  // From the wide step the findings have a pane of their own; the tab then shows one of the others.
  const sideTab: ExposureTab = tab === "findings" ? "dns" : tab;
  const findingsState = search.findings ?? "open";
  const tabs = EXPOSURE_TABS.filter((x) => step === "base" || x !== "findings");

  const verification = data ? verificationKey(data) : null;
  const geo = data?.passive?.geo ?? [];

  return (
    <>
      <Link
        to="/exposure"
        search={{}}
        className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
      >
        <ArrowLeft aria-hidden="true" className="size-4" />
        {t("exposure.back")}
      </Link>
      <PageHeader
        icon={Telescope}
        title={data?.value ?? t("common.loading")}
        description={data ? t(`exposure.kind.${data.kind}`) : ""}
        meta={
          data ? (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <VerificationBadge asset={data} />
              <Stage1Badge asset={data} />
              <Stage2Badge asset={data} />
            </div>
          ) : null
        }
        actions={
          data && canEdit ? (
            <>
              <Button
                disabled={
                  run.isPending || data.stage1.run?.state === "queued" || data.stage1.run?.state === "running"
                }
                onClick={() => run.mutate()}
              >
                <Play aria-hidden="true" className="size-4" />
                {t("exposure.checkNow")}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setRemoveFailed(false);
                  setConfirmRemove(true);
                }}
              >
                <Trash2 aria-hidden="true" className="size-4" />
                {t("exposure.remove")}
              </Button>
            </>
          ) : null
        }
      />
      {!data ? (
        <Card>
          <QueryStatus query={query} />
        </Card>
      ) : (
        <div className="grid gap-4">
          {run.isError ? <Alert tone="error">{t("errors.actionFailed")}</Alert> : null}
          {data.stage1.error ? (
            <Alert tone="error">{t("exposure.stage1Failed", { reason: errorText(data.stage1.error) })}</Alert>
          ) : null}

          <div
            className="grid gap-4 @2xl:grid-cols-2 @wide:grid-cols-3 @xwide:grid-cols-4"
            data-testid="exposure-summary"
          >
            <Card>
              <CardHeader
                title={t("exposure.summaryVerification")}
                actions={
                  canEdit ? (
                    <Button
                      variant="outline"
                      className="h-9 px-3 text-sm"
                      onClick={() => setSearch({ verify: "1" })}
                    >
                      {t("exposure.verifyOpen")}
                    </Button>
                  ) : undefined
                }
              />
              <Facts
                rows={[
                  [
                    t("exposure.summaryState"),
                    verification ? t(`exposure.verification.${verification}`) : "",
                  ],
                  ...(data.verification.method
                    ? ([[t("exposure.summaryMethod"), t(`exposure.method.${data.verification.method}`)]] as [
                        string,
                        React.ReactNode,
                      ][])
                    : []),
                  ...(data.verification.via === "parent" && data.verification.parent
                    ? ([
                        [
                          t("exposure.summaryCoveredBy"),
                          <Link
                            key="p"
                            to="/exposure/$id"
                            params={{ id: data.verification.parent.id }}
                            search={{}}
                            className="text-primary-text hover:underline"
                          >
                            {data.verification.parent.value}
                          </Link>,
                        ],
                      ] as [string, React.ReactNode][])
                    : []),
                  [
                    t("exposure.summaryConfirmed"),
                    data.verification.confirmedAt ? (
                      <time
                        key="c"
                        dateTime={data.verification.confirmedAt}
                        title={formatDateTime(data.verification.confirmedAt)}
                      >
                        {formatRelative(data.verification.confirmedAt)}
                      </time>
                    ) : (
                      dash
                    ),
                  ],
                  ...(data.verification.error && data.verification.state !== "verified"
                    ? ([[t("exposure.summaryProblem"), errorText(data.verification.error)]] as [
                        string,
                        React.ReactNode,
                      ][])
                    : []),
                ]}
              />
              {canEdit && data.kind === "domain" ? (
                <label className="flex items-start gap-2.5 px-5 pb-5 text-sm">
                  <Checkbox
                    className="mt-0.5"
                    checked={data.includeSubdomains}
                    disabled={patch.isPending}
                    onChange={(e) => patch.mutate({ includeSubdomains: e.target.checked })}
                  />
                  <span>
                    {t("exposure.includeSubdomains")}
                    <span className="block text-muted-foreground">{t("exposure.includeSubdomainsHint")}</span>
                  </span>
                </label>
              ) : null}
            </Card>

            <Card>
              <CardHeader title={t("exposure.summaryStage1")} description={t("exposure.summaryStage1Text")} />
              <Facts
                rows={[
                  [
                    t("exposure.summaryLastCheck"),
                    data.stage1.lastAt ? (
                      <time key="l" dateTime={data.stage1.lastAt} title={formatDateTime(data.stage1.lastAt)}>
                        {formatRelative(data.stage1.lastAt)}
                      </time>
                    ) : (
                      dash
                    ),
                  ],
                  [t("exposure.summaryDaily"), data.stage1.enabled ? t("exposure.yes") : t("exposure.no")],
                ]}
              />
              {canEdit ? (
                <label className="flex items-center gap-2.5 px-5 pb-5 text-sm">
                  <Checkbox
                    checked={data.stage1.enabled}
                    disabled={patch.isPending}
                    onChange={(e) => patch.mutate({ passiveEnabled: e.target.checked })}
                  />
                  {t("exposure.stage1Daily")}
                </label>
              ) : null}
            </Card>

            <Card>
              <CardHeader
                title={t("exposure.summaryStage2")}
                description={t("exposure.summaryStage2Text")}
                actions={
                  canEdit ? (
                    <Button
                      variant="outline"
                      className="h-9 px-3 text-sm"
                      onClick={() => setSearch({ stage2: "1" })}
                    >
                      {data.stage2.enabled ? t("exposure.stage2Manage") : t("exposure.stage2Open")}
                    </Button>
                  ) : undefined
                }
              />
              <Facts
                rows={[
                  [
                    t("exposure.summaryState"),
                    data.stage2.enabled
                      ? t(`exposure.schedule.${data.stage2.schedule}`)
                      : t("exposure.stage2State.off"),
                  ],
                  [
                    t("exposure.summaryLastCheck"),
                    data.stage2.lastAt ? (
                      <time key="l" dateTime={data.stage2.lastAt} title={formatDateTime(data.stage2.lastAt)}>
                        {formatRelative(data.stage2.lastAt)}
                      </time>
                    ) : (
                      dash
                    ),
                  ],
                  ...(data.stage2.error
                    ? ([[t("exposure.summaryProblem"), errorText(data.stage2.error)]] as [
                        string,
                        React.ReactNode,
                      ][])
                    : []),
                ]}
              />
            </Card>

            <Card>
              <CardHeader title={t("exposure.summaryWhere")} description={t("exposure.summaryWhereText")} />
              {geo.length === 0 ? (
                <p className="px-5 pb-5 text-sm text-muted-foreground">
                  {data.passive ? t("exposure.noAddress") : t("exposure.notYet")}
                </p>
              ) : (
                <ul className="grid gap-2 px-5 pb-5 text-sm" data-testid="exposure-where">
                  {geo.map((g) => (
                    <li key={g.address}>
                      <span className="font-mono">{g.address}</span>
                      <span className="block text-muted-foreground">
                        {g.country ? countryName(g.country, i18n.language) : t("exposure.locationUnknown")}
                        {g.asn ? ` · AS${g.asn}${g.org ? ` ${g.org}` : ""}` : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          {step === "base" ? (
            <Segmented
              label={t("exposure.tabsLabel")}
              value={tab}
              options={tabs.map((x) => ({ value: x, label: t(`exposure.tab.${x}`) }))}
              onChange={(next) => setSearch({ tab: next === "findings" ? undefined : next })}
            />
          ) : step === "wide" ? (
            <Segmented
              label={t("exposure.tabsLabel")}
              value={sideTab}
              options={tabs.map((x) => ({ value: x, label: t(`exposure.tab.${x}`) }))}
              onChange={(next) => setSearch({ tab: next })}
            />
          ) : null}

          {step === "xwide" ? (
            <div className="grid items-start gap-4 grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
              <FindingsCard
                detail={data}
                state={findingsState}
                onState={(findings) => setSearch({ findings })}
              />
              <div className="grid gap-4">
                <DnsCard detail={data} canEdit={canEdit} />
                <TlsCard detail={data} />
              </div>
              <div className="grid gap-4">
                <HttpCard detail={data} />
                <PortsCard detail={data} canEdit={canEdit} onStage2={() => setSearch({ stage2: "1" })} />
                <HistoryCard detail={data} />
              </div>
            </div>
          ) : step === "wide" ? (
            <div className="grid items-start gap-4 grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
              <FindingsCard
                detail={data}
                state={findingsState}
                onState={(findings) => setSearch({ findings })}
              />
              <TabBody
                tab={sideTab}
                detail={data}
                canEdit={canEdit}
                onStage2={() => setSearch({ stage2: "1" })}
              />
            </div>
          ) : tab === "findings" ? (
            <FindingsCard
              detail={data}
              state={findingsState}
              onState={(findings) => setSearch({ findings })}
            />
          ) : (
            <TabBody tab={tab} detail={data} canEdit={canEdit} onStage2={() => setSearch({ stage2: "1" })} />
          )}

          {canEdit ? (
            <>
              <VerifyDialog
                assetId={id}
                open={search.verify === "1"}
                email={me.user.email}
                onClose={() => setSearch({ verify: undefined })}
              />
              <Stage2Dialog
                asset={data}
                open={search.stage2 === "1"}
                email={me.user.email}
                onClose={() => setSearch({ stage2: undefined })}
              />
              <ConfirmDialog
                open={confirmRemove}
                title={t("exposure.removeTitle", { asset: data.value })}
                description={t("exposure.removeDescription")}
                confirmLabel={t("exposure.remove")}
                pending={remove.isPending}
                error={removeFailed ? t("errors.actionFailed") : null}
                onConfirm={() => remove.mutate()}
                onClose={() => setConfirmRemove(false)}
              />
            </>
          ) : null}
        </div>
      )}
    </>
  );
}

function TabBody({
  tab,
  detail,
  canEdit,
  onStage2,
}: {
  tab: ExposureTab;
  detail: ExposureDetail;
  canEdit: boolean;
  onStage2: () => void;
}) {
  if (tab === "tls") return <TlsCard detail={detail} />;
  if (tab === "http") return <HttpCard detail={detail} />;
  if (tab === "ports") return <PortsCard detail={detail} canEdit={canEdit} onStage2={onStage2} />;
  if (tab === "history") return <HistoryCard detail={detail} />;
  return <DnsCard detail={detail} canEdit={canEdit} />;
}
