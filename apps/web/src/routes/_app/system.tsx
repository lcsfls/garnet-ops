import { STATUS_REFRESH_SECONDS } from "@garnetops/core/system-status";
import type { SystemStatus } from "@garnetops/core/system-status-view";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { Activity } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import {
  AppCard,
  IntegrationsCard,
  LocalBuildCard,
  ScannersCard,
  SummaryCard,
  VulnDbCard,
  WorkerCard,
} from "../../components/system-status.tsx";
import { api } from "../../lib/api.ts";

export const SYSTEM_STATUS_QUERY = ["system-status"] as const;

export const Route = createFileRoute("/_app/system")({
  // Owners and admins only; the API enforces the same rule.
  beforeLoad: ({ context }) => {
    if (context.me.role !== "owner" && context.me.role !== "admin")
      throw redirect({ to: "/", replace: true });
  },
  component: SystemStatusPage,
});

/** A card in the columns. It stays whole: a card is never split between two columns. */
function Cell({ testId, children }: { testId: string; children: ReactNode }) {
  return (
    <div data-testid={testId} className="mb-4 break-inside-avoid">
      {children}
    </div>
  );
}

/**
 * Is everything current and running? One read-only page (ADR 0024). It looks again every minute while it is
 * visible (TanStack Query pauses the interval in a hidden tab). Layout steps follow the content area (AGENTS.md
 * rule 5): one column of reading width at the base step, two columns from 1450 px, three from 1900 px.
 */
function SystemStatusPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const query = useQuery({
    queryKey: SYSTEM_STATUS_QUERY,
    queryFn: () => api<SystemStatus>("/system/status"),
    refetchInterval: STATUS_REFRESH_SECONDS * 1000,
    refetchIntervalInBackground: false,
    staleTime: 0,
  });
  const status = query.data;

  return (
    <div className="mx-auto max-w-[72rem] @wide:max-w-none" data-testid="system-status-page">
      <PageHeader
        icon={Activity}
        title={t("systemStatus.title")}
        description={t("systemStatus.description")}
      />
      {status ? (
        <>
          <SummaryCard status={status} fetching={query.isFetching} onRefresh={() => void query.refetch()} />
          <div className="columns-1 gap-4 @wide:columns-2 @xwide:columns-3">
            <Cell testId="system-vulndb">
              <VulnDbCard vulnDb={status.vulnDb} />
            </Cell>
            <Cell testId="system-scanners">
              <ScannersCard scanners={status.scanners} />
            </Cell>
            <Cell testId="system-local-build">
              <LocalBuildCard build={status.localBuild} />
            </Cell>
            <Cell testId="system-integrations">
              <IntegrationsCard integrations={status.integrations} role={me.role} />
            </Cell>
            <Cell testId="system-worker">
              <WorkerCard worker={status.worker} role={me.role} />
            </Cell>
            <Cell testId="system-app">
              <AppCard app={status.app} role={me.role} />
            </Cell>
          </div>
        </>
      ) : (
        <QueryStatus query={query} />
      )}
    </div>
  );
}
