<script lang="ts">
  import { STATUS_REFRESH_SECONDS } from "@garnetops/core/system-status";
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { Activity } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import AppCard from "#lib/components/system-status/AppCard.svelte";
  import IntegrationsCard from "#lib/components/system-status/IntegrationsCard.svelte";
  import { SYSTEM_STATUS_QUERY } from "#lib/components/system-status/links.ts";
  import LocalBuildCard from "#lib/components/system-status/LocalBuildCard.svelte";
  import ScannersCard from "#lib/components/system-status/ScannersCard.svelte";
  import SummaryCard from "#lib/components/system-status/SummaryCard.svelte";
  import VulnDbCard from "#lib/components/system-status/VulnDbCard.svelte";
  import WorkerCard from "#lib/components/system-status/WorkerCard.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import type { PageData } from "./$types";

  /**
   * Is everything current and running? One read-only page (ADR 0024). It looks again every minute while it is
   * visible (TanStack Query pauses the interval in a hidden tab). Layout steps follow the content area (AGENTS.md
   * rule 5): one column of reading width at the base step, two columns from 1450 px, three from 1900 px.
   */
  let { data }: { data: PageData } = $props();
  const query = createQuery(() => ({
    queryKey: SYSTEM_STATUS_QUERY,
    queryFn: () => api<SystemStatus>("/system/status"),
    refetchInterval: STATUS_REFRESH_SECONDS * 1000,
    refetchIntervalInBackground: false,
    staleTime: 0,
  }));
  const status = $derived(query.data);
</script>

<!-- A card in the columns (the cells below) stays whole: a card is never split between two columns. -->
<div class="mx-auto max-w-[72rem] @wide:max-w-none" data-testid="system-status-page">
  <PageHeader icon={Activity} title={t("systemStatus.title")} description={t("systemStatus.description")} />
  {#if status}
    <SummaryCard {status} fetching={query.isFetching} onRefresh={() => void query.refetch()} />
    <div class="columns-1 gap-4 @wide:columns-2 @xwide:columns-3">
      <div data-testid="system-vulndb" class="mb-4 break-inside-avoid">
        <VulnDbCard vulnDb={status.vulnDb} />
      </div>
      <div data-testid="system-scanners" class="mb-4 break-inside-avoid">
        <ScannersCard scanners={status.scanners} />
      </div>
      <div data-testid="system-local-build" class="mb-4 break-inside-avoid">
        <LocalBuildCard build={status.localBuild} />
      </div>
      <div data-testid="system-integrations" class="mb-4 break-inside-avoid">
        <IntegrationsCard integrations={status.integrations} role={data.me.role} />
      </div>
      <div data-testid="system-worker" class="mb-4 break-inside-avoid">
        <WorkerCard worker={status.worker} role={data.me.role} />
      </div>
      <div data-testid="system-app" class="mb-4 break-inside-avoid">
        <AppCard app={status.app} role={data.me.role} />
      </div>
    </div>
  {:else}
    <QueryStatus {query} />
  {/if}
</div>
