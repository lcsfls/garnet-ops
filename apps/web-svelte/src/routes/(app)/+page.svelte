<script lang="ts" module>
  // The trend is cut into the viewer's own calendar days, so the API needs the browser's zone.
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
</script>

<script lang="ts">
  import { LayoutGrid, RefreshCw, ScanSearch } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import Dashboard from "#lib/components/overview/Dashboard.svelte";
  import EmptyState from "#lib/components/overview/EmptyState.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { cn } from "#lib/cn.ts";
  import { formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import type { Overview } from "#lib/types.ts";
  import type { PageData } from "./$types";

  let { data: pageData }: { data: PageData } = $props();
  const me = $derived(pageData.me);
  const queryClient = useQueryClient();
  const query = createQuery(() => ({
    queryKey: ["overview", timeZone],
    queryFn: () => api<Overview>(`/overview?tz=${encodeURIComponent(timeZone)}`),
    refetchInterval: 30_000,
  }));
  const data = $derived(query.data);
  let queued = $state<number | null>(null);

  const scanAll = createMutation(() => ({
    mutationFn: () => api<{ queued: number }>("/repositories/scan-all", { method: "POST" }),
    onSuccess: async (result: { queued: number }) => {
      queued = result.queued;
      await queryClient.invalidateQueries();
    },
  }));
  const canScan = $derived(me.role !== "viewer" && (data?.repositories.total ?? 0) > 0);
</script>

<PageHeader icon={LayoutGrid} title={t("overview.title")} description={t("overview.description")}>
  {#snippet actions()}
    {#if scanAll.isError}
      <span role="alert" class="text-sm text-destructive-text">
        {t("errors.actionFailed")}
      </span>
    {:else if queued !== null}
      <span role="status" class="text-sm text-muted-foreground">
        {t("overview.scansQueued", { count: queued })}
      </span>
    {:else if query.dataUpdatedAt}
      <span class="text-sm text-muted-foreground">
        {t("overview.updated", { when: formatRelative(new Date(query.dataUpdatedAt)) })}
      </span>
    {/if}
    <Button
      variant="outline"
      class="size-10 px-0"
      aria-label={t("overview.refresh")}
      title={t("overview.refresh")}
      disabled={query.isFetching}
      onclick={() => void query.refetch()}
    >
      <RefreshCw aria-hidden="true" class={cn("size-4", query.isFetching && "motion-safe:animate-spin")} />
    </Button>
    {#if canScan}
      <Button disabled={scanAll.isPending} onclick={() => scanAll.mutate()}>
        <ScanSearch aria-hidden="true" class="size-4" />
        {t("overview.scanAll")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>
{#if !data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else if data.repositories.total === 0}
  <EmptyState />
{:else}
  {#if query.isError}
    <Card class="mb-4">
      <QueryStatus {query} />
    </Card>
  {/if}
  <Dashboard {data} admin={isAdmin(me)} />
{/if}
