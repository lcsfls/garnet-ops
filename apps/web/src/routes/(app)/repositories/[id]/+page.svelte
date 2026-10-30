<script lang="ts">
  import { ArrowLeft, Flame, GitBranch, RefreshCw } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import { cn } from "#lib/cn.ts";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import RunningCard from "#lib/components/hosts/RunningCard.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import GradeSummary from "#lib/components/repositories/GradeSummary.svelte";
  import PatchHistory from "#lib/components/repositories/PatchHistory.svelte";
  import RepositoryFacts from "#lib/components/repositories/RepositoryFacts.svelte";
  import RepositoryTrend from "#lib/components/repositories/RepositoryTrend.svelte";
  import ScanHistory from "#lib/components/repositories/ScanHistory.svelte";
  import SharingCard from "#lib/components/repositories/SharingCard.svelte";
  import WriteAccessCard from "#lib/components/repositories/WriteAccessCard.svelte";
  import Tile from "#lib/components/Tile.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { refreshWhenScansFinish } from "#lib/scan-follow.svelte.ts";
  import { type RepositoryDetailSearch, repositoryDetailSearch } from "#lib/search.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import type { RepositoryDetail, Severity } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

  /**
   * One repository: what is open now, how that changed over 30 days, every scan, and the
   * patch history (which finding was fixed when, and which version the repository has now).
   */
  let { data: pageData }: { data: PageData } = $props();
  const me = $derived(pageData.me);
  const id = $derived(page.params.id ?? "");
  const search = $derived(parseSearch(repositoryDetailSearch, page.url));
  const queryClient = useQueryClient();

  const repo = createQuery(() => ({
    queryKey: ["repository", id],
    queryFn: () => api<RepositoryDetail>(`/repositories/${id}`),
    refetchInterval: (q: { state: { data?: RepositoryDetail } }) =>
      (q.state.data?.lastScan && ["queued", "running"].includes(q.state.data.lastScan.state)) ||
      // The worker is checking a new write token (ADR 0014).
      q.state.data?.writeAccess.access?.status === "unchecked"
        ? 4000
        : false,
  }));
  const scan = createMutation(() => ({
    mutationFn: () => api(`/repositories/${id}/scans`, { method: "POST" }),
    onSuccess: () => {
      toast.success(t("toast.scanQueued", { repository: repo.data?.name ?? "" }));
      return queryClient.invalidateQueries();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  function setSearch(patch: Partial<RepositoryDetailSearch>) {
    void goto(href(page.url.pathname, { ...search, ...patch }), { replace: true, reset: false });
  }

  const data = $derived(repo.data);
  const busy = $derived(data?.lastScan ? ["queued", "running"].includes(data.lastScan.state) : false);
  refreshWhenScansFinish(() => busy);
</script>

{#snippet meta()}
  {#if data}<GradeSummary row={data} {id} />{/if}
{/snippet}

{#snippet actions()}
  {#if data}
    <ExportMenu filters={{ repositoryId: id, state: "all" }} />
    {#if me.role !== "viewer"}
      <Button disabled={busy || scan.isPending} onclick={() => scan.mutate()}>
        <RefreshCw aria-hidden="true" class={cn("size-4", busy && "motion-safe:animate-spin")} />
        {busy && data.lastScan ? t(`scanState.${data.lastScan.state}`) : t("repositories.scanNow")}
      </Button>
    {/if}
  {/if}
{/snippet}

{#snippet flame()}
  <Flame aria-hidden="true" class="size-4 text-destructive-text" />
{/snippet}

<a
  href="/repositories"
  class="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
>
  <ArrowLeft aria-hidden="true" class="size-4" />
  {t("repository.back")}
</a>
<PageHeader
  icon={GitBranch}
  title={data?.name ?? t("common.loading")}
  description={data?.url ?? ""}
  meta={data ? meta : undefined}
  actions={data ? actions : undefined}
/>
{#if !data}
  <Card>
    <QueryStatus query={repo} />
  </Card>
{:else}
  <div class="grid gap-4">
    {#if scan.isError}
      <p role="alert" class="text-sm text-destructive-text">{t("errors.actionFailed")}</p>
    {/if}
    <SharingCard repo={data} {me} />
    <div class="grid gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
      <RepositoryFacts repo={data} />
      <div class="grid grid-cols-2 gap-4 @3xl:grid-cols-4">
        {#each SEVERITIES as severity (severity)}
          <Tile
            label={t("repository.openOf", { severity: t(`severity.${severity}`) })}
            icon={severity === "critical" ? flame : undefined}
            value={data.open[severity] ?? 0}
            href={href("/findings", { repositoryId: id, severity })}
          />
        {/each}
      </div>
    </div>
    <WriteAccessCard repo={data} {me} />
    {#if me.organization.modules?.hosts}<RunningCard repositoryId={id} />{/if}
    <div class="grid gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <RepositoryTrend {id} />
      <ScanHistory
        {id}
        cursor={search.scans}
        pageSize={search.scansPageSize}
        onCursor={(scans) => setSearch({ scans })}
        onPageSize={(scansPageSize) => setSearch({ scansPageSize, scans: undefined })}
      />
    </div>
    <PatchHistory
      {id}
      cursor={search.patches}
      pageSize={search.patchesPageSize}
      onCursor={(patches) => setSearch({ patches })}
      onPageSize={(patchesPageSize) => setSearch({ patchesPageSize, patches: undefined })}
    />
  </div>
{/if}
