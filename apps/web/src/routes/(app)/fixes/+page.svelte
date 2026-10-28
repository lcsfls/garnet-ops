<script lang="ts">
  import { GitPullRequest, RefreshCw } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import { cn } from "#lib/cn.ts";
  import FixProposals from "#lib/components/fixes/FixProposals.svelte";
  import FixPullRequests from "#lib/components/fixes/FixPullRequests.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { type FixSearch, fixSearch } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /** Fix proposals (mockup): version updates for open findings, and the pull requests GarnetOps opened (ADR 0014). */
  let { data }: { data: PageData } = $props();

  const search: FixSearch = $derived(parseSearch(fixSearch, new URL(page.url.href)));
  const setSearch = (patch: Partial<FixSearch>, replace = false) =>
    goto(href(page.url.pathname, { ...search, cursor: undefined, ...patch }), {
      reset: false,
      replace,
    });
  const view = $derived(search.view ?? "proposals");
  let queued = $state(false);

  const queryClient = useQueryClient();
  const refresh = createMutation(() => ({
    mutationFn: () => api("/fixes/refresh", { method: "POST", body: {} }),
    onSuccess: () => {
      queued = true;
      // The worker answers in the background: look again a few times while it asks the forge.
      for (const ms of [1500, 4000, 9000]) {
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["fixes"] }), ms);
      }
    },
  }));
</script>

{#snippet actions()}
  {#if refresh.isError}
    <span role="alert" class="text-sm text-destructive-text">
      {t("errors.actionFailed")}
    </span>
  {:else if queued}
    <span role="status" class="text-sm text-muted-foreground">
      {t("fixes.refreshQueued")}
    </span>
  {/if}
  {#if data.me.role !== "viewer"}
    <Button variant="outline" disabled={refresh.isPending} onclick={() => refresh.mutate()}>
      <RefreshCw aria-hidden="true" class={cn("size-4", refresh.isPending && "motion-safe:animate-spin")} />
      {refresh.isPending ? t("fixes.refreshing") : t("fixes.refresh")}
    </Button>
  {/if}
{/snippet}

<PageHeader icon={GitPullRequest} title={t("fixes.title")} description={t("fixes.description")} {actions} />
<div class="mb-4">
  <Segmented
    label={t("fixes.viewLabel")}
    value={view}
    options={[
      { value: "proposals", label: t("fixes.viewProposals") },
      { value: "prs", label: t("fixes.viewPrs") },
    ]}
    onChange={(next) =>
      void goto(href(page.url.pathname, { view: next === "prs" ? "prs" : undefined }), {
        reset: false,
      })}
  />
</div>
{#if view === "prs"}
  <FixPullRequests {search} {setSearch} />
{:else}
  <FixProposals {search} {setSearch} me={data.me} />
{/if}
