<script lang="ts">
  import { ShieldCheck } from "@lucide/svelte";
  import { cn } from "#lib/cn.ts";
  import GatePipeline from "#lib/components/gates/GatePipeline.svelte";
  import GateRules from "#lib/components/gates/GateRules.svelte";
  import GateRuns from "#lib/components/gates/GateRuns.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { type GateSearch, gateSearch } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /** Quality gates (mockup): rules, recent runs, and how a pipeline asks for a result (ADR 0008). */
  let { data }: { data: PageData } = $props();
  const admin = $derived(isAdmin(data.me));
  const search = $derived(parseSearch(gateSearch, page.url));
  function setSearch(patch: Partial<GateSearch>) {
    void goto(href(page.url.pathname, { ...search, ...patch }), { reset: false });
  }
</script>

<PageHeader icon={ShieldCheck} title={t("gates.title")} description={t("gates.description")} />
<div
  class={cn(
    "grid items-start gap-4",
    "@wide:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)] @wide:[grid-template-areas:'rules_pipeline'_'runs_runs']",
    "@xwide:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,0.9fr)] @xwide:[grid-template-areas:'rules_runs_pipeline']",
  )}
>
  <div class="min-w-0 @wide:[grid-area:rules]">
    <GateRules canEdit={admin} />
  </div>
  <div class="min-w-0 @wide:[grid-area:runs]">
    <GateRuns
      {search}
      onCursor={(cursor) => setSearch({ cursor })}
      onPageSize={(pageSize) => setSearch({ pageSize, cursor: undefined })}
    />
  </div>
  <div class="min-w-0 @wide:[grid-area:pipeline]">
    <GatePipeline
      {admin}
      repositoryId={search.repositoryId}
      onRepository={(repositoryId) => setSearch({ repositoryId })}
    />
  </div>
</div>
