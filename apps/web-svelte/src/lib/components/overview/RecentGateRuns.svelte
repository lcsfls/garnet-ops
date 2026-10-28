<script lang="ts">
  import { ArrowRight } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { GateRunRow, Page } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import GateBadge from "../GateBadge.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";

  /** The last gate results (mockup "Recent gate runs"); only "Passed" is green. */
  const runs = createQuery(() => ({
    queryKey: ["gate-runs", "recent"],
    queryFn: () => api<Page<GateRunRow>>("/gates/runs?pageSize=25"),
  }));
  const items = $derived(runs.data?.items.slice(0, 5) ?? []);
</script>

<Card class="h-full">
  <CardHeader title={t("gates.recentTitle")} description={t("gates.recentDescription")}>
    {#snippet actions()}
      <a href="/gates" class="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline">
        {t("gates.allRuns")}
        <ArrowRight aria-hidden="true" class="size-4" />
      </a>
    {/snippet}
  </CardHeader>
  <QueryStatus query={runs} />
  {#if runs.data && items.length === 0}
    <p class="px-5 pb-6 text-muted-foreground">{t("gates.runsEmpty")}</p>
  {/if}
  <ul class="px-5 pb-3">
    {#each items as run (run.id)}
      <li class="flex items-center gap-2.5 border-t py-2.5 first:border-t-0">
        <GateBadge result={run.result} />
        <span class="min-w-0 flex-1 truncate">
          <RepositoryLink id={run.repositoryId} name={run.repositoryName} />
          <span class="text-muted-foreground">· {t(`gates.trigger.${run.trigger}`)}</span>
        </span>
        <time
          datetime={run.createdAt}
          title={formatDateTime(run.createdAt)}
          class="dash-time flex-none text-[13px] whitespace-nowrap text-muted-foreground"
        >
          {formatRelative(run.createdAt)}
        </time>
      </li>
    {/each}
  </ul>
</Card>
