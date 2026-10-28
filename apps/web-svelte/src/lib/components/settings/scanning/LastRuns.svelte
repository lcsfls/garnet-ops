<script lang="ts">
  import { formatCalendarDate, formatDateTime } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import type { Organization } from "./organization.ts";

  let { runs }: { runs: Organization["lastRuns"] } = $props();
</script>

<Card>
  <CardHeader title={t("settings.lastRuns")} />
  {#if runs.length === 0}
    <p class="px-5 py-5 text-muted-foreground">{t("settings.lastRunsEmpty")}</p>
  {:else}
    <ul>
      {#each runs as run (run.localDate)}
        <li class="flex items-center gap-4 border-b px-5 py-3 last:border-0">
          <span class="font-medium">{formatCalendarDate(run.localDate)}</span>
          <span class="text-muted-foreground">
            {t("settings.queued", { count: run.queuedScans })}
          </span>
          <time datetime={run.createdAt} class="ml-auto text-sm text-muted-foreground">
            {formatDateTime(run.createdAt)}
          </time>
        </li>
      {/each}
    </ul>
  {/if}
</Card>
