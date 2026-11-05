<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { openSeverities, type SeverityCounts } from "../../reports.ts";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /** Open findings by severity, worst first; each badge carries its word and icon, so colour is never the only signal. */
  let { counts, href }: { counts: SeverityCounts; href?: (severity: string) => string } = $props();
  const rows = $derived(openSeverities(counts));
</script>

{#if rows.length === 0}
  <p class="text-muted-foreground">{t("reports.noneOpen")}</p>
{:else}
  <ul class="flex flex-wrap gap-2" data-testid="report-open">
    {#each rows as row (row.severity)}
      <li data-severity={row.severity}>
        {#if href}
          <a href={href(row.severity)} class="rounded-md hover:underline">
            <SeverityBadge severity={row.severity} count={row.count} />
          </a>
        {:else}
          <SeverityBadge severity={row.severity} count={row.count} />
        {/if}
      </li>
    {/each}
  </ul>
{/if}
