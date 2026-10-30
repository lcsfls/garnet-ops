<script lang="ts">
  import { daysUntilEol } from "@garnetops/core/software";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDate } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Badge from "../ui/Badge.svelte";

  /** Websites (ADR 0041): software whose release line still gets fixes but ends within 90 days. Ended lines are findings already. */
  interface Item {
    assetId: string;
    asset: string;
    name: string;
    version: string;
    cycle: string | null;
    eol: string | null;
  }

  const list = createQuery(() => ({
    queryKey: ["early-warnings", "websites"],
    queryFn: () => api<{ enabled: boolean; items: Item[] }>("/early-warnings/websites"),
    refetchInterval: 300_000,
  }));
</script>

<Card>
  <p class="border-b px-5 py-3 text-sm text-muted-foreground">{t("earlyWarnings.websitesHint")}</p>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("earlyWarnings.columnWebsite")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnSoftware")}</th>
        <th class="px-5 py-2.5 font-medium">{t("earlyWarnings.columnEnds")}</th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as item (`${item.assetId}:${item.name}`)}
        <tr class="border-b align-top last:border-0" data-testid="early-warning-website">
          <td class="px-5 py-2.5">
            <a href={`/websites/${encodeURIComponent(item.assetId)}?tab=http`} class="font-medium break-all hover:underline"
              >{item.asset}</a
            >
          </td>
          <td class="px-3 py-2.5">
            {item.name} <span class="font-mono text-sm">{item.version}</span>
            {#if item.cycle}<span class="text-sm text-muted-foreground"> · {t("earlyWarnings.line", { cycle: item.cycle })}</span>{/if}
          </td>
          <td class="px-5 py-2.5">
            {#if item.eol}
              <Badge tone="medium">
                {t("earlyWarnings.distributionEndsIn", { days: daysUntilEol(item.eol, new Date()) ?? 0 })}
              </Badge>
              <span class="ml-1 text-sm text-muted-foreground">{formatDate(item.eol)}</span>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground" data-testid="early-warnings-empty">{t("earlyWarnings.websitesEmpty")}</p>
  {/if}
</Card>
