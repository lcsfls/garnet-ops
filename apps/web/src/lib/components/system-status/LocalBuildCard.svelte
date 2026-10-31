<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { ExternalLink } from "@lucide/svelte";
  import { formatDuration, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import { VULNDB_BUILD_DOCS } from "./links.ts";
  import StatusBadge from "./StatusBadge.svelte";
  import When from "./When.svelte";

  let { build }: { build: SystemStatus["localBuild"] } = $props();
</script>

<Card>
  <CardHeader title={t("systemStatus.localBuild.title")} description={t("systemStatus.localBuild.description")}>
    {#snippet actions()}
      <StatusBadge level={build.level}>
        <span data-testid="local-build-state">
          {build.state === "set_up" ? t("systemStatus.localBuild.setUp") : t("systemStatus.localBuild.notSetUp")}
        </span>
      </StatusBadge>
    {/snippet}
  </CardHeader>
  {#if build.state === "not_set_up"}
    <p class="px-5 pb-4 text-sm text-muted-foreground">
      {t("systemStatus.localBuild.plannedNote")}
      <a
        href={VULNDB_BUILD_DOCS}
        target="_blank"
        rel="noopener noreferrer"
        class="text-primary-text underline-offset-4 hover:underline"
        >{t("systemStatus.localBuild.howTo")}<ExternalLink aria-hidden="true" class="ml-1 inline size-3.5" /></a
      >
    </p>
  {:else}
    <div class="px-5 pb-4">
      {#if build.lastBuildAt}
        <p class="mb-2 text-sm text-muted-foreground">
          {t("systemStatus.localBuild.lastBuild", { when: formatRelative(build.lastBuildAt) })}
        </p>
      {/if}
      {#if build.providers.length === 0}
        <p class="text-sm text-muted-foreground">{t("systemStatus.localBuild.noProviders")}</p>
      {:else}
        <table class="w-full text-left text-sm">
          <thead class="text-muted-foreground">
            <tr>
              <th class="py-1 pr-3 font-medium">{t("systemStatus.localBuild.provider")}</th>
              <th class="py-1 pr-3 font-medium">{t("systemStatus.localBuild.result")}</th>
              <th class="py-1 pr-3 text-right font-medium">{t("systemStatus.localBuild.records")}</th>
              <th class="hidden py-1 pr-3 font-medium @3xl:table-cell">
                {t("systemStatus.localBuild.lastRun")}
              </th>
              <th class="hidden py-1 text-right font-medium @3xl:table-cell">
                {t("systemStatus.localBuild.duration")}
              </th>
            </tr>
          </thead>
          <tbody>
            {#each build.providers as p (p.name)}
              <tr class="border-t">
                <td class="py-1 pr-3 font-mono break-all">{p.name}</td>
                <td class="py-1 pr-3">
                  <StatusBadge level={p.level}>
                    {t(`systemStatus.localBuild.resultValue.${p.result ?? "none"}`)}
                  </StatusBadge>
                </td>
                <td class="py-1 pr-3 text-right tabular-nums">
                  {p.records === null ? "–" : formatNumber(p.records)}
                </td>
                <td class="hidden py-1 pr-3 @3xl:table-cell">
                  {#if p.lastRunAt}<When value={p.lastRunAt} />{:else}–{/if}
                </td>
                <td class="hidden py-1 text-right tabular-nums @3xl:table-cell">
                  {p.durationMs === null ? "–" : formatDuration(p.durationMs / 1000)}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  {/if}
</Card>
