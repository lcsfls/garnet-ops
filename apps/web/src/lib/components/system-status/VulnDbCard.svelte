<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { formatDateTime, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { SOURCE_KEY } from "../../system-status.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Fact from "./Fact.svelte";
  import Facts from "./Facts.svelte";
  import { reasonText } from "./reason.ts";
  import StatusBadge from "./StatusBadge.svelte";
  import When from "./When.svelte";

  let { vulnDb }: { vulnDb: SystemStatus["vulnDb"] } = $props();

  const stateKey = $derived(
    !vulnDb.reported ? "notReported" : vulnDb.valid === false ? "invalid" : vulnDb.freshness,
  );
  const update = $derived(vulnDb.update);
  const reason = $derived(reasonText(update.reason));
  const dueNow = $derived(update.nextAt !== null && new Date(update.nextAt).getTime() <= Date.now());
  const showScanNote = $derived(vulnDb.valid !== false && vulnDb.freshness !== "current");
  const counted = $derived(vulnDb.providers.items.some((p) => p.records !== null));
</script>

<Card>
  <CardHeader title={t("systemStatus.vulnDb.title")} description={t("systemStatus.vulnDb.description")}>
    {#snippet actions()}
      <StatusBadge level={vulnDb.level}>
        <span data-testid="vulndb-state">{t(`systemStatus.vulnDb.state.${stateKey}`)}</span>
      </StatusBadge>
    {/snippet}
  </CardHeader>
  <Facts>
    <Fact label={t("systemStatus.vulnDb.built")}>
      {#if vulnDb.builtAt}
        <time datetime={vulnDb.builtAt} title={formatDateTime(vulnDb.builtAt)}>{formatRelative(vulnDb.builtAt)}</time
        >{vulnDb.ageDays !== null ? ` (${t("systemStatus.vulnDb.age", { days: vulnDb.ageDays })})` : null}
      {:else}
        {t("systemStatus.never")}
      {/if}
    </Fact>
    <Fact label={t("systemStatus.vulnDb.schema")}>
      <span class="font-mono">{vulnDb.schemaVersion ?? "–"}</span>
    </Fact>
    <Fact label={t("systemStatus.vulnDb.source")}>
      {vulnDb.source ? t(`systemStatus.vulnDb.sourceValue.${SOURCE_KEY[vulnDb.source]}`) : "–"}
    </Fact>
    <Fact label={t("systemStatus.vulnDb.checked")}>
      {#if vulnDb.checkedAt}<When value={vulnDb.checkedAt} />{:else}–{/if}
    </Fact>
    <Fact label={t("systemStatus.vulnDb.lastUpdate")}>
      {update.lastResult === "ok" && update.lastAttemptAt
        ? t("systemStatus.vulnDb.updateOk", { when: formatRelative(update.lastAttemptAt) })
        : update.lastResult === "failed" && update.lastAttemptAt
          ? t("systemStatus.vulnDb.updateFailed", {
              when: formatRelative(update.lastAttemptAt),
              reason: reason ?? "",
            })
          : update.mode === null
            ? t("systemStatus.vulnDb.unknownMode")
            : t("systemStatus.vulnDb.noUpdateYet")}
    </Fact>
    <Fact label={t("systemStatus.vulnDb.nextUpdate")}>
      {#if update.mode === "off"}
        {t("systemStatus.vulnDb.nextOff")}
      {:else if update.nextAt}
        {#if dueNow}{t("systemStatus.vulnDb.nextDue")}{:else}<When value={update.nextAt} />{/if}
      {:else if update.mode === null}
        {t("systemStatus.vulnDb.unknownMode")}
      {:else}
        {t("systemStatus.vulnDb.nextNone")}
      {/if}
    </Fact>
    <Fact label={t("systemStatus.vulnDb.thresholds")}>
      {t("systemStatus.vulnDb.thresholdsValue", {
        stale: vulnDb.thresholds.staleAfterDays,
        outdated: vulnDb.thresholds.outdatedAfterDays,
      })}
    </Fact>
  </Facts>
  {#if vulnDb.problem}
    <p class="px-5 pb-3 text-sm text-muted-foreground">
      {t(`systemStatus.vulnDb.problem.${vulnDb.problem}`)}
    </p>
  {/if}
  {#if vulnDb.valid === false}
    <p class="px-5 pb-3 text-sm text-muted-foreground">{t("systemStatus.vulnDb.noDbNote")}</p>
  {/if}
  {#if !vulnDb.reported}
    <p class="px-5 pb-3 text-sm text-muted-foreground">{t("systemStatus.vulnDb.notReportedNote")}</p>
  {/if}
  {#if showScanNote}
    <p class="px-5 pb-3 text-sm text-muted-foreground" data-testid="vulndb-scan-note">
      {t("systemStatus.vulnDb.scanNote")}
    </p>
  {/if}
  {#if vulnDb.reported}
    <div class="border-t px-5 py-3">
      <h3 class="mb-1.5 text-sm font-medium">{t("systemStatus.vulnDb.providers")}</h3>
      {#if vulnDb.providers.available && vulnDb.providers.items.length > 0}
        <table class="w-full text-left text-sm">
          <thead class="text-muted-foreground">
            <tr>
              <th class="py-1 pr-3 font-medium">{t("systemStatus.vulnDb.provider")}</th>
              <th class="py-1 pr-3 text-right font-medium">
                {t("systemStatus.vulnDb.advisories")}
              </th>
              <th class="py-1 font-medium">{t("systemStatus.vulnDb.capturedAt")}</th>
            </tr>
          </thead>
          <tbody>
            {#each vulnDb.providers.items as p (p.name)}
              <tr class="border-t">
                <td class="py-1 pr-3 font-mono break-all">{p.name}</td>
                <td class="py-1 pr-3 text-right tabular-nums">
                  {p.records === null ? "–" : formatNumber(p.records)}
                </td>
                <td class="py-1">{#if p.capturedAt}<When value={p.capturedAt} />{:else}–{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if !counted}
          <p class="mt-1.5 text-sm text-muted-foreground">{t("systemStatus.vulnDb.noCounts")}</p>
        {/if}
      {:else}
        <p class="text-sm text-muted-foreground">{t("systemStatus.vulnDb.providersUnavailable")}</p>
      {/if}
    </div>
  {/if}
</Card>
