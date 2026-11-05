<script lang="ts">
  import { ArrowRight, ShieldAlert } from "@lucide/svelte";
  import { formatNumber } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { SEVERITY_LEVELS } from "../../severity-meta.ts";
  import type { Overview, Severity } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import { remedyHref } from "./links.ts";

  /**
   * "Fix first": the open findings grouped by the upgrade that closes them (overview.ts, groupRemedies), in the order to
   * fix them. One row per package and installed version across the repositories the viewer sees. The table answers to
   * its card's width: the repository names join at the wide card width.
   */
  let { items, summary }: { items: Overview["remedies"]; summary: Overview["remedySummary"] } = $props();

  /** The severities an upgrade closes, worst first, negligible and unknown counted as low. */
  function closing(bySeverity: Partial<Record<Severity, number>>): { severity: Severity; count: number }[] {
    const low = (bySeverity.low ?? 0) + (bySeverity.negligible ?? 0) + (bySeverity.unknown ?? 0);
    return SEVERITY_LEVELS.map((s) => ({
      severity: s as Severity,
      count: s === "low" ? low : (bySeverity[s] ?? 0),
    })).filter((x) => x.count > 0);
  }
</script>

<Card class="@container/fix">
  <CardHeader title={t("overview.fixFirst")} description={t("overview.fixFirstDescription")}>
    {#snippet actions()}
      <a href="/fixes" class="link inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap">
        {t("nav.fixes")}
        <ArrowRight aria-hidden="true" class="size-4" />
      </a>
    {/snippet}
  </CardHeader>
  {#if items.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">
      {summary.open === 0 ? t("overview.headline.noneText", { open: 0 }) : t("overview.nothingToUpgrade")}
    </p>
  {:else}
    <table class="w-full text-left" data-testid="fix-first">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("overview.columnUpgrade")}</th>
          <th class="px-3 py-2.5 font-medium">{t("overview.columnCloses")}</th>
          <th class="hidden px-3 py-2.5 font-medium @2xl/fix:table-cell">{t("overview.columnRepositories")}</th>
          <th class="px-5 py-2.5 text-right font-medium"><span class="sr-only">{t("overview.columnAction")}</span></th>
        </tr>
      </thead>
      <tbody>
        {#each items as r (r.key)}
          {@const names = r.repositories.map((x) => x.name).join(", ")}
          <tr class="border-b align-top last:border-0" data-remedy={r.packageName}>
            <td class="px-5 py-3">
              <div class="font-medium break-all">{r.packageName}</div>
              <div class="font-mono text-sm text-muted-foreground">
                {#if r.toVersion}
                  <span aria-label={t("overview.upgradeTo", { from: r.fromVersion, to: r.toVersion })}
                    >{r.fromVersion} → {r.toVersion}</span
                  >
                {:else}
                  {r.fromVersion}
                {/if}
              </div>
              <!-- Below the width of the repositories column, its count moves here. -->
              <div class="text-sm text-muted-foreground @2xl/fix:hidden" title={names}>
                {t("overview.repositoryCount", { count: r.repositoryCount })}
              </div>
              {#if !r.complete}
                <div class="mt-1 text-sm" data-testid="no-single-fix">
                  <span class="font-medium">{t("overview.noSingleFix")}.</span>
                  <span class="text-muted-foreground">
                    {#if r.toVersion}
                      {t("overview.noSingleFixCloses", { version: r.toVersion, closed: r.closes.total, total: r.findings })}
                    {/if}
                    {r.laterVersion
                      ? t("overview.noSingleFixLater", { version: r.laterVersion })
                      : t("overview.noSingleFixNone")}
                  </span>
                </div>
              {/if}
            </td>
            <td class="px-3 py-3">
              <div class="flex flex-wrap gap-1">
                {#each closing(r.closes.bySeverity) as c (c.severity)}
                  <SeverityBadge severity={c.severity} count={c.count} />
                {/each}
              </div>
              {#if r.closes.knownExploited > 0}
                <div class="mt-1 inline-flex items-center gap-1 text-sm text-critical">
                  <ShieldAlert aria-hidden="true" class="size-3.5" />
                  {t("overview.knownExploitedCount", { count: formatNumber(r.closes.knownExploited) })}
                </div>
              {/if}
            </td>
            <td class="hidden px-3 py-3 text-sm @2xl/fix:table-cell">
              <span title={names}>{t("overview.repositoryCount", { count: r.repositoryCount })}</span>
              <ul class="hidden text-muted-foreground @4xl/fix:block">
                {#each r.repositories as repo (repo.id)}
                  <li class="truncate"><RepositoryLink id={repo.id} name={repo.name} /></li>
                {/each}
                {#if r.repositoryCount > r.repositories.length}
                  <li>{t("overview.moreRepositories", { count: r.repositoryCount - r.repositories.length })}</li>
                {/if}
              </ul>
            </td>
            <td class="px-5 py-3 text-right">
              <a href={remedyHref(r.packageName, r.proposals)} class="link text-sm font-medium whitespace-nowrap">
                {r.proposals.count > 0
                  ? t("overview.openProposals", { count: r.proposals.count })
                  : t("overview.showFindings", { count: r.findings })}
              </a>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
  {#if summary.open > 0}
    <p class="border-t px-5 py-3 text-sm text-muted-foreground" data-testid="fix-first-summary">
      {t("overview.remedySummary", { upgrades: summary.upgrades, closes: summary.closes, open: summary.open })}
    </p>
  {/if}
</Card>
