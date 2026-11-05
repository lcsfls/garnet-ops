<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { ReportFindingRow } from "../../reports.ts";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /**
   * The worst open findings, up to ten. Ids, packages and versions come from scanned data and are shown as text only. The
   * "where" column (hosts: kernel, host packages or an image) moves under the package below the wide step.
   */
  let { rows, where = false }: { rows: ReportFindingRow[]; where?: boolean } = $props();
  const place = (value: string | undefined) =>
    value === "kernel"
      ? t("reports.host.whereKernel")
      : value === "packages"
        ? t("reports.host.wherePackages")
        : (value ?? "");
</script>

{#if rows.length === 0}
  <p class="px-5 pb-5 text-muted-foreground">{t("reports.noneOpen")}</p>
{:else}
  <table class="w-full text-left text-sm" data-testid="report-worst">
    <thead class="text-muted-foreground">
      <tr class="border-y">
        <th class="px-5 py-2 font-medium">{t("reports.columnSeverity")}</th>
        <th class="px-3 py-2 font-medium">{t("reports.columnVulnerability")}</th>
        <th class="px-3 py-2 font-medium">{t("reports.columnPackage")}</th>
        {#if where}<th class="hidden px-3 py-2 font-medium @wide:table-cell">{t("reports.columnWhere")}</th>{/if}
        <th class="hidden px-3 py-2 font-medium @3xl:table-cell">{t("reports.columnFixedIn")}</th>
        <th class="hidden px-5 py-2 font-medium @wide:table-cell">{t("reports.columnExploited")}</th>
      </tr>
    </thead>
    <tbody>
      {#each rows as row, i (i)}
        <tr class="border-b align-top last:border-0">
          <td class="px-5 py-2"><SeverityBadge severity={row.severity} /></td>
          <td class="px-3 py-2 font-mono break-all">{row.vulnerabilityId}</td>
          <td class="max-w-0 px-3 py-2 @wide:max-w-none">
            <span class="font-mono break-all">{row.packageName}</span>
            <span class="font-mono text-muted-foreground break-all">{row.packageVersion}</span>
            {#if where}<span class="block text-muted-foreground break-all @wide:hidden">{place(row.where)}</span>{/if}
            <span class="block text-muted-foreground @3xl:hidden">
              {t("reports.columnFixedIn")}: {row.fixedIn.join(", ") || "–"}
            </span>
          </td>
          {#if where}<td class="hidden px-3 py-2 break-all @wide:table-cell">{place(row.where)}</td>{/if}
          <td class="hidden px-3 py-2 font-mono break-all @3xl:table-cell">{row.fixedIn.join(", ") || "–"}</td>
          <td class="hidden px-5 py-2 @wide:table-cell">{row.knownExploited ? t("reports.yes") : t("reports.no")}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
