<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { type HostReport, reportPdfHref } from "../../reports.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Facts, { type Fact } from "../websites/Facts.svelte";
  import NextSteps from "./NextSteps.svelte";
  import OpenBySeverity from "./OpenBySeverity.svelte";
  import ReportDownload from "./ReportDownload.svelte";
  import WorstFindings from "./WorstFindings.svelte";

  /**
   * The report of one host (ADR 0047): when the agent last reported, the kernel, the host's own packages and the running
   * images with what is open in each (worst first), early warnings and what to do next, and the worst findings. The same
   * data as the PDF. Hosts belong to the whole organisation; repository names are not part of it.
   */
  let { id }: { id: string } = $props();

  const query = createQuery(() => ({
    queryKey: ["hosts", "host", id, "report"],
    queryFn: () => api<HostReport>(`/reports/hosts/${encodeURIComponent(id)}`),
    refetchInterval: 60_000,
  }));
  const report = $derived(query.data);
  const total = (c: { critical: number; high: number; medium: number; low: number }) =>
    c.critical + c.high + c.medium + c.low;

  const facts = $derived.by((): Fact[] => {
    const r = report;
    if (!r) return [];
    const release = r.kernel.release ?? "–";
    return [
      {
        label: t("reports.host.lastReport"),
        text: r.lastReportAt
          ? r.reporting
            ? formatRelative(r.lastReportAt)
            : t("reports.host.notReporting", { when: formatRelative(r.lastReportAt) })
          : t("reports.never"),
        note: r.lastReportAt ? formatDateTime(r.lastReportAt) : null,
      },
      {
        label: t("reports.host.kernel"),
        text: r.kernel.checked
          ? t("reports.host.kernelValue", { release, count: total(r.kernel.open) })
          : t("reports.host.kernelNotChecked", { release }),
      },
      {
        label: t("reports.host.packages"),
        text: r.packages
          ? t("reports.host.packagesValue", { count: r.packages.count ?? 0, open: total(r.packages.open) })
          : t("reports.host.packagesNone"),
      },
      {
        label: t("reports.host.images"),
        text: t("reports.host.imagesValue", {
          containers: r.images.containers,
          images: r.images.images,
          serious: r.images.withSerious,
          updates: r.images.updates,
        }),
      },
      {
        label: t("reports.host.vulnDb"),
        text: r.vulnDb.builtAt
          ? t("reports.vulnDbValue", {
              date: formatDateTime(r.vulnDb.builtAt),
              freshness: t(`reports.freshness.${r.vulnDb.freshness}`),
            })
          : t("reports.vulnDbUnknown"),
      },
      { label: t("reports.host.earlyWarnings"), text: String(r.earlyWarnings.open) },
    ];
  });
</script>

{#snippet download()}
  {#if report}
    <ReportDownload
      href={reportPdfHref(`/reports/hosts/${encodeURIComponent(id)}`)}
      label={t("reports.downloadLabel")}
      testid="host-report-download"
    />
  {/if}
{/snippet}

<Card id="report">
  <CardHeader title={t("reports.title")} description={t("reports.host.description")} actions={download} />
  {#if !report}
    <QueryStatus {query} />
  {:else}
    <div class="grid gap-x-6 border-t pt-4 @wide:grid-cols-2 @xwide:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.4fr)]">
      <Facts rows={facts} />
      <div class="grid content-start gap-4 px-5 pb-5">
        <section>
          <h3 class="mb-2 text-sm font-medium text-muted-foreground">{t("reports.repository.open")}</h3>
          <OpenBySeverity counts={report.open} />
        </section>
        <NextSteps steps={report.nextSteps} />
      </div>
      <section class="border-t @wide:col-span-2 @xwide:col-span-1 @xwide:border-t-0 @xwide:border-l">
        <h3 class="px-5 pt-3 pb-2 text-sm font-medium text-muted-foreground">{t("reports.worstTitle")}</h3>
        <WorstFindings rows={report.top} where />
      </section>
    </div>
  {/if}
</Card>
