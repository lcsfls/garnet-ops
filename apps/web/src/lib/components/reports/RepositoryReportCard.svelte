<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { type RepositoryReport, reportPdfHref } from "../../reports.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import GateBadge from "../GateBadge.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Facts, { type Fact } from "../websites/Facts.svelte";
  import NextSteps from "./NextSteps.svelte";
  import OpenBySeverity from "./OpenBySeverity.svelte";
  import ReportDownload from "./ReportDownload.svelte";
  import WorstFindings from "./WorstFindings.svelte";

  /**
   * The report of one repository (ADR 0047): what was checked and when, what is open (worst first), grade and gate, early
   * warnings and what to do next, and the worst findings. The same data as the PDF; the server builds both with the
   * signed-in person's access. Facts and next steps side by side from the wide step, the worst findings beside them from
   * xwide; below, they stack.
   */
  let { id }: { id: string } = $props();

  const query = createQuery(() => ({
    queryKey: ["repository", id, "report"],
    queryFn: () => api<RepositoryReport>(`/reports/repositories/${encodeURIComponent(id)}`),
  }));
  const report = $derived(query.data);
  const when = (value: string) => `${formatRelative(value)} (${formatDateTime(value)})`;

  const facts = $derived.by((): Fact[] => {
    const r = report;
    if (!r) return [];
    return [
      {
        label: t("reports.repository.lastScan"),
        text: r.lastScan
          ? t(`reports.repository.scanState.${r.lastScan.state}`, { when: formatRelative(r.lastScan.at) })
          : t("reports.never"),
        note: r.lastScan ? formatDateTime(r.lastScan.at) : null,
      },
      {
        label: t("reports.repository.lastSuccessfulScan"),
        text: r.lastSuccessfulScan ? when(r.lastSuccessfulScan.at) : t("reports.never"),
        note: r.lastSuccessfulScan?.commit ? r.lastSuccessfulScan.commit.slice(0, 12) : null,
      },
      {
        label: t("reports.repository.vulnDb"),
        text: r.vulnDb.builtAt
          ? t("reports.vulnDbValue", {
              date: formatDateTime(r.vulnDb.builtAt),
              freshness: t(`reports.freshness.${r.vulnDb.freshness}`),
            })
          : t("reports.vulnDbUnknown"),
      },
      {
        label: t("reports.repository.grade"),
        text: r.grade
          ? r.grade.stale
            ? t("reports.repository.gradeStale", { grade: r.grade.grade })
            : r.grade.grade
          : t("reports.notChecked"),
      },
      {
        label: t("reports.repository.gate"),
        value: r.gate ? gate : undefined,
        text: t("reports.repository.gateResult.none"),
      },
      { label: t("reports.repository.knownExploited"), text: String(r.knownExploited) },
      {
        label: t("reports.repository.accepted"),
        text: t("reports.repository.acceptedValue", { total: r.accepted.total, expired: r.accepted.expired }),
      },
      { label: t("reports.repository.earlyWarnings"), text: String(r.earlyWarnings.open) },
    ];
  });
</script>

{#snippet gate()}
  {#if report?.gate}
    <span class="inline-flex flex-wrap items-center gap-2">
      <GateBadge result={report.gate.result} />
      <time datetime={report.gate.at} title={formatDateTime(report.gate.at)} class="text-muted-foreground"
        >{formatRelative(report.gate.at)}</time
      >
    </span>
  {/if}
{/snippet}

{#snippet download()}
  {#if report}
    <ReportDownload
      href={reportPdfHref(`/reports/repositories/${encodeURIComponent(id)}`)}
      label={t("reports.downloadLabel")}
      testid="repository-report-download"
    />
  {/if}
{/snippet}

<Card id="report">
  <CardHeader title={t("reports.title")} description={t("reports.repository.description")} actions={download} />
  {#if !report}
    <QueryStatus {query} />
  {:else}
    <div class="grid gap-x-6 border-t pt-4 @wide:grid-cols-2 @xwide:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.4fr)]">
      <Facts rows={facts} />
      <div class="grid content-start gap-4 px-5 pb-5">
        <section>
          <h3 class="mb-2 text-sm font-medium text-muted-foreground">{t("reports.repository.open")}</h3>
          <OpenBySeverity counts={report.open} href={(severity) => href("/findings", { repositoryId: id, severity })} />
        </section>
        <NextSteps steps={report.nextSteps} />
      </div>
      <section class="border-t @wide:col-span-2 @xwide:col-span-1 @xwide:border-t-0 @xwide:border-l">
        <div class="flex items-baseline justify-between gap-3 px-5 pt-3 pb-2">
          <h3 class="text-sm font-medium text-muted-foreground">{t("reports.worstTitle")}</h3>
          <a class="link text-sm" href={href("/findings", { repositoryId: id })}
            >{t("reports.allFindings")}</a
          >
        </div>
        <WorstFindings rows={report.top} />
      </section>
    </div>
  {/if}
</Card>
