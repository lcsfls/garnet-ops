<script lang="ts">
  import { ChevronRight, CircleCheck, CircleDashed } from "@lucide/svelte";
  import { cn } from "../../cn.ts";
  import { formatDate, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { WebsiteTab } from "../../search.ts";
  import { type ReportRow, websiteReport } from "../../website-report.ts";
  import { ruleText } from "../../website-rules.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import { SEVERITY_ORDER } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Badge from "../ui/Badge.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import SeverityIcon from "../ui/SeverityIcon.svelte";
  import { SEVERITY_EDGE } from "../ui/tones.ts";

  /**
   * Everything checked for one website in one list (the report): each area with a plain state and one sentence, problems with the
   * worst finding's title. A row opens the tab with the details. Nothing here is new data; fine is neutral, not green.
   * What needs a look comes first, worst first, with its severity's icon and a strip in its colour; then what is fine, then what
   * was not checked. Each state has its own icon, so none of it depends on colour alone.
   */
  let {
    detail,
    onTab,
    class: className = "",
  }: { detail: ExposureDetail; onTab: (tab: WebsiteTab) => void; class?: string } = $props();

  const rank = (row: ReportRow) =>
    row.state.kind === "problem"
      ? SEVERITY_ORDER.indexOf(row.state.severity)
      : row.state.kind === "ok"
        ? 10
        : 20;
  // Stable: rows of the same rank keep the order of the areas.
  const rows = $derived(
    websiteReport(detail)
      .map((row, i) => ({ row, i }))
      .sort((a, b) => rank(a.row) - rank(b.row) || a.i - b.i)
      .map((x) => x.row),
  );
  const problems = $derived(rows.filter((r) => r.state.kind === "problem").length);

  function sentence(row: ReportRow): string {
    const s = row.state;
    if (s.kind === "notChecked") return t(`websites.report.notChecked.${s.reason}`);
    if (row.area === "availability") {
      const u = detail.uptime;
      const av = detail.availability;
      if (u.state === "down") {
        return u.since
          ? t("websites.report.downSince", { when: formatRelative(u.since) })
          : t("websites.uptimeDown");
      }
      if (s.kind === "problem") return t("websites.report.slow", { ms: formatNumber(av.day.averageMs ?? 0) });
      return av.month.percent === null
        ? t("websites.uptimeUp")
        : t("websites.report.availability", {
            percent: formatNumber(av.month.percent),
            ms: formatNumber(av.month.averageMs ?? 0),
          });
    }
    if (s.kind === "problem" && s.software) {
      const { name, version, status } = s.software;
      return t(`websites.report.software.${status}`, { name: `${name} ${version}` });
    }
    if (s.kind === "problem") {
      const first = s.findings.find((f) => f.severity === s.severity) ?? s.findings[0];
      const title = first ? ruleText(first).title : "";
      return s.findings.length > 1
        ? t("websites.report.andMore", { title, count: s.findings.length - 1 })
        : title;
    }
    switch (row.area) {
      case "certificate": {
        const expires = detail.stage1.summary?.certificateExpires;
        return expires
          ? t("websites.report.ok.certificateUntil", { date: formatDate(expires) })
          : t("websites.report.ok.certificate");
      }
      case "software": {
        const names = detail.software.map((x) => `${x.name} ${x.version}`);
        return names.length > 0
          ? t("websites.report.ok.software", { names: names.join(", ") })
          : t("websites.report.ok.softwareNone");
      }
      case "dnssec": {
        const dnssec = detail.passive?.dns?.dnssec;
        return typeof dnssec === "object" && dnssec.state === "secure"
          ? t("websites.report.ok.dnssecSecure")
          : t("websites.report.ok.dnssec");
      }
      case "ports":
        return t("websites.report.ok.ports", { count: detail.active?.open.length ?? 0 });
      default:
        return t(`websites.report.ok.${row.area}`);
    }
  }
</script>

<Card class={className}>
  <CardHeader title={t("websites.report.title")} description={t("websites.report.description")} />
  <p class="px-5 pb-3" data-testid="websites-report-summary">
    {problems === 0
      ? t("websites.report.allFine", { count: rows.length })
      : t("websites.report.problems", { problems, count: rows.length })}
    {#if detail.stage1.lastAt}
      <span class="text-muted-foreground">· {t("websites.report.lastLook", { when: formatRelative(detail.stage1.lastAt) })}</span>
    {/if}
  </p>
  <ul class="grid border-t @wide:grid-cols-2 @xwide:grid-cols-3" data-testid="websites-report">
    {#each rows as row (row.area)}
      <li class="border-b @wide:odd:border-r @xwide:border-r @xwide:[&:nth-child(3n)]:border-r-0">
        <button
          type="button"
          class={cn(
            "flex h-full w-full items-start gap-3 border-l-4 px-4 py-3 text-left hover:bg-muted/50 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ring",
            row.state.kind === "problem" ? SEVERITY_EDGE[row.state.severity] : "border-l-transparent",
          )}
          data-area={row.area}
          data-state={row.state.kind}
          onclick={() => onTab(row.tab)}
        >
          {#if row.state.kind === "problem"}
            <SeverityIcon severity={row.state.severity} colored class="mt-0.5 size-5" />
          {:else if row.state.kind === "ok"}
            <CircleCheck aria-hidden="true" class="mt-0.5 size-5 flex-none text-muted-foreground" />
          {:else}
            <CircleDashed aria-hidden="true" class="mt-0.5 size-5 flex-none text-muted-foreground/70" />
          {/if}
          <span class="min-w-0 flex-1">
            <span class="flex flex-wrap items-center gap-2">
              <span class="font-medium">{t(`websites.report.area.${row.area}`)}</span>
              {#if row.state.kind === "problem"}
                <SeverityBadge severity={row.state.severity} />
              {:else if row.state.kind === "ok"}
                <Badge tone="neutral">{t("websites.report.fine")}</Badge>
              {:else}
                <span class="text-sm text-muted-foreground">{t("websites.report.notCheckedLabel")}</span>
              {/if}
            </span>
            <span class="mt-0.5 block text-sm break-words text-muted-foreground">{sentence(row)}</span>
          </span>
          <ChevronRight aria-hidden="true" class="mt-1 size-4 flex-none text-muted-foreground" />
        </button>
      </li>
    {/each}
  </ul>
</Card>
