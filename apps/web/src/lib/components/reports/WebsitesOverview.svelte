<script lang="ts">
  import { Globe } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { compareWebsites, type WebsiteOverviewRow } from "../../reports.ts";
  import { rowClick } from "../../row-link.ts";
  import { href } from "../../url.ts";
  import { ruleText } from "../../website-rules.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import SortHeader, { type SortDir } from "../SortHeader.svelte";
  import Badge from "../ui/Badge.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /**
   * Every website at a glance (ADR 0047): the state of its daily look, worst first, sortable, each row opening the site's
   * report. The same rows are a section of the organisation report. Below the wide step the certificate and the software move
   * under the name, below xwide the verification and the last look; nothing disappears.
   */
  const query = createQuery(() => ({
    queryKey: ["websites", "overview"],
    queryFn: () => api<{ items: WebsiteOverviewRow[] }>("/reports/websites"),
    refetchInterval: 60_000,
  }));

  type Column = "worst" | "value" | "availability" | "certificate" | "software" | "verification" | "checked";
  let sort = $state<Column | undefined>(undefined);
  let dir = $state<SortDir | undefined>(undefined);

  const NATURAL: Record<Column, SortDir> = {
    worst: "desc",
    value: "asc",
    availability: "desc",
    certificate: "asc",
    software: "desc",
    verification: "asc",
    checked: "desc",
  };
  const BY: Record<Column, (a: WebsiteOverviewRow, b: WebsiteOverviewRow) => number> = {
    // Natural order of each column: worst first, A to Z, down first, ending first, most behind first, unverified first, newest first.
    worst: (a, b) => compareWebsites(a, b),
    value: (a, b) => a.value.localeCompare(b.value),
    availability: (a, b) => availabilityRank(a) - availabilityRank(b),
    certificate: (a, b) =>
      (a.certificateDays ?? Number.MAX_SAFE_INTEGER) - (b.certificateDays ?? Number.MAX_SAFE_INTEGER),
    software: (a, b) =>
      b.software.endOfLife.length - a.software.endOfLife.length ||
      b.software.outdated.length - a.software.outdated.length,
    verification: (a, b) => verifyRank(a) - verifyRank(b),
    checked: (a, b) => (b.lastCheckedAt ?? "").localeCompare(a.lastCheckedAt ?? ""),
  };
  const availabilityRank = (w: WebsiteOverviewRow) =>
    w.availability.state === "down" ? 0 : !w.availability.enabled ? 2 : w.availability.state === null ? 3 : 1;
  const verifyRank = (w: WebsiteOverviewRow) => (w.verifyState === "lost" ? 0 : w.verified ? 2 : 1);

  const rows = $derived.by(() => {
    const items = [...(query.data?.items ?? [])];
    const column = sort ?? "worst";
    const reversed = (dir ?? NATURAL[column]) !== NATURAL[column];
    return items.sort((a, b) => (reversed ? -1 : 1) * BY[column](a, b) || compareWebsites(a, b));
  });
  const onSort = (column: string | undefined, next: SortDir | undefined) => {
    sort = column as Column | undefined;
    dir = next;
  };
  const reportHref = (w: WebsiteOverviewRow) =>
    href(`/websites/${encodeURIComponent(w.id)}`, { tab: "report" });
  const worstTitle = (w: WebsiteOverviewRow) =>
    w.worstRule ? ruleText({ rule: w.worstRule, params: {} }).title : null;
</script>

{#snippet availability(w: WebsiteOverviewRow)}
  {#if !w.availability.enabled}
    <span class="text-muted-foreground">{t("reports.websites.off")}</span>
  {:else if w.availability.state === "down"}
    <Badge tone="high">{t("reports.websites.down")}</Badge>
  {:else if w.availability.state === "up"}
    <span>{t("reports.websites.up")}</span>
  {:else}
    <span class="text-muted-foreground">{t("reports.websites.noLook")}</span>
  {/if}
{/snippet}

{#snippet certificate(w: WebsiteOverviewRow)}
  {#if w.certificateDays === null}
    <span class="text-muted-foreground">{t("reports.websites.certificateNone")}</span>
  {:else if w.certificateDays < 0}
    <Badge tone="critical">{t("reports.websites.certificateEnded")}</Badge>
  {:else}
    <time datetime={w.certificateExpires ?? undefined} title={w.certificateExpires ? formatDateTime(w.certificateExpires) : undefined}
      >{t("reports.websites.certificateDays", { days: w.certificateDays })}</time
    >
  {/if}
{/snippet}

{#snippet software(w: WebsiteOverviewRow)}
  {#if w.software.endOfLife.length === 0 && w.software.outdated.length === 0}
    <span class="text-muted-foreground">{t("reports.websites.softwareFine")}</span>
  {:else}
    <span title={[...w.software.endOfLife, ...w.software.outdated].join(", ")}>
      {#if w.software.endOfLife.length > 0}{t("reports.websites.softwareEndOfLife", { count: w.software.endOfLife.length })}{/if}
      {#if w.software.endOfLife.length > 0 && w.software.outdated.length > 0},{/if}
      {#if w.software.outdated.length > 0}{t("reports.websites.softwareBehind", { count: w.software.outdated.length })}{/if}
    </span>
  {/if}
{/snippet}

{#snippet verification(w: WebsiteOverviewRow)}
  {#if w.verified}
    <span>{t("reports.websites.verified")}</span>
  {:else if w.verifyState === "lost"}
    <Badge tone="medium">{t("reports.websites.lost")}</Badge>
  {:else}
    <span class="text-muted-foreground">{t("reports.websites.unverified")}</span>
  {/if}
{/snippet}

{#snippet checked(w: WebsiteOverviewRow)}
  {#if w.checkError}
    <span class="text-muted-foreground">{t("reports.websites.checkFailed")}</span>
  {:else if w.lastCheckedAt}
    <time datetime={w.lastCheckedAt} title={formatDateTime(w.lastCheckedAt)}>{formatRelative(w.lastCheckedAt)}</time>
  {:else}
    <span class="text-muted-foreground">{t("reports.websites.noLook")}</span>
  {/if}
{/snippet}

<Card>
  <CardHeader title={t("reports.websites.title")} description={t("reports.websites.description")} />
  <table class="w-full text-left" data-testid="websites-overview">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-y">
        <SortHeader column="value" label={t("reports.websites.columnWebsite")} natural="asc" class="px-5" current={sort} {dir} {onSort} />
        <SortHeader column="worst" label={t("reports.websites.columnWorst")} natural="desc" class="px-3" current={sort} {dir} {onSort} />
        <SortHeader
          column="availability"
          label={t("reports.websites.columnAvailability")}
          natural="desc"
          class="px-3"
          current={sort}
          {dir}
          {onSort}
        />
        <SortHeader
          column="certificate"
          label={t("reports.websites.columnCertificate")}
          natural="asc"
          class="hidden px-3 @wide:table-cell"
          current={sort}
          {dir}
          {onSort}
        />
        <SortHeader
          column="software"
          label={t("reports.websites.columnSoftware")}
          natural="desc"
          class="hidden px-3 @wide:table-cell"
          current={sort}
          {dir}
          {onSort}
        />
        <SortHeader
          column="verification"
          label={t("reports.websites.columnVerification")}
          natural="asc"
          class="hidden px-3 @xwide:table-cell"
          current={sort}
          {dir}
          {onSort}
        />
        <SortHeader
          column="checked"
          label={t("reports.websites.columnChecked")}
          natural="desc"
          class="hidden px-5 @xwide:table-cell"
          current={sort}
          {dir}
          {onSort}
        />
      </tr>
    </thead>
    <tbody>
      {#each rows as w (w.id)}
        <!-- The whole row opens the report for the mouse; the name link stays the keyboard and screen-reader path. -->
        <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
        <tr
          class="row-link border-b align-top last:border-0"
          data-website={w.value}
          onclick={rowClick(() => void goto(reportHref(w)))}
        >
          <td class="max-w-0 px-5 py-3 @wide:max-w-none">
            <div class="flex min-w-0 items-start gap-2.5">
              <Globe aria-hidden="true" class="mt-1 size-4 flex-none text-muted-foreground" />
              <div class="min-w-0">
                <a href={reportHref(w)} class="font-medium break-all hover:underline">{w.value}</a>
                <dl class="mt-0.5 grid gap-0.5 text-sm text-muted-foreground @xwide:hidden">
                  <div class="@wide:hidden">
                    <dt class="inline">{t("reports.websites.columnCertificate")}:</dt>
                    <dd class="inline">{@render certificate(w)}</dd>
                  </div>
                  <div class="@wide:hidden">
                    <dt class="inline">{t("reports.websites.columnSoftware")}:</dt>
                    <dd class="inline">{@render software(w)}</dd>
                  </div>
                  <div>
                    <dt class="inline">{t("reports.websites.columnVerification")}:</dt>
                    <dd class="inline">{@render verification(w)}</dd>
                  </div>
                  <div>
                    <dt class="inline">{t("reports.websites.columnChecked")}:</dt>
                    <dd class="inline">{@render checked(w)}</dd>
                  </div>
                </dl>
              </div>
            </div>
          </td>
          <td class="px-3 py-3">
            {#if w.worst}
              <SeverityBadge severity={w.worst} />
              {#if worstTitle(w)}<span class="mt-1 block text-sm text-muted-foreground">{worstTitle(w)}</span>{/if}
            {:else}
              <span class="text-muted-foreground">{t("reports.websites.worstNone")}</span>
            {/if}
          </td>
          <td class="px-3 py-3">{@render availability(w)}</td>
          <td class="hidden px-3 py-3 @wide:table-cell">{@render certificate(w)}</td>
          <td class="hidden px-3 py-3 @wide:table-cell">{@render software(w)}</td>
          <td class="hidden px-3 py-3 @xwide:table-cell">{@render verification(w)}</td>
          <td class="hidden px-5 py-3 @xwide:table-cell">{@render checked(w)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus {query} />
  {#if query.data && query.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("reports.websites.empty")}</p>
  {/if}
</Card>
