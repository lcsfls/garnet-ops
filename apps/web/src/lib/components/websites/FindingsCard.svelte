<script lang="ts">
  import { cn } from "../../cn.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { ruleText } from "../../website-rules.ts";
  import { type ExposureDetail, type ExposureFindingRow, SEVERITY_ORDER } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Segmented from "../Segmented.svelte";
  import Badge from "../ui/Badge.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import { SEVERITY_EDGE } from "../ui/tones.ts";

  type State = "open" | "resolved" | "all";
  /**
   * What looks wrong from the outside, in plain sentences, worst first; each with its severity's word, icon and a strip in its
   * colour. A rule this version does not know shows as its id.
   */
  let {
    detail,
    state,
    onState,
    class: className = "",
  }: { detail: ExposureDetail; state: State; onState: (state: State) => void; class?: string } = $props();

  const weight = (f: ExposureFindingRow) =>
    (f.state === "open" ? 0 : 10) + SEVERITY_ORDER.indexOf(f.severity);
  // Stable: findings of the same weight keep the order the API gives them.
  const shown = $derived(
    detail.findings
      .filter((f) => state === "all" || f.state === state)
      .map((f, i) => ({ f, i }))
      .sort((a, b) => weight(a.f) - weight(b.f) || a.i - b.i)
      .map((x) => x.f),
  );
  const open = $derived(detail.findings.filter((f) => f.state === "open").length);
  const resolved = $derived(detail.findings.filter((f) => f.state === "resolved").length);
</script>

<Card class={className}>
  <CardHeader title={t("websites.findingsTitle")} description={t("websites.findingsDescription")} />
  <div class="px-5 pb-3">
    <Segmented
      label={t("websites.findingsFilter")}
      value={state}
      options={[
        { value: "open", label: t("websites.findingState.open"), count: open },
        { value: "resolved", label: t("websites.findingState.resolved"), count: resolved },
        { value: "all", label: t("websites.findingState.all"), count: open + resolved },
      ]}
      onChange={onState}
    />
  </div>
  {#if shown.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">
      {state === "resolved"
        ? t("websites.findingsNoneResolved")
        : detail.stage1.lastAt
          ? t("websites.findingsNone")
          : t("websites.findingsNotYet")}
    </p>
  {:else}
    <ul data-testid="websites-findings">
      {#each shown as f (f.id)}
        {@const text = ruleText(f)}
        <li
          class={cn(
            "border-t border-l-4 py-3 pr-5 pl-4 first:border-t-0",
            f.state === "open" ? SEVERITY_EDGE[f.severity] : "border-l-transparent",
          )}
          data-severity={f.severity}
        >
          <div class="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <b class="font-semibold">{text.title}</b>
            {#if f.state === "resolved"}<Badge tone="neutral">{t("websites.findingState.resolvedBadge")}</Badge>{/if}
            <span class="text-sm text-muted-foreground">{t(`websites.stageName.${f.stage}`)}</span>
          </div>
          {#if text.text}<p class="mt-1 text-sm break-words text-muted-foreground">{text.text}</p>{/if}
          <p class="mt-1 text-xs text-muted-foreground">
            {f.state === "resolved" && f.resolvedAt
              ? t("websites.findingResolvedOn", { when: formatDateTime(f.resolvedAt) })
              : t("websites.findingFirstSeen", { when: formatRelative(f.firstSeenAt) })}
          </p>
        </li>
      {/each}
    </ul>
  {/if}
</Card>
