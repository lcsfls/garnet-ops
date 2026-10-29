<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";
  import type { ExposureDetail, ExposureFindingRow } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Segmented from "../Segmented.svelte";
  import Badge from "../ui/Badge.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  type State = "open" | "resolved" | "all";
  /** What looks wrong from the outside, in plain sentences. A rule this version does not know shows as its id. */
  let {
    detail,
    state,
    onState,
    class: className = "",
  }: { detail: ExposureDetail; state: State; onState: (state: State) => void; class?: string } = $props();

  function ruleText(f: Pick<ExposureFindingRow, "rule" | "params">): { title: string; text: string } {
    const titleKey = `websites.rules.${f.rule}.title`;
    if (!hasKey(titleKey)) return { title: f.rule, text: "" };
    const service = typeof f.params.service === "string" ? f.params.service : "";
    const category = typeof f.params.category === "string" ? f.params.category : "";
    const values = {
      ...f.params,
      service: hasKey(`websites.service.${service}`)
        ? t(`websites.service.${service}` as MessageKey)
        : service,
      category: hasKey(`websites.category.${category}`)
        ? t(`websites.category.${category}` as MessageKey)
        : category,
    };
    return {
      title: t(titleKey as MessageKey, values),
      text: t(`websites.rules.${f.rule}.text` as MessageKey, values),
    };
  }

  const shown = $derived(detail.findings.filter((f) => state === "all" || f.state === state));
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
        <li class="border-t px-5 py-3 first:border-t-0">
          <div class="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <b class="font-medium">{text.title}</b>
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
