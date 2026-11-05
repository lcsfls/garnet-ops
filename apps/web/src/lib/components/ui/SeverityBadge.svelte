<script lang="ts">
  import { cn } from "../../cn.ts";
  import { t } from "../../i18n.svelte.ts";
  import { LEVEL_BAR_EMPTY, severityMeta } from "../../severity-meta.ts";
  import type { Severity } from "../../types.ts";
  import Badge from "./Badge.svelte";

  /**
   * The severity pill: its word and a level of four bars (critical four filled, low one), so severity reads without
   * colour (WCAG 1.4.1). The bars are decorative; the accessible name is the word (and the count, when given).
   */
  let { severity, count }: { severity: Severity; count?: number } = $props();
  const meta = $derived(severityMeta(severity));
  /** Rising bars like a signal meter; fixed classes, because the CSP allows no inline styles. */
  const HEIGHTS = ["h-1", "h-1.5", "h-2", "h-2.5"] as const;
</script>

<Badge tone={meta.tone}>
  {count === undefined ? t(meta.label) : `${count} ${t(meta.label)}`}
  <span aria-hidden="true" data-level={meta.level} class="ml-0.5 inline-flex h-2.5 items-end gap-px">
    {#each HEIGHTS as height, i (height)}
      <span class={cn("w-[3px] rounded-[1px]", height, i < meta.level ? meta.bar : LEVEL_BAR_EMPTY)}></span>
    {/each}
  </span>
</Badge>
