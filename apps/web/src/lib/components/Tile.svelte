<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { TONE_CLASSES } from "../severity-meta.ts";
  import Sparkline from "./Sparkline.svelte";

  /**
   * A key figure that links to the list explaining it (mockup .kpi): label and icon, the number, then at most a change
   * and a hint in small muted text. With a tone (overview) the number takes that severity's text colour, and a zero is
   * muted, so what needs no attention does not draw it.
   */
  let {
    label,
    icon,
    value,
    display,
    delta,
    hint,
    href,
    trend,
    tone,
  }: {
    label: string;
    icon?: Snippet;
    value: number;
    /** The value as text when a plain number does not fit, e.g. a percentage. */
    display?: string;
    delta?: Snippet;
    hint?: Snippet | string;
    href: string;
    /** The figure per day or week of its range, drawn as a sparkline under the hint. */
    trend?: (number | null)[];
    /** The colour of the number when it is not zero: a severity (the label says which), or the text colour. */
    tone?: "critical" | "high" | "neutral";
  } = $props();
  const numberClass = $derived(
    tone === undefined
      ? undefined
      : value === 0
        ? "text-muted-foreground"
        : tone === "neutral"
          ? undefined
          : TONE_CLASSES[tone].text,
  );
</script>

<a {href} class="block rounded-xl border bg-card px-[18px] py-4 shadow-xs transition-colors hover:border-input">
  <div class="flex items-center justify-between gap-2 text-[15px] text-muted-foreground">
    <span>{label}</span>
    {@render icon?.()}
  </div>
  <div
    class={cn("mt-1.5 text-[28px] leading-tight font-semibold tracking-[-0.02em] tabular-nums", numberClass)}
    data-zero={tone !== undefined && value === 0 ? "" : undefined}
  >
    {display ?? formatNumber(value)}
  </div>
  {#if delta}<div class="text-[13px] text-muted-foreground">{@render delta()}</div>{/if}
  {#if hint}
    <div class="mt-0.5 text-[13px] text-muted-foreground">
      {#if typeof hint === "string"}{hint}{:else}{@render hint()}{/if}
    </div>
  {/if}
  {#if trend}<Sparkline values={trend} />{/if}
</a>
