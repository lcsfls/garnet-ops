<script lang="ts">
  import type { Snippet } from "svelte";
  import { formatNumber } from "../format.ts";

  /**
   * A key figure that links to the list explaining it (mockup .kpi): label and icon, the number, then at most a change
   * and a hint in small muted text.
   */
  let {
    label,
    icon,
    value,
    display,
    delta,
    hint,
    href,
  }: {
    label: string;
    icon?: Snippet;
    value: number;
    /** The value as text when a plain number does not fit, e.g. a percentage. */
    display?: string;
    delta?: Snippet;
    hint?: Snippet | string;
    href: string;
  } = $props();
</script>

<a {href} class="block rounded-xl border bg-card px-[18px] py-4 shadow-xs transition-colors hover:border-primary/40">
  <div class="flex items-center justify-between gap-2 text-[15px] text-muted-foreground">
    <span>{label}</span>
    {@render icon?.()}
  </div>
  <div class="mt-1.5 text-[28px] leading-tight font-semibold tracking-[-0.02em]">{display ?? formatNumber(value)}</div>
  {#if delta}<div class="text-[13px] text-muted-foreground">{@render delta()}</div>{/if}
  {#if hint}
    <div class="mt-0.5 text-[13px] text-muted-foreground">
      {#if typeof hint === "string"}{hint}{:else}{@render hint()}{/if}
    </div>
  {/if}
</a>
