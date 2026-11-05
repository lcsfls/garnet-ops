<script lang="ts">
  import { cn } from "../../cn.ts";
  import { severityMeta, TONE_CLASSES } from "../../severity-meta.ts";
  import type { Severity } from "../../types.ts";
  import StateIcon from "./StateIcon.svelte";

  /**
   * One shape per severity, so it is told apart without colour (WCAG 1.4.1): critical a flame, high a triangle, medium a
   * circle with a mark, low an "i". For places that show the icon alone (a tab); the severity's word is in its label.
   */
  let {
    severity,
    colored = false,
    class: className,
  }: { severity: Severity; colored?: boolean; class?: string } = $props();
  const meta = $derived(severityMeta(severity));
</script>

<StateIcon name={meta.icon} class={cn("flex-none", colored && TONE_CLASSES[meta.tone].text, className)} />
