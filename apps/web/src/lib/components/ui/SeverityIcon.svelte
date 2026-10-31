<script lang="ts">
  import { CircleAlert, Flame, Info, TriangleAlert } from "@lucide/svelte";
  import { cn } from "../../cn.ts";
  import type { Severity } from "../../types.ts";
  import { SEVERITY_TEXT } from "./tones.ts";

  /**
   * One shape per severity, so it is told apart without colour (WCAG 1.4.1): critical a flame, high a triangle, medium a
   * circle with a mark, low an "i". Decorative: the severity's word is always next to it or in its label.
   */
  let {
    severity,
    colored = false,
    class: className,
  }: { severity: Severity; colored?: boolean; class?: string } = $props();
  const Icon = $derived(
    severity === "critical"
      ? Flame
      : severity === "high"
        ? TriangleAlert
        : severity === "medium"
          ? CircleAlert
          : Info,
  );
</script>

<Icon aria-hidden="true" class={cn("flex-none", colored && SEVERITY_TEXT[severity], className)} />
