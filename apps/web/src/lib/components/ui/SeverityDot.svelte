<script lang="ts">
  import { cn } from "../../cn.ts";
  import { severityLevel, TONE_CLASSES } from "../../severity-meta.ts";
  import type { Severity } from "../../types.ts";

  /** A small severity marker in a legend or a count; the word is always in the same row, its label or the legend. */
  let { severity, class: className }: { severity: Severity; class?: string } = $props();
</script>

<span
  aria-hidden="true"
  class={cn("inline-block size-2 flex-none rounded-full", TONE_CLASSES[severityLevel(severity)].swatch, className)}
></span>
