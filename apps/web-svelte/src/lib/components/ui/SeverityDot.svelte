<script lang="ts">
  import { cn } from "../../cn.ts";
  import type { Severity } from "../../types.ts";
  import { SEVERITY_DOT } from "./tones.ts";

  /** A small severity marker next to a title; the word is always in the same row or its label. */
  let { severity, class: className }: { severity: Severity; class?: string } = $props();
</script>

<span aria-hidden="true" class={cn("inline-block size-2 flex-none rounded-full", SEVERITY_DOT[severity], className)}
></span>
