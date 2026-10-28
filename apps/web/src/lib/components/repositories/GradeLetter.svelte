<script lang="ts">
  import { Clock } from "@lucide/svelte";
  import { cn } from "../../cn.ts";
  import type { Grade } from "../../types.ts";
  import { BADGE_TONE } from "../ui/tones.ts";
  import { GRADE_TONE } from "./grade-badge.ts";

  /** The letter in its colour, with a clock when the grade is from an earlier run. */
  let {
    grade,
    stale = false,
    large = false,
    class: className,
  }: { grade: Grade; stale?: boolean; large?: boolean; class?: string } = $props();
</script>

<span
  class={cn(
    "inline-flex min-w-7 items-center justify-center gap-1 rounded-md border border-transparent px-1.5 font-semibold",
    large ? "h-9 min-w-9 text-lg" : "h-7 text-[15px]",
    BADGE_TONE[GRADE_TONE[grade]],
    className,
  )}
>
  {grade}{#if stale}<Clock aria-hidden="true" class={large ? "size-4" : "size-3"} />{/if}
</span>
