<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import { BADGE_TONE, type BadgeTone } from "./tones.ts";

  let {
    tone,
    class: className,
    children,
  }: { tone?: BadgeTone; class?: string; children: Snippet } = $props();
</script>

<span
  class={cn(
    "inline-flex h-[22px] items-center gap-[5px] rounded-md border border-transparent px-2 text-[12.5px] font-medium whitespace-nowrap [&_svg]:size-3",
    tone ? BADGE_TONE[tone] : null,
    className,
  )}
>
  {@render children()}
</span>
