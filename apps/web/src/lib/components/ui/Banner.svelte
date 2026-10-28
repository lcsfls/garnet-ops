<script lang="ts">
  import { TriangleAlert } from "@lucide/svelte";
  import type { Snippet } from "svelte";

  /** A page-level notice that needs attention (mockup .alert): title, one sentence, one action. */
  let { title, children, action }: { title: string; children?: Snippet; action?: Snippet } = $props();
</script>

<div
  role="status"
  class="mb-5 flex flex-wrap items-center gap-3.5 rounded-xl border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-[18px] py-3.5"
>
  <TriangleAlert aria-hidden="true" class="size-[18px] flex-none text-warning-text" />
  <div class="min-w-0 flex-[1_1_20rem]">
    <b class="block font-semibold">{title}</b>
    {#if children}<span class="text-muted-foreground">{@render children()}</span>{/if}
  </div>
  {#if action}<div class="ml-auto">{@render action()}</div>{/if}
</div>
