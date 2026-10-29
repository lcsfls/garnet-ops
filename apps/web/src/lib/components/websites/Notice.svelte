<script lang="ts">
  import { TriangleAlert } from "@lucide/svelte";
  import type { Snippet } from "svelte";

  /** A short warning with an icon: amber like the page-level banner, for things that need a decision before an action. */
  let { title, children }: { title: string; children?: Snippet } = $props();
</script>

<div
  role="note"
  class="flex gap-2.5 rounded-md border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-3 py-2.5 text-sm"
>
  <TriangleAlert aria-hidden="true" class="mt-0.5 size-4 flex-none text-warning-text" />
  <div class="min-w-0">
    <b class="block font-semibold">{title}</b>
    {#if children}<div class="text-muted-foreground">{@render children()}</div>{/if}
  </div>
</div>
