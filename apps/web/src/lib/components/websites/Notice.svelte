<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import { TONE_CLASSES } from "../../severity-meta.ts";
  import StateIcon from "../ui/StateIcon.svelte";

  /** A short warning with an icon: medium (amber) like the page-level banner, for things that need a decision before an action. */
  let { title, children }: { title: string; children?: Snippet } = $props();
</script>

<div role="note" class={cn("flex gap-2.5 rounded-md border px-3 py-2.5 text-sm", TONE_CLASSES.medium.callout)}>
  <StateIcon name="triangle-alert" class={cn("mt-0.5 size-4 flex-none", TONE_CLASSES.medium.text)} />
  <div class="min-w-0">
    <b class="block font-semibold">{title}</b>
    {#if children}<div class="text-muted-foreground">{@render children()}</div>{/if}
  </div>
</div>
