<script lang="ts">
  import type { Snippet } from "svelte";

  /** A row of a card: the title, its status badge and a few lines of detail. */
  let {
    title,
    badge,
    testId,
    children,
  }: {
    title: Snippet | string;
    badge: Snippet;
    testId?: string;
    children?: Snippet;
  } = $props();
</script>

<li data-testid={testId} class="border-t px-5 py-3 first:border-t-0">
  <div class="flex flex-wrap items-start justify-between gap-x-3 gap-y-1.5">
    <div class="min-w-0 flex-[1_1_10rem] font-medium [overflow-wrap:anywhere]">
      {#if typeof title === "string"}{title}{:else}{@render title()}{/if}
    </div>
    {@render badge()}
  </div>
  {#if children}
    <div class="mt-1 grid gap-1 text-sm [overflow-wrap:anywhere] text-muted-foreground [&>*]:min-w-0">
      {@render children()}
    </div>
  {/if}
</li>
