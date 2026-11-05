<script lang="ts">
  import type { Snippet } from "svelte";

  /**
   * The head of a page: title and description on the left, the page's actions on the right. No icon: the navigation
   * already shows it beside the page's name.
   */
  let {
    title,
    description,
    actions,
    meta,
  }: {
    title: string;
    description: string;
    actions?: Snippet;
    /** Facts about the page's subject under the description, e.g. its grade. */
    meta?: Snippet;
  } = $props();
</script>

<div class="mb-5 flex flex-wrap items-start gap-3.5">
  <div class="min-w-0 flex-[1_1_24rem]">
    <h1 class="text-2xl leading-tight font-semibold tracking-tight">{title}</h1>
    <p class="text-muted-foreground">{description}</p>
    {@render meta?.()}
  </div>
  {#if actions}<div class="ml-auto flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
</div>
