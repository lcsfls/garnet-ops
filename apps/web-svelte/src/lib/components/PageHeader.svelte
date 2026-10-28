<script lang="ts">
  import type { LucideIcon } from "@lucide/svelte";
  import type { Snippet } from "svelte";

  let {
    icon: Icon,
    title,
    description,
    actions,
    meta,
  }: {
    icon: LucideIcon;
    title: string;
    description: string;
    actions?: Snippet;
    /** Facts about the page's subject under the description, e.g. its grade. */
    meta?: Snippet;
  } = $props();
</script>

<div class="mb-5 flex flex-wrap items-start gap-3.5">
  <div class="grid size-10 flex-none place-items-center rounded-lg border bg-card shadow-xs">
    <Icon aria-hidden="true" class="size-[18px]" />
  </div>
  <div class="min-w-0 flex-[1_1_24rem]">
    <h1 class="text-2xl leading-tight font-semibold tracking-tight">{title}</h1>
    <p class="text-muted-foreground">{description}</p>
    {@render meta?.()}
  </div>
  {#if actions}<div class="ml-auto flex items-center gap-2">{@render actions()}</div>{/if}
</div>
