<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, description, actions }: { title: string; description?: string; actions?: Snippet } = $props();
</script>

<div class="flex items-start gap-3 px-5 pt-[18px] pb-3">
  <div class="min-w-0 flex-1">
    <h2 class="font-semibold tracking-[-0.01em]">{title}</h2>
    {#if description}<p class="mt-0.5 text-sm text-muted-foreground">{description}</p>{/if}
  </div>
  {@render actions?.()}
</div>
