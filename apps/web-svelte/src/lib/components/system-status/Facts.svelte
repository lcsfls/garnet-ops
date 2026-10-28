<script lang="ts">
  import type { Snippet } from "svelte";

  let { children }: { children: Snippet } = $props();
</script>

<dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 px-5 pt-1 pb-4 text-sm">
  {@render children()}
</dl>
