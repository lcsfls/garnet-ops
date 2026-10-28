<script lang="ts">
  import type { Snippet } from "svelte";

  let { label, children }: { label: string; children: Snippet } = $props();
</script>

<dt class="text-muted-foreground">{label}</dt>
<dd class="min-w-0 [overflow-wrap:anywhere]">{@render children()}</dd>
