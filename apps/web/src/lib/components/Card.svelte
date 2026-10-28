<script lang="ts">
  import type { Snippet } from "svelte";

  /** A bordered surface for tables and panels. */
  let { class: className = "", id, children }: { class?: string; id?: string; children: Snippet } = $props();
</script>

<section {id} class="min-w-0 rounded-xl border bg-card text-card-foreground shadow-xs {className}">
  {@render children()}
</section>
