<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../cn.ts";

  /**
   * The list of sections of a page with sections (Settings, Account). Narrow content shows the sections as a wrapping
   * row above the form; from 48 rem of content width they are a column on the left (AGENTS.md rule 5, measured on the
   * content area). Children are `<li>` elements; use `sectionLinkClass` from section-nav.ts for the links.
   */
  let { label, class: className, children }: { label: string; class?: string; children: Snippet } = $props();
</script>

<nav aria-label={label} class={cn("@3xl:sticky @3xl:top-0", className)}>
  <ul class="flex flex-wrap gap-1 @3xl:grid @3xl:gap-0.5">{@render children()}</ul>
</nav>
