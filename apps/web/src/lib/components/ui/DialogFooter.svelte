<script lang="ts">
  import type { Snippet } from "svelte";

  /** The action row of a dialog, separated by a rule (mockup .dialog-foot). */
  let { children }: { children: Snippet } = $props();
</script>

<div class="-mx-[22px] mt-3 flex flex-wrap justify-end gap-2 border-t px-[22px] pt-3.5">
  {@render children()}
</div>
