<script lang="ts">
  import { cn } from "../cn.ts";

  /** A repository's name, leading to its page (scan and patch history). */
  let { id, name, class: className }: { id: string; name: string; class?: string } = $props();
</script>

<a href="/repositories/{encodeURIComponent(id)}" class={cn("hover:underline", className)}>{name}</a>
