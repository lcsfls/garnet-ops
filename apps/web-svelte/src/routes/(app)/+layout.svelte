<script lang="ts">
  import type { Snippet } from "svelte";
  import AppShell from "#lib/components/AppShell.svelte";
  import type { LayoutData } from "./$types";

  let { data, children }: { data: LayoutData; children: Snippet } = $props();
</script>

<AppShell me={data.me}>
  {@render children()}
</AppShell>
