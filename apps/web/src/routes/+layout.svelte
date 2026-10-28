<script lang="ts">
  import "../app.css";
  import "#lib/theme.svelte.ts";
  import { QueryClientProvider } from "@tanstack/svelte-query";
  import type { Snippet } from "svelte";
  import { queryClient } from "#lib/query.ts";

  let { children }: { children: Snippet } = $props();
</script>

<QueryClientProvider client={queryClient}>
  {@render children()}
</QueryClientProvider>
