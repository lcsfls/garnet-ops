<script lang="ts">
  import type { Snippet } from "svelte";
  import LanguagePicker from "./LanguagePicker.svelte";
  import Wordmark from "./Wordmark.svelte";

  /** Single-column layout for setup and sign-in: reading width, one card, one primary action. */
  let {
    title,
    description,
    children,
    footer,
  }: { title: string; description?: string; children: Snippet; footer?: Snippet } = $props();
</script>

<main class="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-6 px-4 py-12">
  <div class="flex items-center justify-between gap-4">
    <Wordmark />
    <LanguagePicker />
  </div>
  <section class="rounded-lg border bg-card p-6 text-card-foreground shadow-xs">
    <h1 class="text-2xl font-semibold tracking-tight">{title}</h1>
    {#if description}<p class="mt-1 text-muted-foreground">{description}</p>{/if}
    <div class="mt-6">{@render children()}</div>
  </section>
  {#if footer}<div class="text-sm text-muted-foreground">{@render footer()}</div>{/if}
</main>
