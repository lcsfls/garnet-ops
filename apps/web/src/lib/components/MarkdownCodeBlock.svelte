<script lang="ts">
  import { Check, Copy } from "@lucide/svelte";
  import { t } from "../i18n.svelte.ts";

  /** A code block with its own copy button; long lines scroll inside the block. */
  let { code, language }: { code: string; language: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      // The clipboard can be blocked; the text stays selectable.
    }
  }
</script>

<div class="overflow-hidden rounded-lg border bg-muted">
  <div class="flex items-center gap-2 border-b px-3 py-1 text-[13px] text-muted-foreground">
    <span class="font-mono">{language || "text"}</span>
    <button
      type="button"
      class="ml-auto inline-flex h-7 items-center gap-1.5 rounded-md px-2 hover:bg-accent"
      onclick={copy}
    >
      {#if copied}
        <Check aria-hidden="true" class="size-3.5" />
      {:else}
        <Copy aria-hidden="true" class="size-3.5" />
      {/if}
      {copied ? t("ai.copied") : t("ai.copy")}
    </button>
  </div>
  <pre class="overflow-x-auto p-3 font-mono text-[13px] leading-relaxed"><code>{code}</code></pre>
</div>
