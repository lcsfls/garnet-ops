<script lang="ts">
  import { Check, Copy } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";

  let { text }: { text: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      // The clipboard can be blocked; the text stays selectable.
    }
  }
</script>

<Button variant="outline" class="h-8 px-3 text-sm" onclick={copy}>
  {#if copied}
    <Check aria-hidden="true" class="size-3.5" />
  {:else}
    <Copy aria-hidden="true" class="size-3.5" />
  {/if}
  {copied ? t("ai.copied") : t("ai.copy")}
</Button>
