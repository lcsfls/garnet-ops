<script lang="ts">
  import { Check, Copy } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Button from "./Button.svelte";

  /** Copies text to the clipboard and confirms it for two seconds. */
  let { text }: { text: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // The browser refused (no permission, or not a secure page): say so instead of nothing.
      toast.error(t("toast.copyFailed"));
      return;
    }
    copied = true;
    // A screen reader does not hear the button's label change; the toast is announced.
    toast.success(t("toast.copied"));
    setTimeout(() => (copied = false), 2000);
  }
</script>

<Button variant="outline" onclick={copy}>
  {#if copied}<Check aria-hidden="true" class="size-4" />{:else}<Copy aria-hidden="true" class="size-4" />{/if}
  {copied ? t("common.copied") : t("common.copy")}
</Button>
