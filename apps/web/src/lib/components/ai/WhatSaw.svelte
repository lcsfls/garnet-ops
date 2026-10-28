<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import Alert from "../ui/Alert.svelte";

  /** "What the model saw": the fixed instructions and the exact first message, loaded when opened. */
  let { messageId }: { messageId: string } = $props();
  let open = $state(false);
  const context = createQuery(() => ({
    queryKey: ["ai-context", messageId],
    queryFn: () => api<{ system: string; prompt: string | null }>(`/ai/messages/${messageId}/context`),
    enabled: open,
    staleTime: Number.POSITIVE_INFINITY,
  }));
</script>

<details ontoggle={(e) => (open = e.currentTarget.open)} class="text-sm">
  <summary class="cursor-pointer text-muted-foreground hover:text-foreground">{t("ai.whatSaw")}</summary>
  <div class="mt-2 grid gap-2">
    <p class="text-muted-foreground">{t("ai.whatSawHint")}</p>
    {#if context.data}
      <h3 class="font-medium">{t("ai.whatSawInstructions")}</h3>
      <pre
        class="max-h-48 overflow-auto rounded-md border bg-muted p-2.5 font-mono text-[12.5px] break-words whitespace-pre-wrap">{context
          .data.system}</pre>
      {#if context.data.prompt}
        <h3 class="font-medium">{t("ai.whatSawData")}</h3>
        <pre
          class="max-h-64 overflow-auto rounded-md border bg-muted p-2.5 font-mono text-[12.5px] break-words whitespace-pre-wrap">{context
            .data.prompt}</pre>
      {/if}
    {:else if context.isError}
      <Alert tone="error">{t("errors.generic")}</Alert>
    {:else if open}
      <p class="text-muted-foreground">{t("common.loading")}</p>
    {/if}
  </div>
</details>
