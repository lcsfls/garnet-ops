<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { AiMessage } from "../../types.ts";

  let { message }: { message: AiMessage } = $props();
</script>

<div>
  <div class="mb-1 text-[13px] text-muted-foreground">{t("ai.asked", { name: message.author ?? "?" })}</div>
  <p class="break-words whitespace-pre-wrap">{message.content}</p>
</div>
