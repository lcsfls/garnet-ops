<script lang="ts">
  import { Send } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";
  import { MAX_QUESTION } from "./ai-panel.ts";

  let {
    disabled,
    pending,
    onSend,
  }: {
    disabled: boolean;
    pending: boolean;
    onSend: (content: string) => void;
  } = $props();
  let text = $state("");

  function submit(event?: SubmitEvent) {
    event?.preventDefault();
    const content = text.trim();
    if (!content || disabled) return;
    onSend(content);
    text = "";
  }

  function onKeyDown(event: KeyboardEvent) {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      submit();
    }
  }
</script>

<form onsubmit={submit} class="grid gap-1.5 border-t px-5 py-3">
  <label for="ai-question" class="sr-only">{t("ai.askLabel")}</label>
  <div class="flex items-end gap-2">
    <textarea
      id="ai-question"
      bind:value={text}
      onkeydown={onKeyDown}
      maxlength={MAX_QUESTION}
      rows={2}
      placeholder={t("ai.askPlaceholder")}
      aria-describedby="ai-question-hint"
      class="max-h-40 min-h-12 flex-1 resize-y rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs placeholder:text-muted-foreground"
    ></textarea>
    <Button type="submit" variant="outline" disabled={disabled || text.trim() === ""} aria-label={t("ai.send")}>
      <Send aria-hidden="true" class="size-4" />
      <span class="hidden @xl:inline">{pending ? t("common.loading") : t("ai.send")}</span>
    </Button>
  </div>
  <p id="ai-question-hint" class="text-[13px] text-muted-foreground">{t("ai.sendHint", { max: MAX_QUESTION })}</p>
</form>
