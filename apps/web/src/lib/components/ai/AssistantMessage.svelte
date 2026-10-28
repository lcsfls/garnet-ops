<script lang="ts">
  import { partialJsonString } from "@garnetops/core/ai";
  import { RefreshCw, Sparkles, Square } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import type { AiMessage } from "../../types.ts";
  import Markdown from "../Markdown.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import { active, camel, triageText } from "./ai-panel.ts";
  import CopyAction from "./CopyAction.svelte";
  import TriageView from "./TriageView.svelte";
  import WhatSaw from "./WhatSaw.svelte";

  let {
    message,
    canAsk,
    isLast,
    busy,
    onStop,
    onRegenerate,
    onAccept,
    accepting,
  }: {
    message: AiMessage;
    canAsk: boolean;
    isLast: boolean;
    busy: boolean;
    onStop: () => void;
    onRegenerate: () => void;
    onAccept: () => void;
    accepting: boolean;
  } = $props();

  const live = $derived(active(message));
  const triage = $derived(message.kind === "triage");
  const text = $derived(triage && message.structured ? triageText(message.structured) : message.content);
  const stats = $derived.by(() => {
    if (message.status !== "complete" || message.latencyMs === null) return null;
    const parts = [t("ai.seconds", { seconds: (message.latencyMs / 1000).toFixed(1) })];
    if (message.promptTokens !== null && message.completionTokens !== null) {
      parts.push(t("ai.tokens", { prompt: message.promptTokens, completion: message.completionTokens }));
    }
    return parts.join(" · ");
  });
</script>

<div class="grid gap-3">
  <div class="flex flex-wrap items-center gap-2">
    <span class="text-[13px] text-muted-foreground">{t("ai.assistant")}</span>
    <Badge tone="info">
      <Sparkles aria-hidden="true" />
      {t("ai.suggestion")}
    </Badge>
    {#if message.noted}<Badge tone="neutral">{t("ai.accepted")}</Badge>{/if}
  </div>

  {#if message.status === "pending"}
    <p role="status" class="text-muted-foreground">{t("ai.waiting")}</p>
  {:else if triage && message.structured && !live}
    <TriageView result={message.structured} />
  {:else if triage && live}
    {@const summary = partialJsonString(message.content, "summary")}
    <!-- While the JSON of a triage arrives, only its summary (as far as it has come) is shown. -->
    <div role="status" aria-live="polite" class="grid gap-1.5">
      <p class="text-muted-foreground">{t("ai.answering")}</p>
      {#if summary}
        <p class="break-words whitespace-pre-line">{summary}<span aria-hidden="true" class="ai-cursor"></span></p>
      {/if}
    </div>
  {:else if triage && (message.status === "failed" || message.status === "stopped")}
    {@const summary = partialJsonString(message.content, "summary")}
    <!-- The JSON of a cut-off triage is not shown as it is; only the summary that arrived. -->
    {#if summary}<p class="break-words whitespace-pre-line">{summary}</p>{/if}
  {:else if message.content}
    {#if triage && message.status === "complete"}
      <p class="text-sm text-muted-foreground">{t("ai.plainFallback")}</p>
    {/if}
    <div>
      <Markdown text={message.content} />
      {#if live}<span aria-hidden="true" class="ai-cursor"></span>{/if}
    </div>
  {:else if live}
    <p role="status" class="text-muted-foreground">
      {t("ai.answering")}
      <span aria-hidden="true" class="ai-cursor ml-1"></span>
    </p>
  {/if}

  {#if message.status === "failed" || message.status === "stopped"}
    <div class="grid gap-1.5">
      {#if message.content && !(triage && message.structured)}
        <p class="text-sm text-muted-foreground">{t("ai.partial")}</p>
      {/if}
      {#if message.status === "failed" && message.error}
        <Alert tone="error">{t(`ai.error.${camel(message.error)}` as never)}</Alert>
      {/if}
    </div>
  {/if}

  <div class="flex flex-wrap items-center gap-2">
    {#if live && canAsk}
      <Button variant="outline" class="h-8 px-3 text-sm" onclick={onStop}>
        <Square aria-hidden="true" class="size-3.5" />
        {t("ai.stop")}
      </Button>
    {/if}
    {#if !live && message.content}<CopyAction {text} />{/if}
    {#if !live && canAsk && isLast && !busy}
      <Button variant="outline" class="h-8 px-3 text-sm" onclick={onRegenerate}>
        <RefreshCw aria-hidden="true" class="size-3.5" />
        {t("ai.regenerate")}
      </Button>
    {/if}
    {#if message.status === "complete" && canAsk && !message.noted}
      <Button variant="outline" class="h-8 px-3 text-sm" disabled={accepting} onclick={onAccept}>
        {t("ai.acceptNote")}
      </Button>
    {/if}
    {#if stats}<span class="ml-auto text-[13px] text-muted-foreground">{stats}</span>{/if}
  </div>

  {#if triage && message.status !== "pending"}<WhatSaw messageId={message.id} />{/if}
</div>
