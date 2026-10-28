<script lang="ts">
  import { Sparkles, TriangleAlert } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { cn } from "../../cn.ts";
  import { language, t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import type { AiThread } from "../../types.ts";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import { active } from "./ai-panel.ts";
  import AssistantMessage from "./AssistantMessage.svelte";
  import Composer from "./Composer.svelte";
  import NotReady from "./NotReady.svelte";
  import { followThread } from "./thread-stream.svelte.ts";
  import UserMessage from "./UserMessage.svelte";

  /**
   * The AI conversation about one finding (ADR 0013): the structured triage, then free questions. Everything the model
   * wrote is untrusted and shown as text or through the safe Markdown renderer. It is always labelled as a suggestion
   * and changes nothing by itself.
   */
  let {
    findingId,
    me,
    variant,
  }: {
    findingId: string;
    me: Me;
    /** "pane": a card of its own beside the finding (xwide); "drawer": fills the drawer. */
    variant: "pane" | "drawer";
  } = $props();

  const queryClient = useQueryClient();
  const key = $derived(["ai-thread", findingId]);
  let pollFallback = $state(false);
  const thread = createQuery(() => {
    // Read here, so a switch to or from polling re-applies the options (as a re-render did in React).
    const poll = pollFallback;
    return {
      queryKey: key,
      queryFn: () => api<AiThread>(`/ai/findings/${findingId}/thread`),
      // Only when the live stream cannot be used does the panel ask again and again.
      refetchInterval: (query) =>
        poll && query.state.data?.messages.some(active) ? 2000 : false,
    };
  });
  const data = $derived(thread.data);
  // Primitive values: the stream is opened again only when one of them changes, not on every piece of text.
  const threadId = $derived(data?.threadId ?? null);
  const running = $derived(data?.messages.some(active) ?? false);
  const stream = followThread(
    () => threadId,
    () => running,
    () => key,
    (poll) => (pollFallback = poll),
  );

  let error = $state<string | null>(null);
  function failed(e: unknown) {
    const code = e instanceof ApiError ? e.code : null;
    error = t(
      code === "ai-busy"
        ? "ai.askError.busy"
        : code === "ai-thread-busy"
          ? "ai.askError.threadBusy"
          : code === "rate-limited"
            ? "ai.askError.rateLimited"
            : code === "ai-not-ready"
              ? "ai.askError.notReady"
              : "ai.askError.generic",
    );
  }
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });
  const options = {
    onMutate: () => {
      error = null;
    },
    onSuccess: refresh,
    onError: failed,
  };
  const start = createMutation(() => ({
    mutationFn: () => api(`/ai/findings/${findingId}/triage`, { method: "POST", body: { language: language() } }),
    ...options,
  }));
  const ask = createMutation(() => ({
    mutationFn: (content: string) =>
      api(`/ai/threads/${data?.threadId}/messages`, { method: "POST", body: { content, language: language() } }),
    ...options,
  }));
  const stop = createMutation(() => ({
    mutationFn: (id: string) => api(`/ai/messages/${id}/stop`, { method: "POST" }),
    ...options,
  }));
  const regenerate = createMutation(() => ({
    mutationFn: (id: string) =>
      api(`/ai/messages/${id}/regenerate`, { method: "POST", body: { language: language() } }),
    ...options,
  }));
  const accept = createMutation(() => ({
    mutationFn: (id: string) => api(`/ai/messages/${id}/accept-note`, { method: "POST" }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await refresh();
      await queryClient.invalidateQueries({ queryKey: ["finding-notes", findingId] });
    },
    onError: () => {
      error = t("ai.acceptFailed");
    },
  }));

  // Keep the newest text in view while it streams, unless the reader scrolled up.
  let scroller: HTMLDivElement | undefined = $state();
  let stuck = true;
  // After every change of what is shown: new text grows the list, and the reader may have scrolled away on purpose.
  $effect(() => {
    void [data, error, stream.reconnecting, thread.isPending, thread.isError];
    if (scroller && stuck) scroller.scrollTop = scroller.scrollHeight;
  });

  const messages = $derived(data?.messages ?? []);
  const lastAssistant = $derived([...messages].reverse().find((m) => m.role === "assistant"));
  const canAsk = $derived(Boolean(data?.canAsk));
</script>

<section
  aria-label={t("ai.panelTitle")}
  class={cn(
    "flex min-h-0 min-w-0 flex-col",
    variant === "pane" ? "h-full rounded-xl border bg-card text-card-foreground shadow-xs" : "h-full",
  )}
>
  <div class="flex flex-wrap items-center gap-x-2 gap-y-1 border-b px-5 py-3">
    {#if variant === "pane"}
      <Sparkles aria-hidden="true" class="size-4 flex-none text-muted-foreground" />
      <h2 class="font-semibold tracking-[-0.01em]">{t("ai.panelTitle")}</h2>
    {/if}
    {#if data?.state === "ready"}
      {#if data.scope === "external"}
        <Badge class="bg-warning/18 text-warning-text">
          <TriangleAlert aria-hidden="true" />
          {t("ai.externalBadge")}
        </Badge>
      {/if}
      {#if data.insecureTransport && data.scope !== "external"}
        <Badge tone="neutral">{t("ai.insecureBadge")}</Badge>
      {/if}
      <span class="ml-auto max-w-full truncate font-mono text-[13px] text-muted-foreground"
        >{t("ai.modelLine", { model: data.model ?? "" })}</span
      >
    {/if}
  </div>

  <div
    bind:this={scroller}
    onscroll={(e) => {
      const el = e.currentTarget;
      stuck = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    }}
    class="min-h-0 flex-1 overflow-y-auto"
  >
    {#if thread.isPending}<p class="px-5 py-4 text-muted-foreground">{t("common.loading")}</p>{/if}
    {#if thread.isError}
      <div class="px-5 py-4"><Alert tone="error">{t("errors.generic")}</Alert></div>
    {/if}

    {#if data && data.state !== "ready"}<NotReady state={data.state} {me} />{/if}

    {#if data?.state === "ready" && messages.length === 0}
      <div class="grid gap-3 px-5 py-4">
        <p class="text-muted-foreground">{t("ai.empty")}</p>
        <p class="text-sm text-muted-foreground">{t("ai.suggestionHint")}</p>
        {#if canAsk}
          <Button class="justify-self-start" disabled={start.isPending} onclick={() => start.mutate()}>
            <Sparkles aria-hidden="true" class="size-4" />
            {start.isPending ? t("ai.startingTriage") : t("ai.startTriage")}
          </Button>
        {:else}
          <p class="text-sm text-muted-foreground">{t("ai.viewerNote")}</p>
        {/if}
      </div>
    {/if}

    <ol class="grid">
      {#each messages as message (message.id)}
        <li class="border-b px-5 py-4 last:border-b-0">
          {#if message.role === "user"}
            <UserMessage {message} />
          {:else}
            <AssistantMessage
              {message}
              {canAsk}
              isLast={message.id === lastAssistant?.id && messages.at(-1)?.id === message.id}
              busy={running}
              onStop={() => stop.mutate(message.id)}
              onRegenerate={() => regenerate.mutate(message.id)}
              onAccept={() => accept.mutate(message.id)}
              accepting={accept.isPending}
            />
          {/if}
        </li>
      {/each}
    </ol>
    {#if stream.reconnecting}
      <p role="status" class="px-5 pb-3 text-sm text-muted-foreground">{t("ai.reconnecting")}</p>
    {/if}
  </div>

  {#if error}
    <div class="border-t px-5 py-3"><Alert tone="error">{error}</Alert></div>
  {/if}

  {#if data?.state === "ready" && messages.length > 0}
    {#if canAsk}
      <Composer disabled={running || ask.isPending} onSend={(content) => ask.mutate(content)} pending={ask.isPending} />
    {:else}
      <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("ai.viewerNote")}</p>
    {/if}
  {/if}
</section>
