import { partialJsonString } from "@garnetops/core/ai";
import { resolveLanguage } from "@garnetops/i18n";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Check, Copy, RefreshCw, Send, Sparkles, Square, TriangleAlert } from "lucide-react";
import { type FormEvent, type KeyboardEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { safeLink } from "../lib/markdown.ts";
import type { Me } from "../lib/session.ts";
import type { AiMessage, AiThread, TriageResult } from "../lib/types.ts";
import { Markdown } from "./markdown.tsx";
import { isAdmin } from "./nav.ts";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

const MAX_QUESTION = 2000;
const active = (m: AiMessage) => m.status === "pending" || m.status === "streaming";

/** "model-not-found" -> "modelNotFound": the key of its message. */
const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

const byteLength = (text: string) => new TextEncoder().encode(text).length;

/**
 * The AI conversation about one finding (ADR 0013): the structured triage, then free questions.
 * Everything the model wrote is untrusted and shown as text or through the safe Markdown
 * renderer. It is always labelled as a suggestion and changes nothing by itself.
 */
export function AiPanel({
  findingId,
  me,
  variant,
}: {
  findingId: string;
  me: Me;
  /** "pane": a card of its own beside the finding (xwide); "drawer": fills the drawer. */
  variant: "pane" | "drawer";
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const key = ["ai-thread", findingId];
  const [pollFallback, setPollFallback] = useState(false);
  const thread = useQuery({
    queryKey: key,
    queryFn: () => api<AiThread>(`/ai/findings/${findingId}/thread`),
    // Only when the live stream cannot be used does the panel ask again and again.
    refetchInterval: (query) => (pollFallback && query.state.data?.messages.some(active) ? 2000 : false),
  });
  const data = thread.data;
  const running = data?.messages.some(active) ?? false;
  const reconnecting = useThreadStream(data?.threadId ?? null, running, key, setPollFallback);
  const language = resolveLanguage(i18n.language);

  const [error, setError] = useState<string | null>(null);
  const failed = (e: unknown) => {
    const code = e instanceof ApiError ? e.code : null;
    setError(
      t(
        code === "ai-busy"
          ? "ai.askError.busy"
          : code === "ai-thread-busy"
            ? "ai.askError.threadBusy"
            : code === "rate-limited"
              ? "ai.askError.rateLimited"
              : code === "ai-not-ready"
                ? "ai.askError.notReady"
                : "ai.askError.generic",
      ),
    );
  };
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });
  const options = { onMutate: () => setError(null), onSuccess: refresh, onError: failed };
  const start = useMutation({
    mutationFn: () => api(`/ai/findings/${findingId}/triage`, { method: "POST", body: { language } }),
    ...options,
  });
  const ask = useMutation({
    mutationFn: (content: string) =>
      api(`/ai/threads/${data?.threadId}/messages`, { method: "POST", body: { content, language } }),
    ...options,
  });
  const stop = useMutation({
    mutationFn: (id: string) => api(`/ai/messages/${id}/stop`, { method: "POST" }),
    ...options,
  });
  const regenerate = useMutation({
    mutationFn: (id: string) => api(`/ai/messages/${id}/regenerate`, { method: "POST", body: { language } }),
    ...options,
  });
  const accept = useMutation({
    mutationFn: (id: string) => api(`/ai/messages/${id}/accept-note`, { method: "POST" }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refresh();
      await queryClient.invalidateQueries({ queryKey: ["finding-notes", findingId] });
    },
    onError: () => setError(t("ai.acceptFailed")),
  });

  // Keep the newest text in view while it streams, unless the reader scrolled up.
  const scroller = useRef<HTMLDivElement>(null);
  const stuck = useRef(true);
  // After every render: new text grows the list, and the reader may have scrolled away on purpose.
  useEffect(() => {
    const el = scroller.current;
    if (el && stuck.current) el.scrollTop = el.scrollHeight;
  });

  const messages = data?.messages ?? [];
  const lastAssistant = [...messages].reverse().find((m) => m.role === "assistant");
  const canAsk = Boolean(data?.canAsk);

  return (
    <section
      aria-label={t("ai.panelTitle")}
      className={cn(
        "flex min-h-0 min-w-0 flex-col",
        variant === "pane" ? "h-full rounded-xl border bg-card text-card-foreground shadow-xs" : "h-full",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b px-5 py-3">
        {variant === "pane" ? (
          <>
            <Sparkles aria-hidden="true" className="size-4 flex-none text-muted-foreground" />
            <h2 className="font-semibold tracking-[-0.01em]">{t("ai.panelTitle")}</h2>
          </>
        ) : null}
        {data?.state === "ready" ? (
          <>
            {data.scope === "external" ? (
              <Badge className="bg-warning/18 text-warning-text">
                <TriangleAlert aria-hidden="true" />
                {t("ai.externalBadge")}
              </Badge>
            ) : null}
            {data.insecureTransport && data.scope !== "external" ? (
              <Badge tone="neutral">{t("ai.insecureBadge")}</Badge>
            ) : null}
            <span className="ml-auto max-w-full truncate font-mono text-[13px] text-muted-foreground">
              {t("ai.modelLine", { model: data.model ?? "" })}
            </span>
          </>
        ) : null}
      </div>

      <div
        ref={scroller}
        onScroll={(e) => {
          const el = e.currentTarget;
          stuck.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
        }}
        className="min-h-0 flex-1 overflow-y-auto"
      >
        {thread.isPending ? <p className="px-5 py-4 text-muted-foreground">{t("common.loading")}</p> : null}
        {thread.isError ? (
          <div className="px-5 py-4">
            <Alert tone="error">{t("errors.generic")}</Alert>
          </div>
        ) : null}

        {data && data.state !== "ready" ? <NotReady state={data.state} me={me} /> : null}

        {data?.state === "ready" && messages.length === 0 ? (
          <div className="grid gap-3 px-5 py-4">
            <p className="text-muted-foreground">{t("ai.empty")}</p>
            <p className="text-sm text-muted-foreground">{t("ai.suggestionHint")}</p>
            {canAsk ? (
              <Button
                className="justify-self-start"
                disabled={start.isPending}
                onClick={() => start.mutate()}
              >
                <Sparkles aria-hidden="true" className="size-4" />
                {start.isPending ? t("ai.startingTriage") : t("ai.startTriage")}
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground">{t("ai.viewerNote")}</p>
            )}
          </div>
        ) : null}

        <ol className="grid">
          {messages.map((message) => (
            <li key={message.id} className="border-b px-5 py-4 last:border-b-0">
              {message.role === "user" ? (
                <UserMessage message={message} />
              ) : (
                <AssistantMessage
                  message={message}
                  canAsk={canAsk}
                  isLast={message.id === lastAssistant?.id && messages.at(-1)?.id === message.id}
                  busy={running}
                  onStop={() => stop.mutate(message.id)}
                  onRegenerate={() => regenerate.mutate(message.id)}
                  onAccept={() => accept.mutate(message.id)}
                  accepting={accept.isPending}
                />
              )}
            </li>
          ))}
        </ol>
        {reconnecting ? (
          <p role="status" className="px-5 pb-3 text-sm text-muted-foreground">
            {t("ai.reconnecting")}
          </p>
        ) : null}
      </div>

      {error ? (
        <div className="border-t px-5 py-3">
          <Alert tone="error">{error}</Alert>
        </div>
      ) : null}

      {data?.state === "ready" && messages.length > 0 ? (
        canAsk ? (
          <Composer
            disabled={running || ask.isPending}
            onSend={(content) => ask.mutate(content)}
            pending={ask.isPending}
          />
        ) : (
          <p className="border-t px-5 py-3 text-sm text-muted-foreground">{t("ai.viewerNote")}</p>
        )
      ) : null}
    </section>
  );
}

function NotReady({ state, me }: { state: "not-configured" | "disabled"; me: Me }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-2 px-5 py-4">
      <p>{state === "disabled" ? t("ai.disabled") : t("ai.notConfigured")}</p>
      {isAdmin(me) ? (
        <Link to="/settings" search={{ section: "ai" }} className="text-primary-text hover:underline">
          {t("ai.openSettings")}
        </Link>
      ) : (
        <p className="text-sm text-muted-foreground">{t("ai.askAdmin")}</p>
      )}
    </div>
  );
}

function Composer({
  disabled,
  pending,
  onSend,
}: {
  disabled: boolean;
  pending: boolean;
  onSend: (content: string) => void;
}) {
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const submit = (event?: FormEvent) => {
    event?.preventDefault();
    const content = text.trim();
    if (!content || disabled) return;
    onSend(content);
    setText("");
  };
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      submit();
    }
  };
  return (
    <form onSubmit={submit} className="grid gap-1.5 border-t px-5 py-3">
      <label htmlFor="ai-question" className="sr-only">
        {t("ai.askLabel")}
      </label>
      <div className="flex items-end gap-2">
        <textarea
          id="ai-question"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onKeyDown}
          maxLength={MAX_QUESTION}
          rows={2}
          placeholder={t("ai.askPlaceholder")}
          aria-describedby="ai-question-hint"
          className="max-h-40 min-h-12 flex-1 resize-y rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs placeholder:text-muted-foreground"
        />
        <Button
          type="submit"
          variant="outline"
          disabled={disabled || text.trim() === ""}
          aria-label={t("ai.send")}
        >
          <Send aria-hidden="true" className="size-4" />
          <span className="hidden @xl:inline">{pending ? t("common.loading") : t("ai.send")}</span>
        </Button>
      </div>
      <p id="ai-question-hint" className="text-[13px] text-muted-foreground">
        {t("ai.sendHint", { max: MAX_QUESTION })}
      </p>
    </form>
  );
}

function UserMessage({ message }: { message: AiMessage }) {
  const { t } = useTranslation();
  return (
    <div>
      <div className="mb-1 text-[13px] text-muted-foreground">
        {t("ai.asked", { name: message.author ?? "?" })}
      </div>
      <p className="break-words whitespace-pre-wrap">{message.content}</p>
    </div>
  );
}

function AssistantMessage({
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
}) {
  const { t } = useTranslation();
  const live = active(message);
  const triage = message.kind === "triage";
  const text = triage && message.structured ? triageText(message.structured) : message.content;

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[13px] text-muted-foreground">{t("ai.assistant")}</span>
        <Badge tone="info">
          <Sparkles aria-hidden="true" />
          {t("ai.suggestion")}
        </Badge>
        {message.noted ? <Badge tone="neutral">{t("ai.accepted")}</Badge> : null}
      </div>

      {message.status === "pending" ? (
        <p role="status" className="text-muted-foreground">
          {t("ai.waiting")}
        </p>
      ) : triage && message.structured && !live ? (
        <TriageView result={message.structured} />
      ) : triage && live ? (
        <TriageStreaming content={message.content} />
      ) : triage && (message.status === "failed" || message.status === "stopped") ? (
        // The JSON of a cut-off triage is not shown as it is; only the summary that arrived.
        <PartialSummary content={message.content} />
      ) : message.content ? (
        <>
          {triage && message.status === "complete" ? (
            <p className="text-sm text-muted-foreground">{t("ai.plainFallback")}</p>
          ) : null}
          <div>
            <Markdown text={message.content} />
            {live ? <span aria-hidden="true" className="ai-cursor" /> : null}
          </div>
        </>
      ) : live ? (
        <p role="status" className="text-muted-foreground">
          {t("ai.answering")}
          <span aria-hidden="true" className="ai-cursor ml-1" />
        </p>
      ) : null}

      {message.status === "failed" || message.status === "stopped" ? (
        <div className="grid gap-1.5">
          {message.content && !(triage && message.structured) ? (
            <p className="text-sm text-muted-foreground">{t("ai.partial")}</p>
          ) : null}
          {message.status === "failed" && message.error ? (
            <Alert tone="error">{t(`ai.error.${camel(message.error)}` as MessageKey)}</Alert>
          ) : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        {live && canAsk ? (
          <Button variant="outline" className="h-8 px-3 text-sm" onClick={onStop}>
            <Square aria-hidden="true" className="size-3.5" />
            {t("ai.stop")}
          </Button>
        ) : null}
        {!live && message.content ? <CopyAction text={text} /> : null}
        {!live && canAsk && isLast && !busy ? (
          <Button variant="outline" className="h-8 px-3 text-sm" onClick={onRegenerate}>
            <RefreshCw aria-hidden="true" className="size-3.5" />
            {t("ai.regenerate")}
          </Button>
        ) : null}
        {message.status === "complete" && canAsk && !message.noted ? (
          <Button variant="outline" className="h-8 px-3 text-sm" disabled={accepting} onClick={onAccept}>
            {t("ai.acceptNote")}
          </Button>
        ) : null}
        <Stats message={message} />
      </div>

      {triage && message.status !== "pending" ? <WhatSaw messageId={message.id} /> : null}
    </div>
  );
}

function triageText(result: TriageResult): string {
  return [result.summary, result.recommendation].filter(Boolean).join("\n\n");
}

/** The facts of a finished triage, as plain text only. */
function TriageView({ result }: { result: TriageResult }) {
  const { t } = useTranslation();
  const links = result.references.map(safeLink).filter((l): l is NonNullable<typeof l> => l !== null);
  return (
    <div className="grid gap-3">
      <dl className="grid grid-cols-3 gap-px overflow-hidden rounded-lg border bg-border text-center">
        <Fact label={t("ai.exploitability")} value={t(`ai.value.${result.exploitability}`)} />
        <Fact label={t("ai.reachable")} value={t(`ai.value.${result.reachable}`)} />
        <Fact label={t("ai.confidence")} value={t(`ai.value.${result.confidence}`)} />
      </dl>
      <div>
        <h3 className="mb-0.5 text-sm font-medium">{t("ai.summary")}</h3>
        <p className="break-words whitespace-pre-line">{result.summary}</p>
      </div>
      {result.recommendation ? (
        <div>
          <h3 className="mb-0.5 text-sm font-medium">{t("ai.recommendation")}</h3>
          <p className="break-words whitespace-pre-line">{result.recommendation}</p>
        </div>
      ) : null}
      {result.upgradeTo ? (
        <p className="text-sm">
          <span className="font-medium">{t("ai.upgradeTo")}: </span>
          <code className="rounded bg-muted px-1 py-px font-mono">{result.upgradeTo}</code>
          <span className="block text-muted-foreground">{t("ai.upgradeHint")}</span>
        </p>
      ) : null}
      {links.length > 0 ? (
        <div>
          <h3 className="mb-0.5 text-sm font-medium">{t("ai.references")}</h3>
          <ul className="grid gap-0.5 text-sm">
            {links.map((link) => (
              <li key={link.href}>
                <a
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="break-all text-primary-text hover:underline"
                >
                  {link.href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-card px-2 py-2">
      <dt className="text-[13px] text-muted-foreground">{label}</dt>
      <dd className="font-semibold">{value}</dd>
    </div>
  );
}

function PartialSummary({ content }: { content: string }) {
  const summary = partialJsonString(content, "summary");
  return summary ? <p className="break-words whitespace-pre-line">{summary}</p> : null;
}

/** While the JSON of a triage arrives, only its summary (as far as it has come) is shown. */
function TriageStreaming({ content }: { content: string }) {
  const { t } = useTranslation();
  const summary = partialJsonString(content, "summary");
  return (
    <div role="status" aria-live="polite" className="grid gap-1.5">
      <p className="text-muted-foreground">{t("ai.answering")}</p>
      {summary ? (
        <p className="break-words whitespace-pre-line">
          {summary}
          <span aria-hidden="true" className="ai-cursor" />
        </p>
      ) : null}
    </div>
  );
}

function Stats({ message }: { message: AiMessage }) {
  const { t } = useTranslation();
  if (message.status !== "complete" || message.latencyMs === null) return null;
  const parts = [t("ai.seconds", { seconds: (message.latencyMs / 1000).toFixed(1) })];
  if (message.promptTokens !== null && message.completionTokens !== null) {
    parts.push(t("ai.tokens", { prompt: message.promptTokens, completion: message.completionTokens }));
  }
  return <span className="ml-auto text-[13px] text-muted-foreground">{parts.join(" · ")}</span>;
}

function CopyAction({ text }: { text: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      className="h-8 px-3 text-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          // The clipboard can be blocked; the text stays selectable.
        }
      }}
    >
      {copied ? (
        <Check aria-hidden="true" className="size-3.5" />
      ) : (
        <Copy aria-hidden="true" className="size-3.5" />
      )}
      {copied ? t("ai.copied") : t("ai.copy")}
    </Button>
  );
}

/** "What the model saw": the fixed instructions and the exact first message, loaded when opened. */
function WhatSaw({ messageId }: { messageId: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const context = useQuery({
    queryKey: ["ai-context", messageId],
    queryFn: () => api<{ system: string; prompt: string | null }>(`/ai/messages/${messageId}/context`),
    enabled: open,
    staleTime: Number.POSITIVE_INFINITY,
  });
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)} className="text-sm">
      <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
        {t("ai.whatSaw")}
      </summary>
      <div className="mt-2 grid gap-2">
        <p className="text-muted-foreground">{t("ai.whatSawHint")}</p>
        {context.data ? (
          <>
            <h3 className="font-medium">{t("ai.whatSawInstructions")}</h3>
            <pre className="max-h-48 overflow-auto rounded-md border bg-muted p-2.5 font-mono text-[12.5px] break-words whitespace-pre-wrap">
              {context.data.system}
            </pre>
            {context.data.prompt ? (
              <>
                <h3 className="font-medium">{t("ai.whatSawData")}</h3>
                <pre className="max-h-64 overflow-auto rounded-md border bg-muted p-2.5 font-mono text-[12.5px] break-words whitespace-pre-wrap">
                  {context.data.prompt}
                </pre>
              </>
            ) : null}
          </>
        ) : context.isError ? (
          <Alert tone="error">{t("errors.generic")}</Alert>
        ) : open ? (
          <p className="text-muted-foreground">{t("common.loading")}</p>
        ) : null}
      </div>
    </details>
  );
}

/**
 * Follows a thread while an answer is being written: the server sends the stored state first
 * (so a reconnect resumes where the text is), then the text as it grows. Returns true while the
 * connection is being re-established. When the stream cannot be used at all, `onFallback`
 * switches the panel to asking again every couple of seconds.
 */
function useThreadStream(
  threadId: string | null,
  running: boolean,
  key: unknown[],
  onFallback: (poll: boolean) => void,
): boolean {
  const queryClient = useQueryClient();
  const [reconnecting, setReconnecting] = useState(false);
  const keyRef = useRef(key);
  keyRef.current = key;

  useEffect(() => {
    if (!threadId || !running) return;
    if (typeof EventSource === "undefined") {
      onFallback(true);
      return;
    }
    const source = new EventSource(`/api/v1/ai/threads/${threadId}/stream`);
    const update = (fn: (thread: AiThread) => AiThread) =>
      queryClient.setQueryData<AiThread>(keyRef.current, (current) => (current ? fn(current) : current));
    const parse = (event: Event): Record<string, unknown> | null => {
      try {
        return JSON.parse((event as MessageEvent<string>).data) as Record<string, unknown>;
      } catch {
        return null;
      }
    };
    source.addEventListener("open", () => {
      setReconnecting(false);
      onFallback(false);
    });
    source.addEventListener("snapshot", (event) => {
      const body = parse(event);
      if (body && Array.isArray(body.messages)) {
        update((thread) => ({ ...thread, messages: body.messages as AiMessage[] }));
      }
    });
    source.addEventListener("delta", (event) => {
      const body = parse(event);
      if (!body || typeof body.id !== "string" || typeof body.text !== "string") return;
      let missed = false;
      update((thread) => ({
        ...thread,
        messages: thread.messages.map((m) => {
          if (m.id !== body.id) return m;
          // Offsets are bytes, as the server counts them; anything out of line is fetched again.
          if (byteLength(m.content) !== body.from) {
            missed = true;
            return m;
          }
          return { ...m, status: "streaming" as const, content: m.content + (body.text as string) };
        }),
      }));
      if (missed) void queryClient.invalidateQueries({ queryKey: keyRef.current });
    });
    source.addEventListener("message", (event) => {
      const body = parse(event) as AiMessage | null;
      if (!body || typeof body.id !== "string") return;
      update((thread) => {
        const exists = thread.messages.some((m) => m.id === body.id);
        return {
          ...thread,
          messages: exists
            ? thread.messages.map((m) => (m.id === body.id ? { ...m, ...body } : m))
            : [...thread.messages, body],
        };
      });
    });
    source.addEventListener("done", () => {
      source.close();
      void queryClient.invalidateQueries({ queryKey: keyRef.current });
    });
    source.addEventListener("error", () => {
      if (source.readyState === EventSource.CLOSED) {
        onFallback(true);
        void queryClient.invalidateQueries({ queryKey: keyRef.current });
      } else setReconnecting(true);
    });
    return () => {
      source.close();
      setReconnecting(false);
    };
  }, [threadId, running, queryClient, onFallback]);

  return reconnecting;
}
