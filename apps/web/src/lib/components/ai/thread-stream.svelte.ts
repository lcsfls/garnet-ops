import { type QueryKey, useQueryClient } from "@tanstack/svelte-query";
import type { AiMessage, AiThread } from "../../types.ts";
import { byteLength } from "./ai-panel.ts";

/**
 * Follows a thread while an answer is being written: the server sends the stored state first (so a reconnect resumes
 * where the text is), then the text as it grows. `reconnecting` is true while the connection is being re-established.
 * When the stream cannot be used at all, `onFallback` switches the panel to asking again every couple of seconds.
 *
 * Call it while a component initialises (it uses the query client and an effect). `threadId` and `running` should
 * read primitive `$derived` values: the stream is opened again only when one of them changes, not on every delta.
 */
export function followThread(
  threadId: () => string | null,
  running: () => boolean,
  key: () => QueryKey,
  onFallback: (poll: boolean) => void,
): { readonly reconnecting: boolean } {
  const queryClient = useQueryClient();
  let reconnecting = $state(false);

  $effect(() => {
    const id = threadId();
    if (!id || !running()) return;
    if (typeof EventSource === "undefined") {
      onFallback(true);
      return;
    }
    const source = new EventSource(`/api/v1/ai/threads/${id}/stream`);
    const update = (fn: (thread: AiThread) => AiThread) =>
      queryClient.setQueryData<AiThread>(key(), (current) => (current ? fn(current) : current));
    const parse = (event: Event): Record<string, unknown> | null => {
      try {
        return JSON.parse((event as MessageEvent<string>).data) as Record<string, unknown>;
      } catch {
        return null;
      }
    };
    source.addEventListener("open", () => {
      reconnecting = false;
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
      if (missed) void queryClient.invalidateQueries({ queryKey: key() });
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
      void queryClient.invalidateQueries({ queryKey: key() });
    });
    source.addEventListener("error", () => {
      if (source.readyState === EventSource.CLOSED) {
        onFallback(true);
        void queryClient.invalidateQueries({ queryKey: key() });
      } else reconnecting = true;
    });
    return () => {
      source.close();
      reconnecting = false;
    };
  });

  return {
    get reconnecting() {
      return reconnecting;
    },
  };
}
