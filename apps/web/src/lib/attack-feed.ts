/**
 * The live attack feed in the browser (ADR 0021): the latest events as a list that a server-sent event stream keeps
 * current, with polling every 30 seconds as the fallback while the stream is down, and the honest status of the
 * feed. The list route is the source of truth; the stream only saves a poll. Text of events is attacker-influenced and
 * is only ever rendered as plain text by the components.
 */
import { LIVE_VISIBLE } from "@garnetops/core/attack-live";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "./api.ts";
import type { AttackEvent, AttackEventsAnswer, AttackLiveInfo } from "./types.ts";

export const attackEventsKey = ["attack-events"] as const;
const STREAM_URL = "/api/v1/attacks/live";
/** Polling is the fallback while the stream is down; with the stream up it is only a safety net. */
export const POLL_FALLBACK_MS = 30_000;
const POLL_SAFETY_MS = 5 * 60_000;

/** Puts an event on top of the list unless it is there already; keeps the newest 50, newest first. */
export function mergeEvent(
  items: readonly AttackEvent[],
  event: AttackEvent,
  cap = LIVE_VISIBLE,
): AttackEvent[] {
  if (items.some((i) => i.seq === event.seq)) return [...items];
  return [event, ...items].sort((a, b) => b.seq - a.seq).slice(0, cap);
}

/** What the page says about the feed, derived from the status the server sends. */
export type Freshness =
  | { kind: "live"; lastEventAt: string | null }
  | { kind: "waiting"; error: string | null }
  | { kind: "paused"; reason: "disabled" | "certificate" | "privileges" }
  | { kind: "off" };

export function freshnessOf(live: AttackLiveInfo | null | undefined): Freshness {
  if (!live) return { kind: "waiting", error: null };
  switch (live.state) {
    case "live":
      return { kind: "live", lastEventAt: live.lastEventAt };
    case "paused":
      return { kind: "paused", reason: live.reason ?? "disabled" };
    case "off":
      return { kind: "off" };
    default:
      return { kind: "waiting", error: live.error };
  }
}

/** Seconds, minutes, hours or days since a time, as `Intl.RelativeTimeFormat` wants them. */
export function ageOf(iso: string, now: number): { value: number; unit: Intl.RelativeTimeFormatUnit } {
  const seconds = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (seconds < 60) return { value: -seconds, unit: "second" };
  if (seconds < 3600) return { value: -Math.round(seconds / 60), unit: "minute" };
  if (seconds < 86_400) return { value: -Math.round(seconds / 3600), unit: "hour" };
  return { value: -Math.round(seconds / 86_400), unit: "day" };
}

/** "12 sec. ago", "3 min. ago", in the UI language. */
export function formatAge(iso: string, now: number, language: string): string {
  const { value, unit } = ageOf(iso, now);
  return new Intl.RelativeTimeFormat(language, { numeric: "always", style: "short" }).format(value, unit);
}

/** The current time, refreshed every `ms`, so ages on the page keep counting. */
export function useNow(ms = 5_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return now;
}

const parse = <T>(event: Event): T | null => {
  try {
    return JSON.parse((event as MessageEvent<string>).data) as T;
  } catch {
    return null;
  }
};

/**
 * The latest events and the status of the live feed. `events` is undefined until the first answer. The stream is
 * opened while the component is mounted; if it cannot be opened or breaks, the list is polled every 30 seconds and the
 * stream is retried with a growing pause.
 */
export function useAttackFeed(options: { enabled?: boolean } = {}) {
  const enabled = options.enabled ?? true;
  const queryClient = useQueryClient();
  const [connected, setConnected] = useState(false);

  const query = useQuery({
    queryKey: attackEventsKey,
    queryFn: () => api<AttackEventsAnswer>(`/attacks/events?limit=${LIVE_VISIBLE}`),
    enabled,
    refetchInterval: connected ? POLL_SAFETY_MS : POLL_FALLBACK_MS,
  });

  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let stopped = false;
    const reload = () => queryClient.invalidateQueries({ queryKey: attackEventsKey });
    const update = (change: (old: AttackEventsAnswer) => AttackEventsAnswer) =>
      queryClient.setQueryData<AttackEventsAnswer>(attackEventsKey, (old) => (old ? change(old) : old));

    const open = () => {
      source = new EventSource(STREAM_URL);
      source.addEventListener("ready", (event) => {
        failures = 0;
        setConnected(true);
        const data = parse<{ latestSeq?: number; live?: AttackLiveInfo | null }>(event);
        const cached = queryClient.getQueryData<AttackEventsAnswer>(attackEventsKey);
        // Whatever arrived between the list and the stream, or while the stream was down.
        if (!cached || (data?.latestSeq ?? 0) > (cached.items[0]?.seq ?? 0)) void reload();
        else if (data?.live !== undefined) update((old) => ({ ...old, live: data.live ?? null }));
      });
      source.addEventListener("event", (event) => {
        const item = parse<AttackEvent>(event);
        if (!item || typeof item.seq !== "number") return;
        const cached = queryClient.getQueryData<AttackEventsAnswer>(attackEventsKey);
        if (!cached) return void reload();
        update((old) => ({
          ...old,
          items: mergeEvent(old.items, item),
          latestSeq: Math.max(old.latestSeq, item.seq),
        }));
      });
      source.addEventListener("status", (event) => {
        const live = parse<AttackLiveInfo | null>(event);
        update((old) => ({ ...old, live }));
      });
      source.addEventListener("resync", () => void reload());
      source.onerror = () => {
        setConnected(false);
        // CONNECTING: the browser reconnects by itself (and sends the last id). CLOSED: the server refused
        // (signed out, too many streams); try again later, polling meanwhile.
        if (source?.readyState !== EventSource.CLOSED || stopped) return;
        source.close();
        failures++;
        timer = setTimeout(open, Math.min(60_000, 5_000 * 2 ** (failures - 1)));
      };
    };
    open();
    return () => {
      stopped = true;
      clearTimeout(timer);
      source?.close();
      setConnected(false);
    };
  }, [enabled, queryClient]);

  return {
    query,
    events: query.data?.items,
    live: query.data?.live ?? null,
    connected,
  };
}
