/**
 * The live attack feed (ADR 0021): the limits, the cursor, the rhythm of polling and the honest status that the page
 * shows. Pure functions shared by the worker (which polls the Wazuh indexer), the API (which streams to browsers) and
 * the web app. Nothing here touches a network or a database.
 *
 * The feed reads a small page of the newest attack alerts every few seconds, stores them in a bounded table and
 * tells the browsers. It is a window on what is happening now; the numbers of the page stay the 15-minute aggregates.
 */
import { LIVE_LEVEL_MAX, LIVE_LEVEL_MIN } from "./wazuh.ts";

export { LIVE_DESCRIPTION_MAX, LIVE_LEVEL_MAX, LIVE_LEVEL_MIN, LIVE_PAGE_SIZE } from "./wazuh.ts";

export const LIVE_INTERVAL_SECONDS = { min: 15, max: 300, default: 30 } as const;
export const LIVE_LEVEL = { min: LIVE_LEVEL_MIN, max: LIVE_LEVEL_MAX, default: 7 } as const;

/** Events kept per connection; older ones are deleted after every poll that stores something. */
export const LIVE_KEEP_PER_CONNECTION = 500;
/** The first poll of a connection starts this far back: no backfill flood. */
export const LIVE_START_LOOKBACK_MS = 5 * 60_000;
/** However long the worker was away, a poll never reaches back further than this. */
export const LIVE_MAX_LOOKBACK_MS = 15 * 60_000;
/** After a full page the next poll comes sooner, at most this many times in a row. */
export const LIVE_CATCH_UP_POLLS = 5;
export const LIVE_CATCH_UP_DELAY_MS = 5_000;
/** The longest pause after repeated errors. */
export const LIVE_BACKOFF_CAP_MS = 10 * 60_000;
/** A poll that has not finished after this long is considered lost; another worker may take over. */
export const LIVE_LEASE_MS = 2 * 60_000;
/** What the browser list shows at most, and what the events route returns at most. */
export const LIVE_VISIBLE = 50;

/** The PostgreSQL channel a browser stream of one organisation listens to. A notice carries the newest sequence number only. */
export function liveChannel(organizationId: string): string {
  return `attack_live_${organizationId.toLowerCase().replace(/[^a-z0-9]/g, "_")}`.slice(0, 63);
}

export const isLiveInterval = (n: unknown): n is number =>
  typeof n === "number" &&
  Number.isInteger(n) &&
  n >= LIVE_INTERVAL_SECONDS.min &&
  n <= LIVE_INTERVAL_SECONDS.max;
export const isLiveLevel = (n: unknown): n is number =>
  typeof n === "number" && Number.isInteger(n) && n >= LIVE_LEVEL.min && n <= LIVE_LEVEL.max;

/* -------------------------------------------------------------------------- */
/* Cursor                                                                      */
/* -------------------------------------------------------------------------- */

export interface Cursor {
  at: Date;
  id: string | null;
}

/**
 * Where the next poll starts: five minutes back on the first poll, afterwards at the cursor, but never further back
 * than fifteen minutes (a worker that was away must not replay hours of alerts).
 */
export function pollSince(cursor: Date | null, now: Date): Date {
  if (!cursor) return new Date(now.getTime() - LIVE_START_LOOKBACK_MS);
  return new Date(Math.max(cursor.getTime(), now.getTime() - LIVE_MAX_LOOKBACK_MS));
}

/**
 * The cursor after a poll. It moves to the newest time read (and the id of that alert). The query includes the cursor
 * time itself, so alerts that share the newest millisecond are read again and stored once; but if a whole page of
 * alerts shares one time the cursor would never move, so it steps one millisecond past it (at most the few alerts of
 * that millisecond that did not fit are lost).
 */
export function nextCursor(
  current: Date | null,
  read: { at: Date; docId: string }[],
  latest: Date | null,
  fullPage: boolean,
): Cursor | null {
  let newest: { at: Date; docId: string } | null = null;
  for (const event of read) if (!newest || event.at >= newest.at) newest = event;
  let at = current;
  let id: string | null = null;
  if (newest && (!at || newest.at >= at)) {
    at = newest.at;
    id = newest.docId;
  }
  if (latest && (!at || latest > at)) {
    at = latest;
    id = null;
  }
  if (fullPage && at && current && at.getTime() <= current.getTime()) {
    at = new Date(current.getTime() + 1);
    id = null;
  }
  return at ? { at, id } : null;
}

/* -------------------------------------------------------------------------- */
/* Rhythm                                                                      */
/* -------------------------------------------------------------------------- */

/** Milliseconds until the next poll after a successful one. A full page means more may wait: ask again soon, a few times. */
export function nextDelayMs(intervalSeconds: number, fullPage: boolean, catchUps: number): number {
  const regular = intervalSeconds * 1000;
  if (fullPage && catchUps < LIVE_CATCH_UP_POLLS) return Math.min(regular, LIVE_CATCH_UP_DELAY_MS);
  return regular;
}

/** Milliseconds until the next poll after `failures` failed polls in a row (1 or more): doubling, capped at ten minutes. */
export function backoffMs(intervalSeconds: number, failures: number): number {
  const doublings = Math.min(Math.max(failures, 1), 12);
  return Math.min(LIVE_BACKOFF_CAP_MS, intervalSeconds * 1000 * 2 ** doublings);
}

/* -------------------------------------------------------------------------- */
/* Status                                                                      */
/* -------------------------------------------------------------------------- */

export type LiveState = "live" | "waiting" | "paused" | "off";
export type PausedReason = "disabled" | "certificate" | "privileges";

export interface LiveStatusInput {
  /** The admin switched the live feed off. */
  feedEnabled: boolean;
  /** The Wazuh connection is switched on. */
  connectionEnabled: boolean;
  /** Both certificates are confirmed and none has changed. */
  certificatesOk: boolean;
  /** Every extra privilege of the service users is acknowledged. */
  privilegesOk: boolean;
  /** A sync has run, so the adapter (Wazuh 4 or 5) is known. */
  adapterKnown: boolean;
  lastPollAt: Date | null;
  lastError: string | null;
  intervalSeconds: number;
  now: Date;
}

export interface LiveStatus {
  state: LiveState;
  reason: PausedReason | null;
  /** A short error code of the last poll while the state is "waiting" because it failed. */
  error: string | null;
}

/**
 * What the page says about the feed, derived from the facts: "off" (an admin switched it off), "paused" (the
 * connection is blocked: switched off, a certificate to confirm, privileges to acknowledge), "waiting" (nothing to
 * show yet, the last poll failed, or the worker has not polled for much longer than its interval) or "live".
 */
export function liveStatus(input: LiveStatusInput): LiveStatus {
  const status = (state: LiveState, reason: PausedReason | null = null, error: string | null = null) => ({
    state,
    reason,
    error,
  });
  if (!input.feedEnabled) return status("off");
  if (!input.connectionEnabled) return status("paused", "disabled");
  if (!input.certificatesOk) return status("paused", "certificate");
  if (!input.privilegesOk) return status("paused", "privileges");
  if (!input.adapterKnown || !input.lastPollAt) return status("waiting");
  if (input.lastError) return status("waiting", null, input.lastError);
  // Three intervals and a minute: backoff after a few errors is longer than this and shows as an error anyway.
  const stale = input.now.getTime() - input.lastPollAt.getTime() > input.intervalSeconds * 3000 + 60_000;
  return stale ? status("waiting") : status("live");
}

/** Where an event came from (ADR 0022 added UniFi next to Wazuh). */
export type EventSource = "wazuh" | "unifi";

/**
 * The shape of one event in the API and in the stream. Country, network and score are looked up when it is read.
 * For a UniFi event `description` is the signature, `groups` holds its category, `agentName` the site, `level` is 0
 * and `ruleId`/`agentId` are empty; `action` says what the console did (blocked or only alerted).
 */
export interface AttackEventView {
  seq: number;
  at: string;
  ip: string;
  scope: "public" | "internal";
  country: string | null;
  asn: number | null;
  ruleId: string;
  level: number;
  description: string;
  groups: string[];
  agentId: string;
  agentName: string;
  /** The cached OSINT score, only while OSINT is switched on and a result exists. */
  score: number | null;
  source: EventSource;
  /** What UniFi did with the traffic; null for Wazuh alerts (they report, they do not block). */
  action: "blocked" | "alerted" | null;
  /** The port of the attacked service (UniFi events only). */
  destPort: number | null;
}

/** An abuse score above this is drawn and listed as high. */
export const HIGH_ABUSE_SCORE = 80;
