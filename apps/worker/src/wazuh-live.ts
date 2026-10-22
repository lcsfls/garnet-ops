/**
 * The live attack feed (ADR 0021): a light poll of the Wazuh indexer for the newest attack alerts.
 *
 * - **We poll; nothing is exposed.** The worker asks the indexer, read-only, with the one fixed query template
 *   `liveAlerts` (packages/core/src/wazuh.ts): at most 50 alerts per request, oldest first, only the fields the page
 *   shows, from the cursor on. No `full_log`, no query built from anything an alert said.
 * - **Only while healthy.** A connection is polled only if it is switched on, the feed is on, both certificates are
 *   confirmed and unchanged, extra privileges are acknowledged and a sync has run. Errors back off (doubling, ten
 *   minutes at most); a rejected password, a rate limit or a redirect is an error like any other and is not retried
 *   faster. The password is opened for the seconds a poll takes.
 * - **Bounded storage.** New alerts go into `wazuh_attack_event` (the latest 500 per connection), once each. Then the
 *   browsers of the organisation are told with NOTIFY; the notice carries a sequence number and nothing else.
 * - **Hostile text.** Descriptions and agent names are cleaned and cut by the parser; errors are short codes.
 */
import { WazuhError, type WazuhErrorCode } from "@garnetops/core";
import {
  backoffMs,
  LIVE_KEEP_PER_CONNECTION,
  liveChannel,
  nextCursor,
  nextDelayMs,
  pollSince,
} from "@garnetops/core/attack-live";
import { ADAPTERS, parseLiveAlerts, privilegesAcknowledged } from "@garnetops/core/wazuh";
import { schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { db } from "./db.ts";
import {
  applyObservedCertificate,
  type EndpointRow,
  openPassword,
  trustOf,
  type WazuhDeps,
} from "./wazuh.ts";
import { CertificateMismatch, IndexerClient, resolveWazuhAddress, type Trust } from "./wazuh-http.ts";

/** How often the worker looks for connections that are due. The interval of a connection is at least 15 seconds. */
export const LIVE_TICK_MS = 5_000;
/** A poll asks for one page of at most 50 alerts; a few kilobytes. One MiB is far more than it can need. */
const LIVE_MAX_BYTES = 1024 * 1024;
/** While a worker polls, the row is leased for this long; if it dies, another worker takes over after it. */
const LEASE_SECONDS = 120;
const POLL_AT_MOST_PARALLEL = 4;
/** A blocked connection is looked at again after this long (the block clears when an admin acts). */
const BLOCKED_RECHECK_SECONDS = 60;

type ConnectionRow = typeof schema.wazuhConnection.$inferSelect;
type StateRow = typeof schema.wazuhLiveState.$inferSelect;

export interface LiveDeps extends WazuhDeps {
  /** Poll even if the connection is not due (tests). */
  force?: boolean;
  /** The clock used for the start of the query (tests). The schedule itself uses the database clock. */
  now?: Date;
}

export type PollOutcome =
  | { status: "not-due" }
  | { status: "blocked"; reason: "disabled" | "certificate" | "privileges" | "no-sync" | "off" }
  | { status: "polled"; read: number; stored: number; fullPage: boolean }
  | { status: "failed"; code: WazuhErrorCode };

/** Pauses in a row that follow a full page, per connection (only the rhythm; not worth persisting). */
const catchUps = new Map<string, number>();

/** Why a connection must not be polled now, or null if it may. */
function blockedReason(
  connection: ConnectionRow,
  endpoints: EndpointRow[],
  state: StateRow,
): "disabled" | "certificate" | "privileges" | "no-sync" | "off" | null {
  if (!state.enabled) return "off";
  if (!connection.enabled) return "disabled";
  const indexer = endpoints.find((e) => e.kind === "indexer");
  const manager = endpoints.find((e) => e.kind === "manager");
  if (!indexer || !manager) return "certificate";
  for (const endpoint of [manager, indexer]) {
    if (endpoint.certStatus !== "confirmed" || !trustOf(endpoint)) return "certificate";
  }
  if (
    connection.extraPrivileges.length > 0 &&
    !privilegesAcknowledged(connection.extraPrivileges, connection.acknowledgedPrivileges)
  ) {
    return "privileges";
  }
  if (!connection.adapter) return "no-sync";
  return null;
}

/** Takes the lease on a connection's live state if it is due. Atomic: two workers never poll the same connection. */
async function claim(connectionId: string, force: boolean): Promise<StateRow | null> {
  const s = schema.wazuhLiveState;
  const [row] = await db
    .update(s)
    .set({ nextPollAt: sql`now() + make_interval(secs => ${LEASE_SECONDS})` })
    .where(and(eq(s.connectionId, connectionId), force ? undefined : sql`${s.nextPollAt} <= now()`))
    .returning();
  return row ?? null;
}

const later = (seconds: number) => sql`now() + make_interval(secs => ${seconds})`;

/**
 * Polls one connection once if it is due. Never throws for a problem of the Wazuh installation: that becomes the
 * state's error code and a longer pause.
 */
export async function pollConnection(connectionId: string, deps: LiveDeps = {}): Promise<PollOutcome> {
  const state = await claim(connectionId, deps.force === true);
  if (!state) return { status: "not-due" };
  const s = schema.wazuhLiveState;
  const [connection] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.id, connectionId))
    .limit(1);
  if (!connection) return { status: "not-due" };
  const endpoints = await db
    .select()
    .from(schema.wazuhEndpoint)
    .where(eq(schema.wazuhEndpoint.connectionId, connectionId));
  const blocked = blockedReason(connection, endpoints, state);
  if (blocked) {
    await db
      .update(s)
      .set({ nextPollAt: later(BLOCKED_RECHECK_SECONDS), updatedAt: new Date() })
      .where(eq(s.connectionId, connectionId));
    return { status: "blocked", reason: blocked };
  }
  const indexer = endpoints.find((e) => e.kind === "indexer") as EndpointRow;
  const adapter = ADAPTERS[connection.adapter as keyof typeof ADAPTERS];
  let client: IndexerClient | null = null;
  try {
    const password = await openPassword(indexer);
    const address = await (deps.resolve ?? resolveWazuhAddress)(indexer.host).catch((error: unknown) => {
      throw error instanceof WazuhError ? error.forEndpoint("indexer") : error;
    });
    client = new IndexerClient({
      endpoint: { host: indexer.host, port: indexer.port, address },
      trust: trustOf(indexer) as Trust,
      username: indexer.username,
      password,
      maxBytes: deps.maxBytes ?? LIVE_MAX_BYTES,
      ...(deps.gapMs !== undefined ? { gapMs: deps.gapMs } : {}),
      ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
      ...(deps.test ? { test: deps.test } : {}),
    });
    const since = pollSince(state.cursorAt, deps.now ?? new Date());
    const answer = await client.run(adapter, { kind: "liveAlerts", since, minLevel: state.minLevel });
    const parsed = parseLiveAlerts(answer, adapter);
    if (!parsed) throw new WazuhError("invalidResponse", { endpoint: "indexer" });
    return await store(connection, state, parsed);
  } catch (error) {
    // A certificate other than the pin: record what was seen so that an admin can decide (the password was not sent).
    const seen = error instanceof CertificateMismatch ? error.seen : client?.mismatch;
    if (seen) await applyObservedCertificate(connection, indexer, seen).catch(() => {});
    const code: WazuhErrorCode = error instanceof WazuhError ? error.code : "unexpected";
    if (!(error instanceof WazuhError)) {
      // Never the message of an unknown error: it could quote what Wazuh sent.
      console.error(`wazuh live ${connectionId}: ${(error as Error)?.name ?? "error"}`);
    }
    const failures = state.failures + 1;
    catchUps.delete(connectionId);
    await db
      .update(s)
      .set({
        failures,
        lastError: code,
        lastPollAt: new Date(),
        nextPollAt: later(backoffMs(state.intervalSeconds, failures) / 1000),
        updatedAt: new Date(),
      })
      .where(eq(s.connectionId, connectionId));
    return { status: "failed", code };
  } finally {
    client?.close();
  }
}

/** Stores the new alerts, trims the table, moves the cursor and tells the browsers: one transaction. */
async function store(
  connection: ConnectionRow,
  state: StateRow,
  parsed: NonNullable<ReturnType<typeof parseLiveAlerts>>,
): Promise<PollOutcome> {
  const e = schema.wazuhAttackEvent;
  const s = schema.wazuhLiveState;
  const cursor = nextCursor(
    state.cursorAt,
    parsed.alerts.map((a) => ({ at: a.at, docId: a.docId })),
    parsed.latest,
    parsed.fullPage,
  );
  const followUps = parsed.fullPage ? (catchUps.get(connection.id) ?? 0) : 0;
  const delayMs = nextDelayMs(state.intervalSeconds, parsed.fullPage, followUps);
  if (parsed.fullPage) catchUps.set(connection.id, followUps + 1);
  else catchUps.delete(connection.id);

  let stored = 0;
  await db.transaction(async (tx) => {
    let newestSeq = 0;
    if (parsed.alerts.length > 0) {
      const inserted = await tx
        .insert(e)
        .values(
          parsed.alerts.map((a) => ({
            organizationId: connection.organizationId,
            connectionId: connection.id,
            docId: a.docId,
            at: a.at,
            ip: a.ip,
            ruleId: a.ruleId,
            ruleLevel: a.level,
            description: a.description,
            groups: a.groups,
            agentId: a.agentId,
            agentName: a.agentName,
          })),
        )
        .onConflictDoNothing({ target: [e.connectionId, e.docId] })
        .returning({ seq: e.seq });
      stored = inserted.length;
      for (const row of inserted) newestSeq = Math.max(newestSeq, row.seq);
    }
    if (stored > 0) {
      // Keep the newest 500 of this connection.
      await tx.execute(sql`
        delete from wazuh_attack_event
        where connection_id = ${connection.id}
          and seq <= (select seq from wazuh_attack_event where connection_id = ${connection.id}
                      order by seq desc offset ${LIVE_KEEP_PER_CONNECTION} limit 1)`);
    }
    const newestAt = parsed.alerts.reduce<Date | null>((m, a) => (!m || a.at > m ? a.at : m), null);
    await tx
      .update(s)
      .set({
        cursorAt: cursor?.at ?? state.cursorAt,
        cursorId: cursor?.id ?? null,
        lastPollAt: new Date(),
        ...(stored > 0 && newestAt
          ? {
              lastEventAt: sql`greatest(coalesce(${s.lastEventAt}, ${newestAt.toISOString()}::timestamptz), ${newestAt.toISOString()}::timestamptz)`,
            }
          : {}),
        lastError: null,
        failures: 0,
        nextPollAt: later(delayMs / 1000),
        updatedAt: new Date(),
      })
      .where(eq(s.connectionId, connection.id));
    if (stored > 0) {
      // Delivered when the transaction commits, so a browser that reacts finds the rows.
      await tx.execute(
        sql`select pg_notify(${liveChannel(connection.organizationId)}, ${JSON.stringify({ s: newestSeq })})`,
      );
    }
  });
  return { status: "polled", read: parsed.alerts.length, stored, fullPage: parsed.fullPage };
}

/** Makes sure every connection has a live state (the defaults), then polls the ones that are due, a few at a time. */
export async function liveTick(deps: LiveDeps = {}): Promise<number> {
  await db.execute(sql`
    insert into wazuh_live_state (connection_id, organization_id)
    select id, organization_id from wazuh_connection
    on conflict do nothing`);
  const s = schema.wazuhLiveState;
  const due = await db
    .select({ id: s.connectionId })
    .from(s)
    .innerJoin(schema.wazuhConnection, eq(schema.wazuhConnection.id, s.connectionId))
    .where(and(eq(s.enabled, true), eq(schema.wazuhConnection.enabled, true), sql`${s.nextPollAt} <= now()`))
    .orderBy(s.nextPollAt)
    .limit(50);
  let polled = 0;
  for (let i = 0; i < due.length; i += POLL_AT_MOST_PARALLEL) {
    const batch = due.slice(i, i + POLL_AT_MOST_PARALLEL);
    const results = await Promise.all(
      batch.map((row) =>
        pollConnection(row.id, deps).catch((error: Error) => {
          console.error(`wazuh live ${row.id}: ${error?.name ?? "error"}`);
          return { status: "not-due" } as PollOutcome;
        }),
      ),
    );
    polled += results.filter((r) => r.status === "polled" || r.status === "failed").length;
  }
  return polled;
}

/** Starts the live poll of the worker; returns the function that stops it. */
export function startWazuhLivePoller(deps: LiveDeps = {}): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    liveTick(deps)
      .catch((error: Error) => console.error("wazuh live tick:", error?.name ?? "error"))
      .finally(() => {
        running = false;
      });
  }, LIVE_TICK_MS);
  timer.unref();
  return () => clearInterval(timer);
}
