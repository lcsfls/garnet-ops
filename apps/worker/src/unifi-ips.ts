/**
 * The IPS / threat event preview (ADR 0022): a light poll of the console's internal API for the newest
 * intrusion prevention events. Off by default, marked "preview" everywhere, and designed for the API changing.
 *
 * - **A separate view-only user.** The password of a local console user is sealed in the vault and opened here for
 *   the seconds of a poll. The session cookie and the CSRF token live in an `IpsSession` object and are never
 *   stored; the poll logs out when it is done, however it ended. The only POSTs are the console's login and logout.
 * - **Only while healthy.** The preview is polled only if it is switched on, the connection is enabled, the
 *   certificate is confirmed and a sync has found the sites and the kind of console. Errors back off (doubling, ten
 *   minutes at most); a rejected login, a rate limit or a redirect is an error like any other.
 * - **Bounded storage.** New events go into `unifi_threat_event` (at most 20,000 per connection, and the retention
 *   period of the attack overview), once each. Then the browsers are told with NOTIFY; the notice carries a
 *   sequence number and nothing else.
 * - **Hostile text.** Signature and category are cleaned and cut by the parser; errors are short texts of a fixed list.
 */
import { UnifiError, type UnifiErrorCode, unifiErrorMessage } from "@garnetops/core";
import { backoffMs, liveChannel, nextCursor, pollSince } from "@garnetops/core/attack-live";
import {
  IPS_KEEP_PER_CONNECTION,
  IPS_PAGE_LIMIT,
  type IpsEvent,
  ipsRightsAcknowledged,
  isSiteRef,
  parseIpsEvents,
  sameRights,
} from "@garnetops/core/unifi-ips";
import { schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { db } from "./db.ts";
import {
  applyObservedCertificate,
  type ConnectionRow,
  errorCodeOf,
  openUnifiSecret,
  type UnifiDeps,
} from "./unifi.ts";
import { CertificateMismatch, IpsSession, resolveUnifiAddress } from "./unifi-http.ts";
import { tellUsers } from "./user-notify.ts";

/** How often the worker looks for connections that are due. The interval of a connection is at least 30 seconds. */
export const IPS_TICK_MS = 10_000;
/** While a worker polls, the row is leased for this long; if it dies, another worker takes over after it. */
const LEASE_SECONDS = 120;
const POLL_AT_MOST_PARALLEL = 4;
/** A blocked connection is looked at again after this long (the block clears when an admin acts). */
const BLOCKED_RECHECK_SECONDS = 60;
/**
 * While the IPS user reports rights beyond viewing that no admin has acknowledged, the console is asked again this
 * rarely: one login and logout, no events read. Acknowledging starts the poll at once.
 */
const RIGHTS_RECHECK_SECONDS = 600;
/** Sites polled per connection and poll. */
const MAX_SITES = 20;

export interface IpsDeps extends UnifiDeps {
  /** Poll even if the connection is not due (tests). */
  force?: boolean;
  /** The clock used for the start of the query (tests). The schedule itself uses the database clock. */
  now?: Date;
}

export type IpsOutcome =
  | { status: "not-due" }
  | { status: "blocked"; reason: "certificate" | "no-sync" | "credentials" | "no-sites" | "rights" }
  | { status: "polled"; read: number; stored: number }
  | { status: "failed"; code: UnifiErrorCode };

const later = (seconds: number) => sql`now() + make_interval(secs => ${seconds})`;

/** Takes the lease on a connection if the preview is on and due. Atomic: two workers never poll the same connection. */
async function claim(connectionId: string, force: boolean): Promise<ConnectionRow | null> {
  const c = schema.unifiConnection;
  const [row] = await db
    .update(c)
    .set({ ipsNextPollAt: later(LEASE_SECONDS) })
    .where(
      and(
        eq(c.id, connectionId),
        eq(c.ipsEnabled, true),
        eq(c.enabled, true),
        force ? undefined : sql`${c.ipsNextPollAt} <= now()`,
      ),
    )
    .returning();
  return row ?? null;
}

/**
 * Polls one connection once if it is due. Never throws for a problem of the console: that becomes the stored
 * error and a longer pause.
 */
export async function pollIps(connectionId: string, deps: IpsDeps = {}): Promise<IpsOutcome> {
  const connection = await claim(connectionId, deps.force === true);
  if (!connection) return { status: "not-due" };
  const c = schema.unifiConnection;
  const sites = await db
    .select()
    .from(schema.unifiSite)
    .where(eq(schema.unifiSite.connectionId, connection.id));
  const refs = sites
    .filter((s) => s.internalRef && isSiteRef(s.internalRef))
    .slice(0, MAX_SITES)
    .map((s) => ({ ref: s.internalRef as string, name: s.name }));
  const blocked: Extract<IpsOutcome, { status: "blocked" }>["reason"] | null =
    connection.certStatus !== "confirmed" || !connection.certFingerprint
      ? "certificate"
      : connection.apiBase === "auto"
        ? "no-sync"
        : !connection.ipsUsername || !connection.ipsSecretId
          ? "credentials"
          : refs.length === 0
            ? "no-sites"
            : null;
  if (blocked) {
    await db
      .update(c)
      .set({ ipsNextPollAt: later(BLOCKED_RECHECK_SECONDS), updatedAt: new Date() })
      .where(eq(c.id, connection.id));
    return { status: "blocked", reason: blocked };
  }

  let session: IpsSession | null = null;
  try {
    const password = await openUnifiSecret(
      connection,
      connection.ipsSecretId,
      "unifi-ips-password",
      "ipsCredentialsMissing",
    );
    const address = await (deps.resolve ?? resolveUnifiAddress)(connection.host);
    session = new IpsSession({
      endpoint: { host: connection.host, port: connection.port, address },
      pinned: connection.certFingerprint as string,
      flavor: connection.apiBase === "network-app" ? "network-app" : "unifi-os",
      ...(deps.gapMs !== undefined ? { gapMs: deps.gapMs } : {}),
      ...(deps.maxBytes !== undefined ? { maxBytes: deps.maxBytes } : {}),
      ...(deps.timeoutMs !== undefined ? { timeoutMs: deps.timeoutMs } : {}),
      ...(deps.test ? { test: deps.test } : {}),
    });
    const { rights } = await session.login(connection.ipsUsername as string, password);
    // Rights beyond viewing that nobody acknowledged: nothing is read (the session is ended in `finally`).
    const verdict = await checkRights(connection, rights);
    if (verdict === "changed-meanwhile") return { status: "not-due" };
    if (verdict === "blocked") {
      await db
        .update(c)
        .set({
          ipsLastError: null,
          ipsFailures: 0,
          ipsNextPollAt: later(RIGHTS_RECHECK_SECONDS),
          updatedAt: new Date(),
        })
        .where(eq(c.id, connection.id));
      return { status: "blocked", reason: "rights" };
    }

    const now = deps.now ?? new Date();
    const since = pollSince(connection.ipsCursorAt, now);
    const events: (IpsEvent & { siteName: string })[] = [];
    let latest: Date | null = null;
    let fullPage = false;
    for (const site of refs) {
      const answer = await session.events(site.ref, since.getTime(), now.getTime(), IPS_PAGE_LIMIT);
      const parsed = parseIpsEvents(answer);
      if (!parsed) throw new UnifiError("invalidResponse");
      for (const event of parsed.events) events.push({ ...event, siteName: site.name });
      if (parsed.latest && (!latest || parsed.latest > latest)) latest = parsed.latest;
      fullPage ||= parsed.fullPage;
    }
    return await store(connection, events, latest, fullPage);
  } catch (error) {
    // A certificate other than the pin: record what was seen so that an admin can decide (nothing was sent).
    const seen = error instanceof CertificateMismatch ? error.seen : session?.mismatch;
    if (seen) await applyObservedCertificate(connection, seen).catch(() => {});
    const code = errorCodeOf(error);
    if (!(error instanceof UnifiError)) {
      // Never the message of an unknown error: it could quote what the console sent.
      console.error(`unifi ips ${connectionId}: ${(error as Error)?.name ?? "error"}`);
    }
    const failures = connection.ipsFailures + 1;
    await db
      .update(c)
      .set({
        ipsFailures: failures,
        ipsLastError: unifiErrorMessage(code),
        ipsLastPollAt: new Date(),
        ipsNextPollAt: later(backoffMs(connection.ipsIntervalSeconds, failures) / 1000),
        updatedAt: new Date(),
      })
      .where(eq(c.id, connection.id));
    return { status: "failed", code };
  } finally {
    // Always end the session; this also drops cookie and token from memory.
    await session?.logout();
    session?.close();
  }
}

/**
 * Compares the rights of this login with the stored ones (ADR 0022). A different list clears the acknowledgement and,
 * if any right beyond viewing is reported, is audited and told to the admins once. The poll may go on only if no such
 * right is reported or an admin acknowledged exactly this list. Reads the row again under a lock, so an
 * acknowledgement that arrives while the poll runs is seen and a change of credentials is not mixed up.
 */
async function checkRights(
  connection: ConnectionRow,
  rights: string[],
): Promise<"ok" | "blocked" | "changed-meanwhile"> {
  const c = schema.unifiConnection;
  if (
    sameRights(rights, connection.ipsRights) &&
    ipsRightsAcknowledged(rights, connection.ipsRightsAcknowledged)
  ) {
    return "ok";
  }
  let newlyReported = false;
  const verdict = await db.transaction(async (tx) => {
    const [fresh] = await tx.select().from(c).where(eq(c.id, connection.id)).for("update");
    if (
      !fresh ||
      fresh.ipsSecretId !== connection.ipsSecretId ||
      fresh.ipsUsername !== connection.ipsUsername
    ) {
      return "changed-meanwhile" as const;
    }
    if (!sameRights(rights, fresh.ipsRights)) {
      await tx
        .update(c)
        .set({
          ipsRights: rights,
          ipsRightsAcknowledged: [],
          ipsRightsAcknowledgedAt: null,
          ipsRightsAcknowledgedBy: null,
          updatedAt: new Date(),
        })
        .where(eq(c.id, connection.id));
      if (rights.length > 0) {
        newlyReported = true;
        await tx.insert(schema.auditLog).values({
          organizationId: connection.organizationId,
          action: "unifi.ips_rights_detected",
          targetType: "unifi_connection",
          targetId: connection.id,
          data: { name: connection.name, user: connection.ipsUsername, rights },
        });
      }
      return rights.length > 0 ? ("blocked" as const) : ("ok" as const);
    }
    return ipsRightsAcknowledged(rights, fresh.ipsRightsAcknowledged)
      ? ("ok" as const)
      : ("blocked" as const);
  });
  if (newlyReported) {
    await tellUsers({
      organizationId: connection.organizationId,
      titleKey: "unifiIpsBlocked",
      params: { name: connection.name },
      link: "/settings?section=unifi",
    });
  }
  return verdict;
}

/** Stores the new events, trims the table, moves the cursor and tells the browsers: one transaction. */
async function store(
  connection: ConnectionRow,
  events: (IpsEvent & { siteName: string })[],
  latest: Date | null,
  fullPage: boolean,
): Promise<IpsOutcome> {
  const e = schema.unifiThreatEvent;
  const c = schema.unifiConnection;
  const cursor = nextCursor(
    connection.ipsCursorAt,
    events.map((x) => ({ at: x.at, docId: x.docId })),
    latest,
    fullPage,
  );
  let stored = 0;
  await db.transaction(async (tx) => {
    let newestSeq = 0;
    if (events.length > 0) {
      const inserted = await tx
        .insert(e)
        .values(
          events.map((x) => ({
            organizationId: connection.organizationId,
            connectionId: connection.id,
            docId: x.docId,
            at: x.at,
            ip: x.ip,
            action: x.action,
            signature: x.signature,
            category: x.category,
            destPort: x.destPort,
            proto: x.proto,
            siteName: x.siteName,
          })),
        )
        .onConflictDoNothing({ target: [e.connectionId, e.docId] })
        .returning({ seq: e.seq });
      stored = inserted.length;
      for (const row of inserted) newestSeq = Math.max(newestSeq, Number(row.seq));
    }
    if (stored > 0) {
      await tx.execute(sql`
        delete from unifi_threat_event
        where connection_id = ${connection.id}
          and seq <= coalesce((select seq from unifi_threat_event where connection_id = ${connection.id}
                      order by seq desc offset ${IPS_KEEP_PER_CONNECTION} limit 1), 0)`);
    }
    const newestAt = events.reduce<Date | null>((m, x) => (!m || x.at > m ? x.at : m), null);
    await tx
      .update(c)
      .set({
        ipsCursorAt: cursor?.at ?? connection.ipsCursorAt,
        ipsLastPollAt: new Date(),
        ...(stored > 0 && newestAt
          ? {
              ipsLastEventAt: sql`greatest(coalesce(${c.ipsLastEventAt}, ${newestAt.toISOString()}::timestamptz), ${newestAt.toISOString()}::timestamptz)`,
            }
          : {}),
        ipsLastError: null,
        ipsFailures: 0,
        ipsNextPollAt: later(connection.ipsIntervalSeconds),
        updatedAt: new Date(),
      })
      .where(eq(c.id, connection.id));
    if (stored > 0) {
      // Delivered when the transaction commits, so a browser that reacts finds the rows.
      await tx.execute(
        sql`select pg_notify(${liveChannel(connection.organizationId)}, ${JSON.stringify({ s: newestSeq })})`,
      );
    }
  });
  return { status: "polled", read: events.length, stored };
}

/** Polls the connections that are due, a few at a time. */
export async function ipsTick(deps: IpsDeps = {}): Promise<number> {
  const c = schema.unifiConnection;
  const due = await db
    .select({ id: c.id })
    .from(c)
    .where(and(eq(c.ipsEnabled, true), eq(c.enabled, true), sql`${c.ipsNextPollAt} <= now()`))
    .orderBy(c.ipsNextPollAt)
    .limit(50);
  let polled = 0;
  for (let i = 0; i < due.length; i += POLL_AT_MOST_PARALLEL) {
    const batch = due.slice(i, i + POLL_AT_MOST_PARALLEL);
    const results = await Promise.all(
      batch.map((row) =>
        pollIps(row.id, deps).catch((error: Error) => {
          console.error(`unifi ips ${row.id}: ${error?.name ?? "error"}`);
          return { status: "not-due" } as IpsOutcome;
        }),
      ),
    );
    polled += results.filter((r) => r.status === "polled" || r.status === "failed").length;
  }
  return polled;
}

/** Starts the preview poll of the worker; returns the function that stops it. */
export function startUnifiIpsPoller(deps: IpsDeps = {}): () => void {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    ipsTick(deps)
      .catch((error: Error) => console.error("unifi ips tick:", error?.name ?? "error"))
      .finally(() => {
        running = false;
      });
  }, IPS_TICK_MS);
  timer.unref();
  return () => clearInterval(timer);
}
