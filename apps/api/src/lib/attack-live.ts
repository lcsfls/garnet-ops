/**
 * What the API tells browsers about the live attack feed (ADR 0021): the honest status of the feed and the events
 * as the page shows them. The events are enriched when they are read, from the local GeoIP tables and the cached
 * OSINT scores; nothing is sent anywhere and nothing is looked up that was not already stored.
 */
import {
  type AttackEventView,
  LIVE_INTERVAL_SECONDS,
  LIVE_LEVEL,
  type LiveState,
  liveStatus,
  type PausedReason,
} from "@garnetops/core/attack-live";
import { canonicalIp, ipScope } from "@garnetops/core/geoip";
import { type IpsState, ipsStatus } from "@garnetops/core/unifi-ips";
import { privilegesAcknowledged } from "@garnetops/core/wazuh";
import { lookupIps, schema } from "@garnetops/db";
import { and, desc, eq, gt, inArray, sql } from "drizzle-orm";
import { db } from "../db.ts";

export interface LiveInfo {
  enabled: boolean;
  intervalSeconds: number;
  minLevel: number;
  state: LiveState;
  reason: PausedReason | null;
  /** A short code of the last failed poll while the state is "waiting". */
  error: string | null;
  lastEventAt: string | null;
  lastPollAt: string | null;
}

/** The status of the live feed of an organisation's Wazuh connection, or null if there is no connection. */
export async function liveInfo(organizationId: string, now = new Date()): Promise<LiveInfo | null> {
  const [connection] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.organizationId, organizationId))
    .limit(1);
  if (!connection) return null;
  const [state] = await db
    .select()
    .from(schema.wazuhLiveState)
    .where(eq(schema.wazuhLiveState.connectionId, connection.id))
    .limit(1);
  const endpoints = await db
    .select({ certStatus: schema.wazuhEndpoint.certStatus })
    .from(schema.wazuhEndpoint)
    .where(eq(schema.wazuhEndpoint.connectionId, connection.id));
  const intervalSeconds = state?.intervalSeconds ?? LIVE_INTERVAL_SECONDS.default;
  const status = liveStatus({
    feedEnabled: state?.enabled ?? true,
    connectionEnabled: connection.enabled,
    certificatesOk: endpoints.length === 2 && endpoints.every((e) => e.certStatus === "confirmed"),
    privilegesOk:
      connection.extraPrivileges.length === 0 ||
      privilegesAcknowledged(connection.extraPrivileges, connection.acknowledgedPrivileges),
    adapterKnown: connection.adapter !== null,
    lastPollAt: state?.lastPollAt ?? null,
    lastError: state?.lastError ?? null,
    intervalSeconds,
    now,
  });
  return {
    enabled: state?.enabled ?? true,
    intervalSeconds,
    minLevel: state?.minLevel ?? LIVE_LEVEL.default,
    state: status.state,
    reason: status.reason,
    error: status.error,
    lastEventAt: state?.lastEventAt?.toISOString() ?? null,
    lastPollAt: state?.lastPollAt?.toISOString() ?? null,
  };
}

type WazuhEventRow = typeof schema.wazuhAttackEvent.$inferSelect;
type UnifiEventRow = typeof schema.unifiThreatEvent.$inferSelect;
export type EventRow = ({ source: "wazuh" } & WazuhEventRow) | ({ source: "unifi" } & UnifiEventRow);

const we = schema.wazuhAttackEvent;
const ue = schema.unifiThreatEvent;

/**
 * Events of both origins (Wazuh alerts and UniFi threat events, ADR 0022) of one organisation, ordered by their shared
 * sequence number. `after` returns the ones newer than a number, oldest first; without it the newest ones come first.
 */
export async function loadEvents(
  organizationId: string,
  options: { after?: number; limit: number },
): Promise<EventRow[]> {
  const { after, limit } = options;
  const ascending = after !== undefined;
  const [wazuh, unifi] = await Promise.all([
    db
      .select()
      .from(we)
      .where(and(eq(we.organizationId, organizationId), ascending ? gt(we.seq, after) : undefined))
      .orderBy(ascending ? we.seq : desc(we.seq))
      .limit(limit),
    db
      .select()
      .from(ue)
      .where(and(eq(ue.organizationId, organizationId), ascending ? gt(ue.seq, after) : undefined))
      .orderBy(ascending ? ue.seq : desc(ue.seq))
      .limit(limit),
  ]);
  const rows: EventRow[] = [
    ...wazuh.map((r) => ({ source: "wazuh" as const, ...r })),
    ...unifi.map((r) => ({ source: "unifi" as const, ...r })),
  ];
  rows.sort((a, b) => (ascending ? a.seq - b.seq : b.seq - a.seq));
  return rows.slice(0, limit);
}

/** The newest sequence number of the organisation's events of both origins; 0 if there are none. */
export async function newestSeq(organizationId: string): Promise<number> {
  const [a] = await db
    .select({ seq: sql<number>`coalesce(max(${we.seq}), 0)::bigint` })
    .from(we)
    .where(eq(we.organizationId, organizationId));
  const [b] = await db
    .select({ seq: sql<number>`coalesce(max(${ue.seq}), 0)::bigint` })
    .from(ue)
    .where(eq(ue.organizationId, organizationId));
  return Math.max(Number(a?.seq ?? 0), Number(b?.seq ?? 0));
}

/**
 * The events as the page shows them: country and network from the local tables (internal addresses are never looked
 * up), and the cached abuse score when OSINT is on. Text fields are passed on as stored (already cleaned and cut);
 * the page renders them as plain text.
 */
export async function viewEvents(organizationId: string, rows: EventRow[]): Promise<AttackEventView[]> {
  if (rows.length === 0) return [];
  const canonical = (ip: string) => canonicalIp(ip) ?? ip;
  const publicIps = [...new Set(rows.filter((r) => ipScope(r.ip) === "public").map((r) => r.ip))];
  const geo = await lookupIps(db, publicIps);
  const [settings] = await db
    .select({ enabled: schema.attackSettings.osintEnabled, provider: schema.attackSettings.osintProvider })
    .from(schema.attackSettings)
    .where(eq(schema.attackSettings.organizationId, organizationId))
    .limit(1);
  const scores = new Map<string, number>();
  if (settings?.enabled && settings.provider && publicIps.length > 0) {
    const o = schema.attackOsintResult;
    const found = await db
      .select({ ip: o.ip, score: o.score })
      .from(o)
      .where(
        and(
          eq(o.organizationId, organizationId),
          eq(o.provider, settings.provider),
          inArray(o.ip, publicIps.map(canonical)),
        ),
      );
    for (const r of found) scores.set(r.ip, r.score);
  }
  return rows.map((r) => {
    const scope = ipScope(r.ip) === "public" ? ("public" as const) : ("internal" as const);
    const info = scope === "public" ? geo.get(canonical(r.ip)) : undefined;
    const common = {
      seq: Number(r.seq),
      at: r.at.toISOString(),
      ip: r.ip,
      scope,
      country: info?.country ?? null,
      asn: info?.asn ?? null,
      score: scope === "public" ? (scores.get(canonical(r.ip)) ?? null) : null,
    };
    if (r.source === "unifi") {
      return {
        ...common,
        ruleId: "",
        level: 0,
        description: r.signature,
        groups: r.category ? [r.category] : [],
        agentId: "",
        agentName: r.siteName ?? "",
        source: "unifi" as const,
        action: r.action,
        destPort: r.destPort,
      };
    }
    return {
      ...common,
      ruleId: r.ruleId,
      level: r.ruleLevel,
      description: r.description,
      groups: r.groups,
      agentId: r.agentId,
      agentName: r.agentName,
      source: "wazuh" as const,
      action: null,
      destPort: null,
    };
  });
}

/* -------------------------------------------------------------------------- */
/* The UniFi preview                                                           */
/* -------------------------------------------------------------------------- */

export interface UnifiLiveInfo {
  enabled: boolean;
  state: IpsState;
  reason: "disabled" | "certificate" | "credentials" | "no-sync" | "rights" | null;
  /** A stored error text of the last poll while the state is "waiting". */
  error: string | null;
  lastEventAt: string | null;
  lastPollAt: string | null;
  /** The connections whose preview is switched on. */
  connections: number;
}

/**
 * The state of the IPS preview of an organisation (ADR 0022), or null if no console has it switched on. With several
 * consoles the one with the newest event speaks for all; the others only add to the count.
 */
export async function unifiLiveInfo(organizationId: string, now = new Date()): Promise<UnifiLiveInfo | null> {
  const c = schema.unifiConnection;
  const rows = await db
    .select()
    .from(c)
    .where(and(eq(c.organizationId, organizationId), eq(c.ipsEnabled, true)));
  if (rows.length === 0) return null;
  const infos = rows.map((row) => ({
    row,
    status: ipsStatus({
      enabled: row.ipsEnabled,
      connectionEnabled: row.enabled,
      certificateOk: row.certStatus === "confirmed",
      hasCredentials: Boolean(row.ipsUsername && row.ipsSecretId),
      synced: row.apiBase !== "auto" && row.lastSyncAt !== null,
      rights: row.ipsRights,
      rightsAcknowledged: row.ipsRightsAcknowledged,
      lastPollAt: row.ipsLastPollAt,
      lastError: row.ipsLastError,
      intervalSeconds: row.ipsIntervalSeconds,
      now,
    }),
  }));
  const best =
    infos.find((i) => i.status.state === "live") ??
    infos.find((i) => i.status.state === "waiting") ??
    (infos[0] as (typeof infos)[number]);
  const lastEvent = rows.reduce<Date | null>(
    (m, r) => (r.ipsLastEventAt && (!m || r.ipsLastEventAt > m) ? r.ipsLastEventAt : m),
    null,
  );
  const lastPoll = rows.reduce<Date | null>(
    (m, r) => (r.ipsLastPollAt && (!m || r.ipsLastPollAt > m) ? r.ipsLastPollAt : m),
    null,
  );
  return {
    enabled: true,
    state: best.status.state,
    reason: best.status.reason,
    error: best.status.error,
    lastEventAt: lastEvent?.toISOString() ?? null,
    lastPollAt: lastPoll?.toISOString() ?? null,
    connections: rows.length,
  };
}

/**
 * Whether UniFi threat events (ADR 0022) are part of the picture: the preview is switched on for a console, or events
 * of it are still stored. Without Wazuh, this is what makes the page show anything.
 */
export async function unifiActive(organizationId: string): Promise<boolean> {
  const [on] = await db
    .select({ id: schema.unifiConnection.id })
    .from(schema.unifiConnection)
    .where(
      and(
        eq(schema.unifiConnection.organizationId, organizationId),
        eq(schema.unifiConnection.ipsEnabled, true),
      ),
    )
    .limit(1);
  if (on) return true;
  const [event] = await db
    .select({ seq: schema.unifiThreatEvent.seq })
    .from(schema.unifiThreatEvent)
    .where(eq(schema.unifiThreatEvent.organizationId, organizationId))
    .limit(1);
  return Boolean(event);
}
