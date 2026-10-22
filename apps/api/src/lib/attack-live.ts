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
import { privilegesAcknowledged } from "@garnetops/core/wazuh";
import { lookupIps, schema } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
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

type EventRow = typeof schema.wazuhAttackEvent.$inferSelect;

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
    return {
      seq: r.seq,
      at: r.at.toISOString(),
      ip: r.ip,
      scope,
      country: info?.country ?? null,
      asn: info?.asn ?? null,
      ruleId: r.ruleId,
      level: r.ruleLevel,
      description: r.description,
      groups: r.groups,
      agentId: r.agentId,
      agentName: r.agentName,
      score: scope === "public" ? (scores.get(canonical(r.ip)) ?? null) : null,
    };
  });
}
