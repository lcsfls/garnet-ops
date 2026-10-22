/**
 * The stored attack aggregates of a Wazuh connection, enriched from the local GeoIP tables
 * (ADR 0016). Used by the API (the Attacks page) and by the worker (the AI summary), so both count
 * the same way. Enrichment reads only the local tables; nothing is sent anywhere.
 */
import { type AttackSource, mergeSources, windowOf } from "@garnetops/core/attacks";
import { canonicalIp, ipScope } from "@garnetops/core/geoip";
import { MAX_SOURCE_IPS, type Window } from "@garnetops/core/wazuh";
import { and, eq, sql } from "drizzle-orm";
import { lookupIps } from "./geoip.ts";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";

export async function loadAttackSources(
  db: Database,
  connectionId: string,
  window: Window,
): Promise<AttackSource[]> {
  const s = schema.wazuhSourceIp;
  const rows = await db
    .select()
    .from(s)
    .where(and(eq(s.connectionId, connectionId), eq(s.window, windowOf(window))));
  const geo = await lookupIps(
    db,
    rows.map((r) => r.ip),
  );
  return rows.map((r) => {
    const scope = ipScope(r.ip) === "public" ? ("public" as const) : ("internal" as const);
    const info = scope === "public" ? geo.get(canonical(r.ip)) : undefined;
    return {
      ip: r.ip,
      count: r.count,
      groups: r.groups,
      firstSeen: r.firstSeenAt?.toISOString() ?? null,
      lastSeen: r.lastSeenAt?.toISOString() ?? null,
      agents: r.agents,
      scope,
      country: info?.country ?? null,
      asn: info?.asn ?? null,
      org: info?.org ?? null,
    };
  });
}

const canonical = (ip: string) => canonicalIp(ip) ?? ip;

const WINDOW_HOURS: Record<Window, number> = { "24h": 24, "7d": 7 * 24, "30d": 30 * 24 };

/** The numbers of the UniFi threat events of an organisation in a window and in the period before it (ADR 0022). */
export interface UnifiTotals {
  alerts: number;
  distinctSources: number;
  previousAlerts: number;
  previousDistinctSources: number;
  /** The newest event stored, whatever the window. */
  lastEventAt: Date | null;
}

export async function loadUnifiTotals(
  db: Database,
  organizationId: string,
  window: Window,
  now: Date = new Date(),
): Promise<UnifiTotals> {
  const e = schema.unifiThreatEvent;
  const hours = WINDOW_HOURS[window];
  const to = now.toISOString();
  const rows = await db.execute<{
    alerts: number;
    sources: number;
    previous_alerts: number;
    previous_sources: number;
    last_at: Date | null;
  }>(sql`
    select
      (count(*) filter (where ${e.at} > ${to}::timestamptz - make_interval(hours => ${hours})))::int as alerts,
      (count(distinct ${e.ip}) filter (where ${e.at} > ${to}::timestamptz - make_interval(hours => ${hours})))::int as sources,
      (count(*) filter (where ${e.at} <= ${to}::timestamptz - make_interval(hours => ${hours})))::int as previous_alerts,
      (count(distinct ${e.ip}) filter (where ${e.at} <= ${to}::timestamptz - make_interval(hours => ${hours})))::int as previous_sources,
      max(${e.at}) as last_at
    from ${e}
    where ${e.organizationId} = ${organizationId}
      and ${e.at} > ${to}::timestamptz - make_interval(hours => ${hours * 2})`);
  const row = rows.rows[0];
  return {
    alerts: row?.alerts ?? 0,
    distinctSources: row?.sources ?? 0,
    previousAlerts: row?.previous_alerts ?? 0,
    previousDistinctSources: row?.previous_sources ?? 0,
    lastEventAt: row?.last_at ? new Date(row.last_at) : null,
  };
}

/**
 * The busiest source addresses of the UniFi threat events of an organisation in a window, with the part that the
 * console blocked and the same local GeoIP enrichment as the Wazuh sources (ADR 0022). Counted when read from the
 * stored events, so the numbers follow the retention period and the "delete now" action at once.
 */
export async function loadUnifiSources(
  db: Database,
  organizationId: string,
  window: Window,
  now: Date = new Date(),
): Promise<AttackSource[]> {
  const e = schema.unifiThreatEvent;
  const hours = WINDOW_HOURS[window];
  const rows = await db.execute<{
    ip: string;
    count: number;
    blocked: number;
    first_at: Date;
    last_at: Date;
  }>(sql`
    select ${e.ip} as ip, count(*)::int as count,
           (count(*) filter (where ${e.action} = 'blocked'))::int as blocked,
           min(${e.at}) as first_at, max(${e.at}) as last_at
    from ${e}
    where ${e.organizationId} = ${organizationId}
      and ${e.at} > ${now.toISOString()}::timestamptz - make_interval(hours => ${hours})
    group by ${e.ip}
    order by count(*) desc, ${e.ip}
    limit ${MAX_SOURCE_IPS}`);
  const geo = await lookupIps(
    db,
    rows.rows.map((r) => r.ip),
  );
  return rows.rows.map((r) => {
    const scope = ipScope(r.ip) === "public" ? ("public" as const) : ("internal" as const);
    const info = scope === "public" ? geo.get(canonical(r.ip)) : undefined;
    return {
      ip: r.ip,
      count: r.count,
      blocked: r.blocked,
      groups: [],
      firstSeen: new Date(r.first_at).toISOString(),
      lastSeen: new Date(r.last_at).toISOString(),
      agents: [],
      scope,
      country: info?.country ?? null,
      asn: info?.asn ?? null,
      org: info?.org ?? null,
    };
  });
}

/** The sources of the Wazuh connection (if any) and of the UniFi threat events, joined (ADR 0022). */
export async function loadAllAttackSources(
  db: Database,
  organizationId: string,
  wazuhConnectionId: string | null,
  window: Window,
): Promise<AttackSource[]> {
  const wazuh = wazuhConnectionId ? await loadAttackSources(db, wazuhConnectionId, window) : [];
  const unifi = await loadUnifiSources(db, organizationId, window);
  return unifi.length === 0 ? wazuh : mergeSources(wazuh, unifi, canonical);
}
