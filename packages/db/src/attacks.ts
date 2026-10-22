/**
 * The stored attack aggregates of a Wazuh connection, enriched from the local GeoIP tables
 * (ADR 0016). Used by the API (the Attacks page) and by the worker (the AI summary), so both count
 * the same way. Enrichment reads only the local tables; nothing is sent anywhere.
 */
import { type AttackSource, windowOf } from "@garnetops/core/attacks";
import { canonicalIp, ipScope } from "@garnetops/core/geoip";
import type { Window } from "@garnetops/core/wazuh";
import { and, eq } from "drizzle-orm";
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
