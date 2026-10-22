/**
 * Storing and asking the local GeoIP data (ADR 0016).
 *
 * A dataset is loaded in one transaction: the ranges are inserted in batches while the file is
 * read, validated and counted; only when the whole file has passed does the new dataset replace the
 * active one (which is deleted in the same transaction). Any failure, a damaged file, a size limit
 * or a lost connection, rolls the transaction back, so the last good dataset stays untouched, and
 * the reason is recorded. One load per kind at a time (an advisory lock).
 *
 * Lookup is one indexed probe per address and table: the range with the largest start at or below
 * the address, kept only if its end covers the address. That is correct because the ranges of a
 * dataset do not overlap (the reader refuses overlapping ranges).
 */

import { newId } from "@garnetops/core";
import {
  canonicalIp,
  GeoipError,
  type GeoipKind,
  type GeoipRow,
  ipScope,
  type ParseStats,
} from "@garnetops/core/geoip";
import { and, desc, eq, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";

const BATCH = 2000;

export class GeoipBusyError extends Error {
  constructor() {
    super("Another load of this kind is running");
    this.name = "GeoipBusyError";
  }
}

export interface ImportInput {
  kind: GeoipKind;
  source: "import" | "download";
  /** `YYYY-MM` of the DB-IP release, if known. */
  month: string | null;
  importedBy: string | null;
  rows: AsyncIterable<GeoipRow>;
  /** The reader's counters; read after the rows have been consumed (SHA-256, sizes). */
  stats: ParseStats;
  /**
   * Names a failure of the source of the rows (a network error, say) with a short code to store.
   * Return null for errors that are not the source's; those are stored as `storage`.
   */
  classify?: (error: unknown) => string | null;
}

/** Loads a dataset and makes it the active one. Throws `GeoipError` (stored as a failed load) or `GeoipBusyError` (not stored). */
export async function importDataset(db: Database, input: ImportInput): Promise<{ id: string; rows: number }> {
  const id = newId("geo");
  try {
    let count = 0;
    await db.transaction(async (tx) => {
      const lock = await tx.execute<{ ok: boolean }>(
        sql`select pg_try_advisory_xact_lock(hashtext(${`garnetops:geoip:${input.kind}`})) as ok`,
      );
      if (!lock.rows[0]?.ok) throw new GeoipBusyError();
      await tx.insert(schema.geoipDataset).values({
        id,
        kind: input.kind,
        state: "loading",
        source: input.source,
        datasetMonth: input.month,
        importedBy: input.importedBy,
      });
      let batch: GeoipRow[] = [];
      const flush = async () => {
        if (batch.length === 0) return;
        if (input.kind === "country") {
          await tx.insert(schema.geoipCountryRange).values(
            batch.map((r) => ({
              datasetId: id,
              rangeStart: r.start,
              rangeEnd: r.end,
              country: (r as { country: string }).country,
            })),
          );
        } else {
          await tx.insert(schema.geoipAsnRange).values(
            batch.map((r) => ({
              datasetId: id,
              rangeStart: r.start,
              rangeEnd: r.end,
              asn: (r as { asn: number }).asn,
              org: (r as { org: string }).org,
            })),
          );
        }
        count += batch.length;
        batch = [];
      };
      for await (const row of input.rows) {
        batch.push(row);
        if (batch.length >= BATCH) await flush();
      }
      await flush();
      if (count === 0) throw new GeoipError("empty");
      const d = schema.geoipDataset;
      await tx.delete(d).where(and(eq(d.kind, input.kind), eq(d.state, "active")));
      await tx.delete(d).where(and(eq(d.kind, input.kind), eq(d.state, "failed")));
      await tx
        .update(d)
        .set({
          state: "active",
          rowCount: count,
          sha256: input.stats.sha256,
          compressedBytes: input.stats.compressedBytes,
          finishedAt: new Date(),
        })
        .where(eq(d.id, id));
    });
    return { id, rows: count };
  } catch (error) {
    if (error instanceof GeoipBusyError) throw error;
    const named = error instanceof GeoipError ? null : (input.classify?.(error) ?? null);
    const code = error instanceof GeoipError ? error.code : (named ?? "storage");
    await recordFailure(db, input, code).catch(() => {});
    if (error instanceof GeoipError || named) throw error;
    throw new GeoipError("storage");
  }
}

/** Remembers why the last load of this kind was refused; the active dataset is untouched. */
export async function recordFailure(
  db: Database,
  input: Pick<ImportInput, "kind" | "source" | "month" | "importedBy" | "stats">,
  code: string,
): Promise<void> {
  const d = schema.geoipDataset;
  await db.transaction(async (tx) => {
    await tx.delete(d).where(and(eq(d.kind, input.kind), eq(d.state, "failed")));
    await tx.insert(d).values({
      id: newId("geo"),
      kind: input.kind,
      state: "failed",
      source: input.source,
      datasetMonth: input.month,
      error: code,
      importedBy: input.importedBy,
      compressedBytes: input.stats.compressedBytes || null,
      finishedAt: new Date(),
    });
  });
}

export interface DatasetStatus {
  kind: GeoipKind;
  active: {
    id: string;
    source: "import" | "download";
    month: string | null;
    rows: number;
    loadedAt: Date;
    sha256: string | null;
  } | null;
  /** The last refused load, if it is newer than the active dataset or there is none. */
  lastFailure: { source: "import" | "download"; error: string; at: Date } | null;
}

export async function datasetStatus(db: Database): Promise<DatasetStatus[]> {
  const d = schema.geoipDataset;
  const rows = await db.select().from(d).orderBy(desc(d.createdAt));
  return (["country", "asn"] as const).map((kind) => {
    const active = rows.find((r) => r.kind === kind && r.state === "active");
    const failed = rows.find((r) => r.kind === kind && r.state === "failed");
    return {
      kind,
      active: active
        ? {
            id: active.id,
            source: active.source,
            month: active.datasetMonth,
            rows: active.rowCount ?? 0,
            loadedAt: active.finishedAt ?? active.createdAt,
            sha256: active.sha256,
          }
        : null,
      lastFailure:
        failed && (!active || failed.createdAt > active.createdAt)
          ? {
              source: failed.source,
              error: failed.error ?? "storage",
              at: failed.finishedAt ?? failed.createdAt,
            }
          : null,
    };
  });
}

export interface GeoInfo {
  country: string | null;
  asn: number | null;
  org: string | null;
}

const LOOKUP_CHUNK = 2000;

/**
 * Country, AS number and organisation for each public address, from the local tables only.
 * Internal (private or reserved) addresses and text that is not an address are not looked up and
 * are absent from the result. An address the tables do not cover maps to nulls. Keys are the
 * canonical text (`canonicalIp`) of the input.
 */
export async function lookupIps(db: Database, ips: readonly string[]): Promise<Map<string, GeoInfo>> {
  const wanted = [
    ...new Set(ips.flatMap((ip) => (ipScope(ip) === "public" ? [canonicalIp(ip) as string] : []))),
  ];
  const result = new Map<string, GeoInfo>();
  if (wanted.length === 0) return result;
  const d = schema.geoipDataset;
  const active = await db.select({ id: d.id, kind: d.kind }).from(d).where(eq(d.state, "active"));
  const countryId = active.find((a) => a.kind === "country")?.id ?? null;
  const asnId = active.find((a) => a.kind === "asn")?.id ?? null;
  for (const ip of wanted) result.set(ip, { country: null, asn: null, org: null });
  if (!countryId && !asnId) return result;

  for (let i = 0; i < wanted.length; i += LOOKUP_CHUNK) {
    const chunk = wanted.slice(i, i + LOOKUP_CHUNK);
    const list = sql.join(
      chunk.map((ip) => sql`${ip}::inet`),
      sql`, `,
    );
    const countryJoin = countryId
      ? sql`left join lateral (
          select x.country from (
            select r.range_end, r.country from geoip_country_range r
            where r.dataset_id = ${countryId} and r.range_start <= q.ip
            order by r.range_start desc limit 1) x
          where x.range_end >= q.ip) c on true`
      : sql`left join lateral (select null::text as country where false) c on true`;
    const asnJoin = asnId
      ? sql`left join lateral (
          select x.asn, x.org from (
            select r.range_end, r.asn, r.org from geoip_asn_range r
            where r.dataset_id = ${asnId} and r.range_start <= q.ip
            order by r.range_start desc limit 1) x
          where x.range_end >= q.ip) a on true`
      : sql`left join lateral (select null::bigint as asn, null::text as org where false) a on true`;
    const rows = await db.execute<{
      ip: string;
      country: string | null;
      asn: string | number | null;
      org: string | null;
    }>(
      sql`select host(q.ip) as ip, c.country, a.asn, a.org
          from unnest(array[${list}]) as q(ip)
          ${countryJoin}
          ${asnJoin}`,
    );
    for (const row of rows.rows) {
      const key = canonicalIp(row.ip);
      if (!key) continue;
      result.set(key, {
        country: row.country,
        asn: row.asn === null ? null : Number(row.asn),
        org: row.org,
      });
    }
  }
  return result;
}
