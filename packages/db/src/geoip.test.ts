/**
 * Loading and looking up the local GeoIP tables (ADR 0016) against a throw-away database on the
 * development PostgreSQL: lookup correctness against a brute-force reference, IPv6, internal
 * addresses, speed for 10,000 addresses, replacing a dataset, keeping the last good one when a
 * load fails halfway, one load per kind at a time. Synthetic data only (documentation ranges).
 * Skipped without the development PostgreSQL.
 */
import { gzipSync } from "node:zlib";
import {
  canonicalIp,
  formatIp,
  type GeoipRow,
  newParseStats,
  parseIp,
  readDataset,
} from "@garnetops/core/geoip";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { datasetStatus, GeoipBusyError, importDataset, lookupIps } from "./geoip.ts";
import { schema } from "./index.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";

const adminUrl = devDatabaseUrl();

async function* from<T>(items: Iterable<T>): AsyncGenerator<T> {
  for (const item of items) yield item;
}
const rng = (seed: number) => () => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 2 ** 32;
};
const COUNTRIES = ["DE", "FR", "NL", "US", "BR", "JP", "ZZ"];

/** Sorted, non-overlapping IPv4 ranges with gaps, from a seed. */
function syntheticRanges(n: number, seed = 1) {
  const random = rng(seed);
  const ranges: { start: number; end: number; country: string; asn: number }[] = [];
  let cursor = 16_777_216; // 1.0.0.0
  for (let i = 0; i < n; i++) {
    cursor += 1 + Math.floor(random() * 300);
    const size = 1 + Math.floor(random() * 255);
    ranges.push({
      start: cursor,
      end: cursor + size - 1,
      country: COUNTRIES[Math.floor(random() * COUNTRIES.length)] as string,
      asn: 64_500 + Math.floor(random() * 50),
    });
    cursor += size;
  }
  return ranges;
}
const v4 = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");

describe.skipIf(!adminUrl)("GeoIP tables", () => {
  let t: TestDatabase;
  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "geoip");
  });
  afterAll(async () => {
    await t?.drop();
  });

  const country = (ranges: ReturnType<typeof syntheticRanges>): GeoipRow[] =>
    ranges.map((r) => ({ start: v4(r.start), end: v4(r.end), country: r.country }));
  const asn = (ranges: ReturnType<typeof syntheticRanges>): GeoipRow[] =>
    ranges.map((r) => ({ start: v4(r.start), end: v4(r.end), asn: r.asn, org: `Example Network ${r.asn}` }));
  const load = (kind: "country" | "asn", rows: GeoipRow[], month: string | null = "2026-10") =>
    importDataset(t.db, {
      kind,
      source: "import",
      month,
      importedBy: null,
      rows: from(rows),
      stats: newParseStats(),
    });

  it("finds the right range for every kind of address and nothing for gaps", async () => {
    const ranges = syntheticRanges(300, 7);
    await load("country", [
      ...country(ranges),
      { start: "2001:db8::", end: "2001:db8::ffff", country: "NL" },
      { start: "2001:db8:1::", end: "2001:db8:1::ffff", country: "FR" },
    ]);
    await load("asn", [
      ...asn(ranges),
      { start: "2001:db8::", end: "2001:db8::ffff", asn: 64_999, org: "Example v6" } as GeoipRow,
    ]);
    const probes: string[] = [];
    const random = rng(99);
    for (const r of ranges) {
      probes.push(v4(r.start), v4(r.end), v4(r.start + Math.floor((r.end - r.start) / 2)));
      probes.push(v4(r.start - 1), v4(r.end + 1)); // edges just outside (a gap or the next range)
    }
    for (let i = 0; i < 200; i++) probes.push(v4(16_777_216 + Math.floor(random() * 90_000)));
    probes.push("2001:db8::1", "2001:db8::ffff", "2001:db8::1:0", "2001:db8:1::5", "2001:db9::1");

    const found = await lookupIps(t.db, probes);
    const reference = (ip: string) => {
      const parsed = parseIp(ip) as NonNullable<ReturnType<typeof parseIp>>;
      if (parsed.family === 4) {
        const n = Number(parsed.value);
        const r = ranges.find((x) => n >= x.start && n <= x.end);
        return r ? { country: r.country, asn: r.asn } : { country: null, asn: null };
      }
      if (
        formatIp(parsed).startsWith("2001:db8:0:0:0:0:0:") &&
        parsed.value <= 0x20010db8000000000000000000000000n + 0xffffn
      ) {
        return { country: "NL", asn: 64_999 };
      }
      if (formatIp(parsed).startsWith("2001:db8:1:")) return { country: "FR", asn: null };
      return { country: null, asn: null };
    };
    let checked = 0;
    for (const ip of probes) {
      const key = canonicalIp(ip);
      if (!key) continue;
      const got = found.get(key);
      const want = reference(ip);
      if (!got) continue; // internal or invalid addresses are not looked up (checked below)
      expect({ ip, country: got.country, asn: got.asn }, ip).toEqual({ ip, ...want });
      checked++;
    }
    expect(checked).toBeGreaterThan(1000);
    expect(found.get(canonicalIp("2001:db8::1") as string)).toMatchObject({
      country: "NL",
      asn: 64_999,
      org: "Example v6",
    });
  });

  it("does not look up internal addresses and reads IPv4-mapped IPv6 as IPv4", async () => {
    const ranges = syntheticRanges(5, 3);
    await load("country", country(ranges));
    const inside = v4(ranges[2]?.start as number);
    const found = await lookupIps(t.db, [
      "10.0.0.1",
      "192.168.1.1",
      "127.0.0.1",
      "fd00::1",
      "fe80::1",
      "garbage",
      `::ffff:${inside}`,
      inside,
    ]);
    expect([...found.keys()]).toEqual([inside]);
    expect(found.get(inside)?.country).toBe(ranges[2]?.country);
  });

  it("answers with nulls when no dataset is loaded, without failing", async () => {
    const empty = await createTestDatabase(adminUrl as string, "geoip_empty");
    try {
      const found = await lookupIps(empty.db, ["198.51.100.7"]);
      expect(found.get("198.51.100.7")).toEqual({ country: null, asn: null, org: null });
    } finally {
      await empty.drop();
    }
  });

  it("looks up 10,000 addresses in a table of 200,000 ranges quickly", async () => {
    const big = await createTestDatabase(adminUrl as string, "geoip_speed");
    try {
      const ranges = syntheticRanges(200_000, 11);
      const started = performance.now();
      await importDataset(big.db, {
        kind: "country",
        source: "import",
        month: "2026-10",
        importedBy: null,
        rows: from(country(ranges)),
        stats: newParseStats(),
      });
      await importDataset(big.db, {
        kind: "asn",
        source: "import",
        month: "2026-10",
        importedBy: null,
        rows: from(asn(ranges)),
        stats: newParseStats(),
      });
      const loadMs = performance.now() - started;
      const random = rng(5);
      const probes = Array.from({ length: 10_000 }, () => v4(16_777_216 + Math.floor(random() * 90_000_000)));
      const t0 = performance.now();
      const found = await lookupIps(big.db, probes);
      const lookupMs = performance.now() - t0;
      const hits = [...found.values()].filter((g) => g.country !== null).length;
      console.log(
        `geoip: loaded 2 x 200000 ranges in ${Math.round(loadMs)} ms; 10000 lookups in ${Math.round(lookupMs)} ms (${hits} located)`,
      );
      expect(found.size).toBeGreaterThan(9000);
      expect(hits).toBeGreaterThan(100);
      expect(lookupMs).toBeLessThan(3000);
    } finally {
      await big.drop();
    }
  }, 120_000);

  it("replaces the active dataset and records the month, rows and checksum", async () => {
    await load("country", country(syntheticRanges(10, 21)), "2026-09");
    const before = (await datasetStatus(t.db)).find((s) => s.kind === "country");
    expect(before?.active).toMatchObject({ month: "2026-09", rows: 10, source: "import" });
    const stats = newParseStats();
    const gz = gzipSync(Buffer.from("198.51.100.0,198.51.100.255,DE\n203.0.113.0,203.0.113.255,FR\n"));
    await importDataset(t.db, {
      kind: "country",
      source: "download",
      month: "2026-10",
      importedBy: null,
      rows: readDataset("country", from([gz]), stats),
      stats,
    });
    const after = (await datasetStatus(t.db)).find((s) => s.kind === "country");
    expect(after?.active).toMatchObject({ month: "2026-10", rows: 2, source: "download" });
    expect(after?.active?.sha256).toMatch(/^[0-9a-f]{64}$/);
    // The old dataset's ranges are gone with it.
    const datasets = await t.db.select().from(schema.geoipDataset);
    expect(datasets.filter((d) => d.kind === "country" && d.state === "active")).toHaveLength(1);
    const remaining = await t.pool.query("select count(*)::int as n from geoip_country_range");
    expect(remaining.rows[0].n).toBe(2);
    expect((await lookupIps(t.db, ["198.51.100.9"])).get("198.51.100.9")?.country).toBe("DE");
  });

  it("keeps the last good dataset when a load fails halfway, and says why", async () => {
    await load("country", [{ start: "198.51.100.0", end: "198.51.100.255", country: "DE" }], "2026-08");
    async function* broken(): AsyncGenerator<GeoipRow> {
      for (let i = 0; i < 5000; i++) {
        yield { start: v4(50_000_000 + i * 10), end: v4(50_000_000 + i * 10 + 5), country: "FR" };
      }
      throw new Error("the connection was lost");
    }
    await expect(
      importDataset(t.db, {
        kind: "country",
        source: "import",
        month: "2026-11",
        importedBy: null,
        rows: broken(),
        stats: newParseStats(),
      }),
    ).rejects.toMatchObject({ name: "GeoipError", code: "storage" });
    const status = (await datasetStatus(t.db)).find((s) => s.kind === "country");
    expect(status?.active).toMatchObject({ month: "2026-08", rows: 1 });
    expect(status?.lastFailure).toMatchObject({ error: "storage", source: "import" });
    // No half-loaded ranges stay behind.
    const n = await t.pool.query("select count(*)::int as n from geoip_country_range");
    expect(n.rows[0].n).toBe(1);
    expect((await lookupIps(t.db, ["198.51.100.1"])).get("198.51.100.1")?.country).toBe("DE");

    // A refused file (not gzip) is recorded with its code.
    const stats = newParseStats();
    await expect(
      importDataset(t.db, {
        kind: "country",
        source: "import",
        month: null,
        importedBy: null,
        rows: readDataset("country", from([Buffer.from("not gzip at all")]), stats),
        stats,
      }),
    ).rejects.toMatchObject({ code: "notGzip" });
    expect((await datasetStatus(t.db)).find((s) => s.kind === "country")?.lastFailure?.error).toBe("notGzip");
    // A later success clears the failure.
    await load("country", [{ start: "198.51.100.0", end: "198.51.100.255", country: "NL" }], "2026-10");
    expect((await datasetStatus(t.db)).find((s) => s.kind === "country")?.lastFailure).toBeNull();
  });

  it("refuses an empty dataset and a second load of the same kind while one runs", async () => {
    await expect(load("asn", [])).rejects.toMatchObject({ code: "empty" });
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function* slow(): AsyncGenerator<GeoipRow> {
      yield { start: "198.51.100.0", end: "198.51.100.255", asn: 64_500, org: "Slow" };
      await gate;
    }
    const first = importDataset(t.db, {
      kind: "asn",
      source: "import",
      month: null,
      importedBy: null,
      rows: slow(),
      stats: newParseStats(),
    });
    // Wait until the first load holds its lock.
    for (let i = 0; i < 100; i++) {
      const held = await t.pool.query("select count(*)::int as n from pg_locks where locktype = 'advisory'");
      if (held.rows[0].n > 0) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    await expect(
      load("asn", [{ start: "203.0.113.0", end: "203.0.113.255", asn: 64_501, org: "Second" } as GeoipRow]),
    ).rejects.toBeInstanceOf(GeoipBusyError);
    release();
    await first;
    const status = (await datasetStatus(t.db)).find((s) => s.kind === "asn");
    expect(status?.active?.rows).toBe(1);
  });
});
