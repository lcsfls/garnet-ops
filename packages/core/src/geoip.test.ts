import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  canonicalIp,
  cleanText,
  dbipUrl,
  dbipUrlPattern,
  formatIp,
  GEOIP_LIMITS,
  inflateLimited,
  ipKey,
  ipScope,
  monthOf,
  monthsSince,
  newParseStats,
  parseDatasetFilename,
  parseIp,
  parseLine,
  parseRows,
  previousMonth,
  readDataset,
  splitCsvLine,
  splitLines,
} from "./geoip.ts";

async function* chunked(data: Uint8Array, size = 1000): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < data.length; i += size) yield data.subarray(i, i + size);
}
const gz = (text: string) => gzipSync(Buffer.from(text));
async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
}
async function* lines(...xs: string[]) {
  for (const x of xs) yield x;
}
const fails = (promise: Promise<unknown>, code: string) =>
  expect(promise).rejects.toMatchObject({ name: "GeoipError", code });

describe("IP addresses", () => {
  it("parses IPv4 and IPv6 into comparable numbers", () => {
    expect(parseIp("192.0.2.1")).toEqual({ family: 4, value: 0xc0000201n });
    expect(parseIp("2001:db8::1")).toEqual({ family: 6, value: 0x20010db8000000000000000000000001n });
    expect(parseIp("::")).toEqual({ family: 6, value: 0n });
    expect(parseIp("::1")).toEqual({ family: 6, value: 1n });
    expect(parseIp("2001:db8:0:0:0:0:0:1")).toEqual(parseIp("2001:db8::1"));
    expect(parseIp("2001:DB8::1")).toEqual(parseIp("2001:db8::1"));
  });

  it("reads IPv4-mapped IPv6 addresses as IPv4, so one machine is never two keys", () => {
    expect(parseIp("::ffff:192.0.2.1")).toEqual(parseIp("192.0.2.1"));
    expect(parseIp("::ffff:c000:201")).toEqual(parseIp("192.0.2.1"));
    expect(parseIp("64:ff9b::192.0.2.1")?.family).toBe(6);
  });

  it("refuses anything that is not an address", () => {
    for (const bad of [
      "",
      "1.2.3",
      "256.1.1.1",
      "1.2.3.4.5",
      "01.2.3.4",
      "abc",
      "2001:db8::1::2",
      "1:2:3:4:5:6:7:8:9",
      " 1.2.3.4",
      "1.2.3.4/24",
      "::ffff:1.2.3",
      "g::1",
    ]) {
      expect(parseIp(bad), bad).toBeNull();
    }
  });

  it("formats canonical text that round-trips", () => {
    for (const text of [
      "192.0.2.1",
      "0.0.0.0",
      "255.255.255.255",
      "2001:db8::1",
      "::",
      "ffff::",
      "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
    ]) {
      const ip = parseIp(text);
      expect(ip).not.toBeNull();
      expect(parseIp(formatIp(ip as NonNullable<typeof ip>))).toEqual(ip);
    }
    expect(canonicalIp("::ffff:192.0.2.1")).toBe("192.0.2.1");
    expect(canonicalIp("2001:db8::1")).toBe("2001:db8:0:0:0:0:0:1");
    expect(canonicalIp("nope")).toBeNull();
  });

  it("orders every IPv4 address before every IPv6 address", () => {
    const v4max = ipKey(parseIp("255.255.255.255") as never);
    const v6min = ipKey(parseIp("::") as never);
    expect(v4max < v6min).toBe(true);
  });

  it("calls private and reserved addresses internal and documentation ranges public", () => {
    expect(ipScope("10.1.2.3")).toBe("internal");
    expect(ipScope("192.168.0.9")).toBe("internal");
    expect(ipScope("172.16.5.5")).toBe("internal");
    expect(ipScope("100.64.0.1")).toBe("internal");
    expect(ipScope("127.0.0.1")).toBe("internal");
    expect(ipScope("169.254.169.254")).toBe("internal");
    expect(ipScope("fd00::1")).toBe("internal");
    expect(ipScope("fe80::1")).toBe("internal");
    expect(ipScope("::ffff:10.0.0.1")).toBe("internal");
    expect(ipScope("224.0.0.1")).toBe("internal");
    expect(ipScope("198.51.100.7")).toBe("public");
    expect(ipScope("203.0.113.9")).toBe("public");
    expect(ipScope("2001:db8::7")).toBe("public");
    expect(ipScope("garbage")).toBe("invalid");
  });
});

describe("DB-IP names and URLs", () => {
  it("builds the one download URL and refuses anything else", () => {
    expect(dbipUrl("country", "2026-10")).toBe(
      "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz",
    );
    expect(dbipUrl("asn", "2026-01")).toBe("https://download.db-ip.com/free/dbip-asn-lite-2026-01.csv.gz");
    expect(dbipUrlPattern("asn")).toBe("https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.csv.gz");
    for (const bad of ["2026-13", "2026-00", "26-10", "2026-10/../x", "2026-1", "../../etc", "1999-01"]) {
      expect(() => dbipUrl("country", bad), bad).toThrow();
    }
  });

  it("knows the file names and months", () => {
    expect(parseDatasetFilename("dbip-country-lite-2026-10.csv.gz")).toEqual({
      kind: "country",
      month: "2026-10",
    });
    expect(parseDatasetFilename("dbip-asn-lite-2026-02.csv.gz")).toEqual({ kind: "asn", month: "2026-02" });
    expect(parseDatasetFilename("dbip-city-lite-2026-10.csv.gz")).toBeNull();
    expect(parseDatasetFilename("../dbip-country-lite-2026-10.csv.gz")).toBeNull();
    expect(monthOf(new Date(Date.UTC(2026, 0, 31)))).toBe("2026-01");
    expect(previousMonth("2026-01")).toBe("2025-12");
    expect(previousMonth("2026-10")).toBe("2026-09");
    expect(monthsSince("2026-07", new Date(Date.UTC(2026, 9, 22)))).toBe(3);
    expect(monthsSince("junk", new Date())).toBe(Number.POSITIVE_INFINITY);
  });
});

describe("CSV lines", () => {
  it("splits plain, quoted and empty fields (RFC 4180)", () => {
    expect(splitCsvLine("a,b,c")).toEqual(["a", "b", "c"]);
    expect(splitCsvLine('1.0.0.0,1.0.0.255,64500,"Example, Inc."')).toEqual([
      "1.0.0.0",
      "1.0.0.255",
      "64500",
      "Example, Inc.",
    ]);
    expect(splitCsvLine('a,"he said ""hi""",c')).toEqual(["a", 'he said "hi"', "c"]);
    expect(splitCsvLine("a,,c")).toEqual(["a", "", "c"]);
    expect(splitCsvLine("a,b,")).toEqual(["a", "b", ""]);
    expect(splitCsvLine('a,""')).toEqual(["a", ""]);
  });

  it("rejects broken quoting instead of guessing", () => {
    for (const bad of ['a,"unclosed', 'a,b"c,d', 'a,"b"c', '"a"b']) expect(splitCsvLine(bad), bad).toBeNull();
  });
});

describe("one line", () => {
  it("reads a country line, IPv4 and IPv6", () => {
    const v4 = parseLine("country", "198.51.100.0,198.51.100.255,de");
    expect(v4).toMatchObject({
      ok: true,
      row: { start: "198.51.100.0", end: "198.51.100.255", country: "DE" },
    });
    const v6 = parseLine("country", "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,FR");
    expect(v6).toMatchObject({ ok: true, row: { country: "FR" } });
  });

  it("reads an ASN line with a quoted organisation and cleans it", () => {
    const row = parseLine("asn", '203.0.113.0,203.0.113.255,64500,"Example‮ Networks,\tInc."');
    expect(row).toMatchObject({ ok: true, row: { asn: 64500, org: "Example Networks, Inc." } });
    expect(parseLine("asn", "203.0.113.0,203.0.113.255,AS64501,Example")).toMatchObject({
      ok: true,
      row: { asn: 64501 },
    });
    expect(parseLine("asn", "203.0.113.0,203.0.113.255,0,")).toMatchObject({
      ok: true,
      row: { asn: 0, org: "" },
    });
  });

  it("explains why a line is not usable", () => {
    expect(parseLine("country", "198.51.100.0,198.51.100.255")).toEqual({ ok: false, problem: "shape" });
    expect(parseLine("country", "198.51.100.0,198.51.100.255,DEU")).toEqual({ ok: false, problem: "code" });
    expect(parseLine("country", "198.51.100.0,198.51.100.255,1X")).toEqual({ ok: false, problem: "code" });
    expect(parseLine("country", "198.51.100.255,198.51.100.0,DE")).toEqual({ ok: false, problem: "order" });
    expect(parseLine("country", "198.51.100.0,2001:db8::1,DE")).toEqual({ ok: false, problem: "address" });
    expect(parseLine("country", "not-an-ip,198.51.100.0,DE")).toEqual({ ok: false, problem: "address" });
    expect(parseLine("asn", "198.51.100.0,198.51.100.255,99999999999,X")).toEqual({
      ok: false,
      problem: "asn",
    });
    expect(parseLine("asn", "198.51.100.0,198.51.100.255,-5,X")).toEqual({ ok: false, problem: "asn" });
    expect(parseLine("country", "198.51.100.0,198.51.100.255,64500,Example")).toEqual({
      ok: false,
      problem: "kind",
    });
    expect(parseLine("asn", "198.51.100.0,198.51.100.255,DE")).toEqual({ ok: false, problem: "kind" });
  });

  it("cleans text for display", () => {
    expect(cleanText("  A\u0000B\n\tC  ", 10)).toBe("A B C");
    expect(cleanText("x".repeat(500), 200)).toHaveLength(200);
  });
});

describe("rows of a file", () => {
  const row = (a: string, b: string, cc = "DE") => `${a},${b},${cc}`;

  it("returns valid rows in order, IPv4 then IPv6, and counts them", async () => {
    const stats = newParseStats();
    const rows = await collect(
      parseRows(
        "country",
        lines(
          row("198.51.100.0", "198.51.100.255"),
          row("203.0.113.0", "203.0.113.255", "FR"),
          "",
          row("2001:db8::", "2001:db8::ffff", "NL"),
        ),
        stats,
      ),
    );
    expect(rows).toHaveLength(3);
    expect(stats).toMatchObject({ lines: 3, rows: 3, invalid: 0 });
  });

  it("skips overlapping and out-of-order ranges and counts them", async () => {
    const stats = newParseStats();
    const rows = await collect(
      parseRows(
        "country",
        lines(
          row("198.51.100.0", "198.51.100.255"),
          row("198.51.100.128", "198.51.101.10"), // overlaps the first
          row("198.51.100.0", "198.51.100.255"), // the same again
          row("192.0.2.0", "192.0.2.255"), // before the previous: unsorted
          row("198.51.101.0", "198.51.101.255"), // adjacent, fine
          row("198.51.102.0", "198.51.102.255"),
        ),
        stats,
      ),
    );
    expect(rows.map((r) => r.start)).toEqual(["198.51.100.0", "198.51.101.0", "198.51.102.0"]);
    expect(stats.overlapping).toBe(3);
    expect(stats.invalid).toBe(3);
  });

  it("tolerates a header or a stray line but not a file of garbage", async () => {
    const ok = newParseStats();
    const rows = await collect(
      parseRows("country", lines("ip_start,ip_end,country", row("198.51.100.0", "198.51.100.255")), ok),
    );
    expect(rows).toHaveLength(1);
    expect(ok.invalid).toBe(1);

    const many = Array.from({ length: 300 }, (_, i) => `garbage line ${i}`);
    await fails(
      collect(parseRows("country", lines(...many, row("198.51.100.0", "198.51.100.255")), newParseStats())),
      "tooManyInvalid",
    );
    await fails(collect(parseRows("country", lines("only", "garbage"), newParseStats())), "empty");
    await fails(collect(parseRows("country", lines(), newParseStats())), "empty");
  });

  it("stops early on endless garbage", async () => {
    const seen = { n: 0 };
    async function* endless() {
      for (;;) {
        seen.n++;
        yield "this is not a range";
      }
    }
    await fails(collect(parseRows("asn", endless(), newParseStats())), "tooManyInvalid");
    expect(seen.n).toBeLessThan(GEOIP_LIMITS.abortInvalidLines + 5);
  });

  it("recognises the other kind of file", async () => {
    const asn = ["198.51.100.0,198.51.100.255,64500,Example", "203.0.113.0,203.0.113.255,64501,Other"];
    await fails(collect(parseRows("country", lines(...asn), newParseStats())), "wrongKind");
    const country = [row("198.51.100.0", "198.51.100.255"), row("203.0.113.0", "203.0.113.255")];
    await fails(collect(parseRows("asn", lines(...country), newParseStats())), "wrongKind");
  });

  it("enforces the row limit", async () => {
    const many = Array.from({ length: 6 }, (_, i) => row(`198.51.100.${i * 2}`, `198.51.100.${i * 2 + 1}`));
    await fails(
      collect(parseRows("country", lines(...many), newParseStats(), { maxRows: 5 })),
      "tooManyRows",
    );
  });
});

describe("lines of a byte stream", () => {
  it("splits lines across chunk borders, with LF, CRLF and no final newline", async () => {
    const data = Buffer.from("one\r\ntwo\nthr");
    const out = await collect(splitLines(chunked(Buffer.concat([data, Buffer.from("ee")]), 3)));
    expect(out).toEqual(["one", "two", "three"]);
  });

  it("keeps multi-byte characters intact across chunks", async () => {
    const text = "Müller GmbH,日本語\n";
    const out = await collect(splitLines(chunked(Buffer.from(text), 2)));
    expect(out).toEqual([text.trim()]);
  });

  it("ends the read at a line that is far too long, with or without a newline", async () => {
    await fails(collect(splitLines(chunked(Buffer.from(`${"x".repeat(5000)}\n`), 100))), "lineTooLong");
    await fails(collect(splitLines(chunked(Buffer.from("x".repeat(5000)), 100))), "lineTooLong");
    await fails(
      collect(splitLines(chunked(Buffer.from(`ok\n${"y".repeat(2000)}\nok\n`), 10), 1000)),
      "lineTooLong",
    );
  });

  it("never buffers a huge line: it stops after about one limit's worth", async () => {
    let produced = 0;
    async function* endless(): AsyncGenerator<Uint8Array> {
      for (;;) {
        produced += 1024;
        yield Buffer.alloc(1024, 0x78);
      }
    }
    await fails(collect(splitLines(endless())), "lineTooLong");
    expect(produced).toBeLessThanOrEqual(4 * 1024);
  });
});

describe("gzip with limits", () => {
  const text = `${row()}\n`.repeat(1);
  function row() {
    return "198.51.100.0,198.51.100.255,DE";
  }

  it("inflates a normal file and records sizes and the SHA-256 of the compressed bytes", async () => {
    const compressed = gz("hello world\n".repeat(100));
    const stats = newParseStats();
    const out = Buffer.concat(await collect(inflateLimited(chunked(compressed, 7), stats)));
    expect(out.toString()).toBe("hello world\n".repeat(100));
    expect(stats.compressedBytes).toBe(compressed.length);
    expect(stats.decompressedBytes).toBe(out.length);
    expect(stats.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("stops a compression bomb at the inflated cap, long before it has been fully inflated", async () => {
    // 200 MiB of zeros compress to about 200 KiB.
    const bomb = gzipSync(Buffer.alloc(200 * 1024 * 1024), { level: 9 });
    expect(bomb.length).toBeLessThan(1024 * 1024);
    const stats = newParseStats();
    await fails(
      collect(inflateLimited(chunked(bomb, 64 * 1024), stats, { maxDecompressedBytes: 5 * 1024 * 1024 })),
      "decompressedTooLarge",
    );
    expect(stats.decompressedBytes).toBeLessThan(5 * 1024 * 1024 + 1024 * 1024);
  });

  it("stops an upload that is larger than the compressed cap", async () => {
    const big = gzipSync(
      Buffer.from(`${Array.from({ length: 5000 }, (_, i) => `line ${i} ${Math.random()}`).join("\n")}\n`),
    );
    await fails(
      collect(inflateLimited(chunked(big, 500), newParseStats(), { maxCompressedBytes: 1000 })),
      "tooLarge",
    );
  });

  it("refuses data that is not gzip, an empty body and damaged gzip", async () => {
    await fails(
      collect(inflateLimited(chunked(Buffer.from("plain text, not gzip")), newParseStats())),
      "notGzip",
    );
    await fails(collect(inflateLimited(chunked(Buffer.alloc(0)), newParseStats())), "notGzip");
    const damaged = Buffer.from(gz(text.repeat(50)));
    damaged[damaged.length - 6] = (damaged[damaged.length - 6] as number) ^ 0xff;
    await fails(collect(inflateLimited(chunked(damaged), newParseStats())), "corrupt");
    const truncated = gz(text.repeat(50)).subarray(0, 20);
    await fails(collect(inflateLimited(chunked(truncated), newParseStats())), "corrupt");
  });

  it("reads a whole dataset from a gzip stream", async () => {
    const csv = ["198.51.100.0,198.51.100.255,DE", "203.0.113.0,203.0.113.255,FR", ""].join("\n");
    const stats = newParseStats();
    const rows = await collect(readDataset("country", chunked(gz(csv), 11), stats));
    expect(rows).toHaveLength(2);
    expect(stats.rows).toBe(2);
    expect(stats.sha256).not.toBeNull();
  });

  it("fails a dataset whose gzip hides a huge line", async () => {
    const csv = `198.51.100.0,198.51.100.255,DE\n${"A".repeat(2_000_000)}\n`;
    await fails(collect(readDataset("country", chunked(gz(csv)), newParseStats())), "lineTooLong");
  });

  it("closes the source when the read stops early", async () => {
    let closed = false;
    async function* source(): AsyncGenerator<Uint8Array> {
      try {
        for (let i = 0; i < 100_000; i++) yield gz("x");
      } finally {
        closed = true;
      }
    }
    await fails(collect(inflateLimited(source(), newParseStats(), { maxCompressedBytes: 200 })), "tooLarge");
    await new Promise((r) => setTimeout(r, 20));
    expect(closed).toBe(true);
  });
});
