/**
 * Local GeoIP data for the attack overview (ADR 0016): reading the DB-IP "IP to Country Lite" and
 * "IP to ASN Lite" CSV files (CC BY 4.0, https://db-ip.com), safely.
 *
 * The files come from an admin (manual import) or from DB-IP over HTTPS (opt-in download). Either
 * way they are untrusted input: a damaged file, a wrong file, a compression bomb or a deliberately
 * hostile one must not exhaust memory, disk or time, and must never replace a dataset that works.
 * Everything here is a stream: the compressed size is capped while it arrives, the decompressed
 * size while it is inflated, every line is capped before it is looked at, and every row is
 * validated on its own. Rows are handed on one at a time; nothing holds the whole file.
 *
 * Format (RFC 4180, UTF-8, no header, sorted, non-overlapping):
 *   country: `first_ip,last_ip,CC`            e.g. `198.51.100.0,198.51.100.255,DE`
 *   asn:     `first_ip,last_ip,asn,"org"`     e.g. `203.0.113.0,203.0.113.255,64500,Example Networks`
 * IPv4 and IPv6 ranges are in the same file. The data is approximate: it says where an address
 * range is registered or used, not where an attacker sits (see docs/attacks.md).
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { createGunzip } from "node:zlib";
import { classifyAddress } from "./ai-endpoint.ts";

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

export const GEOIP_KINDS = ["country", "asn"] as const;
export type GeoipKind = (typeof GEOIP_KINDS)[number];

export const GEOIP_LIMITS = {
  /** The real files are 5 to 10 MiB compressed. */
  maxCompressedBytes: 64 * 1024 * 1024,
  /** The real files are 30 to 60 MiB inflated; a bomb stops here. */
  maxDecompressedBytes: 256 * 1024 * 1024,
  /** A real line is below 200 bytes. */
  maxLineBytes: 1024,
  /** The real files have 0.5 to 1 million ranges. */
  maxRows: 3_000_000,
  /** Lines that may be invalid (a header, a stray empty line) before the file counts as broken: the larger of this and 0.1 %. */
  maxInvalidLines: 10,
  maxInvalidShare: 0.001,
  /** Whatever the share, this many invalid lines end the read early. */
  abortInvalidLines: 1000,
  maxOrgChars: 200,
} as const;

export type GeoipErrorCode =
  | "tooLarge"
  | "decompressedTooLarge"
  | "notGzip"
  | "corrupt"
  | "lineTooLong"
  | "empty"
  | "tooManyRows"
  | "tooManyInvalid"
  | "wrongKind"
  | "timeout"
  | "storage";

/** Fixed English texts, translated in the web app by code. Nothing from the file is ever put into one. */
export const GEOIP_ERROR_TEXT: Record<GeoipErrorCode, string> = {
  tooLarge: "The file is larger than the limit",
  decompressedTooLarge: "The file inflates to more than the limit",
  notGzip: "The file is not a gzip file",
  corrupt: "The gzip data is damaged",
  lineTooLong: "The file has a line that is far too long for this format",
  empty: "The file contains no usable ranges",
  tooManyRows: "The file has more ranges than the limit",
  tooManyInvalid: "Too many lines in the file are not valid ranges",
  wrongKind: "This looks like the other kind of file (country versus ASN)",
  timeout: "The transfer took too long",
  storage: "The ranges could not be stored",
};

export class GeoipError extends Error {
  readonly code: GeoipErrorCode;
  constructor(code: GeoipErrorCode) {
    super(GEOIP_ERROR_TEXT[code]);
    this.name = "GeoipError";
    this.code = code;
  }
}

/* -------------------------------------------------------------------------- */
/* Where the data comes from                                                   */
/* -------------------------------------------------------------------------- */

export const DBIP_HOST = "download.db-ip.com";
export const DBIP_ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0";
export const DBIP_SITE = "https://db-ip.com";
export const DBIP_LICENSE = "https://creativecommons.org/licenses/by/4.0/";
/** Natural Earth is public domain; named anyway. */
export const MAP_ATTRIBUTION = "Map: Natural Earth (public domain)";

const MONTH = /^(\d{4})-(0[1-9]|1[0-2])$/;
export const isDbipMonth = (value: string): boolean => {
  const m = MONTH.exec(value);
  return m !== null && Number(m[1]) >= 2020 && Number(m[1]) <= 2100;
};

/** The one URL a file is downloaded from; `month` is `YYYY-MM`. */
export function dbipUrl(kind: GeoipKind, month: string): string {
  if (!isDbipMonth(month)) throw new Error("Not a month");
  return `https://${DBIP_HOST}/free/dbip-${kind}-lite-${month}.csv.gz`;
}
/** The same URL as it is shown to people, with the month as a placeholder. */
export const dbipUrlPattern = (kind: GeoipKind) =>
  `https://${DBIP_HOST}/free/dbip-${kind}-lite-YYYY-MM.csv.gz`;

/** `YYYY-MM` of a UTC date. */
export const monthOf = (date: Date): string =>
  `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
/** The month before `YYYY-MM`. */
export function previousMonth(month: string): string {
  const m = MONTH.exec(month);
  if (!m) throw new Error("Not a month");
  const date = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, 1));
  date.setUTCMonth(date.getUTCMonth() - 1);
  return monthOf(date);
}

/** `dbip-country-lite-2026-10.csv.gz` gives the kind and the month; any other name gives null. */
export function parseDatasetFilename(name: string): { kind: GeoipKind; month: string } | null {
  const m = /^dbip-(country|asn)-lite-(\d{4}-\d{2})\.csv\.gz$/i.exec(name.trim());
  if (!m || !isDbipMonth(m[2] as string)) return null;
  return { kind: (m[1] as string).toLowerCase() as GeoipKind, month: m[2] as string };
}

/* -------------------------------------------------------------------------- */
/* IP addresses as numbers                                                     */
/* -------------------------------------------------------------------------- */

export interface ParsedIp {
  family: 4 | 6;
  value: bigint;
}

/**
 * Parses an IPv4 or IPv6 address. An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) becomes the IPv4
 * address, so the same machine is never two keys. Null if the text is not an address.
 */
export function parseIp(text: string): ParsedIp | null {
  const kind = isIP(text);
  if (kind === 4) {
    const parts = text.split(".").map(Number);
    return { family: 4, value: parts.reduce((n, p) => (n << 8n) | BigInt(p), 0n) };
  }
  if (kind !== 6) return null;
  let head = text;
  let tailV4: bigint | null = null;
  const dot = text.lastIndexOf(".");
  if (dot >= 0) {
    const colon = text.lastIndexOf(":");
    const v4 = parseIp(text.slice(colon + 1));
    if (v4?.family !== 4) return null;
    tailV4 = v4.value;
    head = `${text.slice(0, colon + 1)}0:0`;
  }
  const zone = head.indexOf("%");
  if (zone >= 0) head = head.slice(0, zone);
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string) => (part === "" ? [] : part.split(":"));
  const left = groups(halves[0] as string);
  const right = halves.length === 2 ? groups(halves[1] as string) : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...right];
  if (all.length !== 8) return null;
  let value = 0n;
  for (const g of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(`0x${g}`);
  }
  if (tailV4 !== null) value = (value & ~0xffffffffn) | tailV4;
  if (value >> 32n === 0xffffn) return { family: 4, value: value & 0xffffffffn };
  return { family: 6, value };
}

/** A key that orders every IPv4 address before every IPv6 address. */
export const ipKey = (ip: ParsedIp): bigint => (ip.family === 6 ? 1n << 128n : 0n) + ip.value;

/** Canonical text: dotted quad, or eight hex groups (PostgreSQL's `inet` accepts both). */
export function formatIp(ip: ParsedIp): string {
  if (ip.family === 4) {
    return [24n, 16n, 8n, 0n].map((shift) => Number((ip.value >> shift) & 0xffn)).join(".");
  }
  const groups: string[] = [];
  for (let i = 7n; i >= 0n; i--) groups.push(((ip.value >> (i * 16n)) & 0xffffn).toString(16));
  return groups.join(":");
}

/** The canonical text of an address (IPv4-mapped IPv6 as IPv4), or null if it is none. */
export function canonicalIp(text: string): string | null {
  const ip = parseIp(text.trim());
  return ip ? formatIp(ip) : null;
}

/**
 * "internal": private, loopback, link-local, multicast and other reserved addresses. They are
 * labelled as such, never looked up in the GeoIP tables and never sent to an OSINT provider.
 * "public": everything else that is an address. "invalid": not an address.
 */
export function ipScope(text: string): "public" | "internal" | "invalid" {
  const ip = parseIp(text);
  if (!ip) return "invalid";
  return classifyAddress(formatIp(ip)) === "public" ? "public" : "internal";
}

/* -------------------------------------------------------------------------- */
/* Lines and rows                                                              */
/* -------------------------------------------------------------------------- */

export interface CountryRow {
  start: string;
  end: string;
  country: string;
}
export interface AsnRow {
  start: string;
  end: string;
  asn: number;
  org: string;
}
export type GeoipRow = CountryRow | AsnRow;

/** Control, line-separator and bidirectional-override characters have no place in an organisation name. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
export function cleanText(value: string, max: number): string {
  return value.replace(UNSAFE_TEXT, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

/**
 * Splits one line of RFC 4180 CSV. Null if a quote is not closed or a quote sits inside an
 * unquoted field. A quoted field cannot contain a line break (a line is a record in these files).
 */
export function splitCsvLine(line: string): string[] | null {
  const fields: string[] = [];
  let i = 0;
  while (i <= line.length) {
    if (line[i] === '"') {
      let value = "";
      i++;
      for (;;) {
        if (i >= line.length) return null;
        if (line[i] === '"') {
          if (line[i + 1] === '"') {
            value += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        value += line[i];
        i++;
      }
      fields.push(value);
      if (i === line.length) return fields;
      if (line[i] !== ",") return null;
      i++;
    } else {
      const next = line.indexOf(",", i);
      const end = next === -1 ? line.length : next;
      const value = line.slice(i, end);
      if (value.includes('"')) return null;
      fields.push(value);
      if (next === -1) return fields;
      i = next + 1;
    }
  }
  return fields;
}

export type LineProblem = "shape" | "address" | "order" | "code" | "asn" | "kind";

/** One line of a country file or an ASN file as a row, or why it is not one. Pure. */
export function parseLine(
  kind: GeoipKind,
  line: string,
): { ok: true; row: GeoipRow; startKey: bigint; endKey: bigint } | { ok: false; problem: LineProblem } {
  const fields = splitCsvLine(line);
  const want = kind === "country" ? 3 : 4;
  if (!fields) return { ok: false, problem: "shape" };
  if (fields.length !== want) {
    // The other kind of file has the other number of fields.
    return { ok: false, problem: fields.length === (kind === "country" ? 4 : 3) ? "kind" : "shape" };
  }
  const start = parseIp((fields[0] as string).trim());
  const end = parseIp((fields[1] as string).trim());
  if (!start || !end || start.family !== end.family) return { ok: false, problem: "address" };
  if (start.value > end.value) return { ok: false, problem: "order" };
  const startKey = ipKey(start);
  const endKey = ipKey(end);
  const common = { start: formatIp(start), end: formatIp(end) };
  if (kind === "country") {
    const country = (fields[2] as string).trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(country)) return { ok: false, problem: "code" };
    return { ok: true, row: { ...common, country }, startKey, endKey };
  }
  const asnText = (fields[2] as string).trim().replace(/^AS/i, "");
  if (!/^\d{1,10}$/.test(asnText) || Number(asnText) > 4_294_967_295) return { ok: false, problem: "asn" };
  const org = cleanText(fields[3] as string, GEOIP_LIMITS.maxOrgChars);
  return { ok: true, row: { ...common, asn: Number(asnText), org }, startKey, endKey };
}

export interface ParseStats {
  /** Non-empty lines read. */
  lines: number;
  rows: number;
  invalid: number;
  overlapping: number;
  /** Lines with the field count of the other kind of file. */
  otherKind: number;
  /** Bytes before and after inflating, and the SHA-256 of the compressed file (hex), set by `readDataset`. */
  compressedBytes: number;
  decompressedBytes: number;
  sha256: string | null;
}
export const newParseStats = (): ParseStats => ({
  lines: 0,
  rows: 0,
  invalid: 0,
  overlapping: 0,
  otherKind: 0,
  compressedBytes: 0,
  decompressedBytes: 0,
  sha256: null,
});

/**
 * Cuts a stream of bytes into lines. A line longer than `maxLineBytes` ends the read: no real
 * file has one, and waiting for its end would let a hostile file grow a buffer without bound.
 */
export async function* splitLines(
  chunks: AsyncIterable<Uint8Array>,
  maxLineBytes: number = GEOIP_LIMITS.maxLineBytes,
): AsyncGenerator<string> {
  let pending: Buffer = Buffer.alloc(0);
  for await (const chunk of chunks) {
    pending = pending.length === 0 ? Buffer.from(chunk) : Buffer.concat([pending, chunk]);
    let from = 0;
    for (;;) {
      const newline = pending.indexOf(0x0a, from);
      if (newline === -1) break;
      if (newline - from > maxLineBytes) throw new GeoipError("lineTooLong");
      yield pending.toString("utf8", from, newline).replace(/\r$/, "");
      from = newline + 1;
    }
    pending = pending.subarray(from);
    if (pending.length > maxLineBytes) throw new GeoipError("lineTooLong");
  }
  if (pending.length > 0) yield pending.toString("utf8").replace(/\r$/, "");
}

/**
 * Validated rows from lines. Each line is checked on its own; a line that is not a valid range, or
 * that overlaps or precedes the one before (the files are sorted), is skipped and counted. The
 * read ends with an error when the file is empty, too large, mostly invalid, or the other kind.
 */
export async function* parseRows(
  kind: GeoipKind,
  lines: AsyncIterable<string>,
  stats: ParseStats,
  limits: { maxRows?: number } = {},
): AsyncGenerator<GeoipRow> {
  const maxRows = limits.maxRows ?? GEOIP_LIMITS.maxRows;
  let lastEnd = -1n;
  for await (const raw of lines) {
    const line = raw.trim();
    if (line === "") continue;
    stats.lines++;
    const parsed = parseLine(kind, line);
    if (!parsed.ok) {
      stats.invalid++;
      if (parsed.problem === "kind") stats.otherKind++;
      if (stats.invalid > GEOIP_LIMITS.abortInvalidLines) throw new GeoipError("tooManyInvalid");
      continue;
    }
    if (parsed.startKey <= lastEnd) {
      stats.invalid++;
      stats.overlapping++;
      if (stats.invalid > GEOIP_LIMITS.abortInvalidLines) throw new GeoipError("tooManyInvalid");
      continue;
    }
    lastEnd = parsed.endKey;
    stats.rows++;
    if (stats.rows > maxRows) throw new GeoipError("tooManyRows");
    yield parsed.row;
  }
  finishParse(stats);
}

/** Throws when what was read is not a dataset. */
export function finishParse(stats: ParseStats): void {
  if (stats.rows === 0) throw new GeoipError(stats.otherKind > 0 ? "wrongKind" : "empty");
  const allowed = Math.max(
    GEOIP_LIMITS.maxInvalidLines,
    Math.floor(stats.lines * GEOIP_LIMITS.maxInvalidShare),
  );
  if (stats.invalid > allowed)
    throw new GeoipError(stats.otherKind > stats.rows ? "wrongKind" : "tooManyInvalid");
}

/* -------------------------------------------------------------------------- */
/* Compression                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Inflates a gzip stream with both sizes capped: the compressed bytes as they arrive and the
 * inflated bytes as they come out (so a compression bomb stops at the cap, not at memory). The
 * source is read only as fast as the consumer takes data. Counts and the SHA-256 of the
 * compressed bytes are written to `stats`.
 */
export async function* inflateLimited(
  source: AsyncIterable<Uint8Array>,
  stats: ParseStats,
  limits: { maxCompressedBytes?: number; maxDecompressedBytes?: number } = {},
): AsyncGenerator<Buffer> {
  const maxCompressed = limits.maxCompressedBytes ?? GEOIP_LIMITS.maxCompressedBytes;
  const maxDecompressed = limits.maxDecompressedBytes ?? GEOIP_LIMITS.maxDecompressedBytes;
  const gunzip = createGunzip();
  // Errors reach the consumer through the iterator; this keeps a late one from being unhandled.
  gunzip.on("error", () => {});
  const hash = createHash("sha256");
  let stop = false;
  let first = true;
  /** Resolves when the stream can take more data, or is gone. */
  const drained = () =>
    new Promise<void>((resolve) => {
      const done = () => {
        gunzip.off("drain", done);
        gunzip.off("close", done);
        resolve();
      };
      gunzip.once("drain", done);
      gunzip.once("close", done);
    });
  const feed = (async () => {
    try {
      for await (const chunk of source) {
        if (stop) break;
        if (first) {
          first = false;
          if (chunk.length < 2 || chunk[0] !== 0x1f || chunk[1] !== 0x8b) throw new GeoipError("notGzip");
        }
        stats.compressedBytes += chunk.length;
        if (stats.compressedBytes > maxCompressed) throw new GeoipError("tooLarge");
        hash.update(chunk);
        if (!gunzip.write(chunk)) await drained();
      }
      if (first) throw new GeoipError("notGzip");
      gunzip.end();
    } catch (error) {
      gunzip.destroy(error as Error);
    }
  })();
  try {
    for await (const out of gunzip) {
      stats.decompressedBytes += out.length;
      if (stats.decompressedBytes > maxDecompressed) throw new GeoipError("decompressedTooLarge");
      yield out as Buffer;
    }
  } catch (error) {
    if (error instanceof GeoipError) throw error;
    // zlib's own errors (a bad header, a cut-off stream) are a damaged file; anything else is the
    // source's failure (a dropped connection, a timeout) and is passed on as it is.
    const code = (error as NodeJS.ErrnoException)?.code;
    if (typeof code === "string" && code.startsWith("Z_")) throw new GeoipError("corrupt");
    throw error;
  } finally {
    // The feeder ends at its next chunk; it is not awaited, because the source may be a stalled
    // connection that its owner closes after the error.
    stop = true;
    gunzip.destroy();
    void feed;
    stats.sha256 = hash.digest("hex");
  }
}

/** A gzip stream as validated rows: inflate with caps, cut into lines, parse. */
export function readDataset(
  kind: GeoipKind,
  source: AsyncIterable<Uint8Array>,
  stats: ParseStats = newParseStats(),
  limits: { maxCompressedBytes?: number; maxDecompressedBytes?: number; maxRows?: number } = {},
): AsyncGenerator<GeoipRow> {
  return parseRows(kind, splitLines(inflateLimited(source, stats, limits)), stats, limits);
}

/* -------------------------------------------------------------------------- */
/* Retention and settings                                                      */
/* -------------------------------------------------------------------------- */

export const RETENTION = { defaultDays: 90, minDays: 1, maxDays: 365 } as const;
export const isRetentionDays = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isInteger(value) &&
  value >= RETENTION.minDays &&
  value <= RETENTION.maxDays;

/** A GeoIP dataset is stale when it is older than this many months. */
export const GEOIP_STALE_MONTHS = 3;

/** Whole months from `YYYY-MM` to the month of `now`. */
export function monthsSince(month: string, now: Date): number {
  const m = MONTH.exec(month);
  if (!m) return Number.POSITIVE_INFINITY;
  return (now.getUTCFullYear() - Number(m[1])) * 12 + (now.getUTCMonth() + 1 - Number(m[2]));
}
