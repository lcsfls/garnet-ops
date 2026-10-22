/**
 * Servers (ADR 0011): validation of what an admin types, the CSV import, the host key scan
 * output, the inventory report a server prints, and the SBOM built from it.
 *
 * Everything a server prints is hostile input. The parsers accept only what they know, check
 * every field against a strict pattern, cap every size and drop the rest; they never throw
 * on a bad line, only on a report that is unusable as a whole. Nothing here executes,
 * evaluates or interpolates server output.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { isForbiddenAddress } from "./notifications.ts";
import { fingerprint } from "./ssh.ts";

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

/** The inventory output is cut off here; a larger report is refused. */
export const MAX_REPORT_BYTES = 16 * 1024 * 1024;
/** The inventory ends after this long. */
export const INVENTORY_TIMEOUT_SECONDS = 60;
/** Packages kept per server; a larger inventory is refused, never stored unbounded. */
export const MAX_PACKAGES_PER_HOST = 20_000;
/** Servers per organisation. */
export const MAX_HOSTS = 2000;
/** Rows of one CSV import. */
export const MAX_IMPORT_ROWS = 500;
export const DEFAULT_SSH_PORT = 22;
/** The account the host setup script creates; the default for new servers. */
export const DEFAULT_SSH_USER = "garnetops";

/* -------------------------------------------------------------------------- */
/* What an admin types                                                         */
/* -------------------------------------------------------------------------- */

export type AddressProblem = "empty" | "tooLong" | "characters" | "option" | "reserved" | "numeric";
export type AddressCheck =
  | { ok: true; address: string; kind: "ipv4" | "ipv6" | "hostname" }
  | { ok: false; problem: AddressProblem };

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Checks and normalises the address of a server: a host name or an IP address, nothing else.
 *
 * Refused: anything that could be read as an ssh option (leading "-"), whitespace, user@,
 * brackets, zone ids, ports, paths; loopback, link-local (cloud metadata), unspecified and
 * multicast addresses; and "numeric" names such as `127.1` or `0x7f.1`, which resolvers turn
 * into an IPv4 address the checks above never saw.
 */
export function checkHostAddress(value: string): AddressCheck {
  const address = value.trim();
  if (address.length === 0) return { ok: false, problem: "empty" };
  if (address.length > 253) return { ok: false, problem: "tooLong" };
  if (address.startsWith("-")) return { ok: false, problem: "option" };
  if (!/^[A-Za-z0-9.:-]+$/.test(address)) return { ok: false, problem: "characters" };
  const kind = isIP(address);
  if (kind === 4 || kind === 6) {
    if (isForbiddenAddress(address)) return { ok: false, problem: "reserved" };
    return {
      ok: true,
      address: kind === 6 ? address.toLowerCase() : address,
      kind: kind === 6 ? "ipv6" : "ipv4",
    };
  }
  if (address.includes(":")) return { ok: false, problem: "characters" };
  const name = address.toLowerCase();
  const labels = name.split(".");
  if (!labels.every((l) => HOST_LABEL.test(l))) return { ok: false, problem: "characters" };
  const last = labels[labels.length - 1] as string;
  if (/^[0-9]+$/.test(last) || /^0x/.test(last)) return { ok: false, problem: "numeric" };
  if (name === "localhost" || name.endsWith(".localhost")) return { ok: false, problem: "reserved" };
  return { ok: true, address: name, kind: "hostname" };
}

/** A TCP port from 1 to 65535, or null. Accepts a number or a string of digits. */
export function parsePort(value: unknown): number | null {
  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^\d{1,5}$/.test(value.trim())
        ? Number(value)
        : Number.NaN;
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** A display name: printable text, 1 to 120 characters. */
export function checkHostName(value: string): string | null {
  const name = value.trim();
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (name.length === 0 || name.length > 120 || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

/** The user name on the server: a portable POSIX user name. */
export const SSH_USER_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;

export type SourceProblem = "empty" | "tooMany" | "invalid" | "any";

/**
 * The addresses the access key may be used from (`from=` in authorized_keys): IP addresses or
 * CIDR ranges separated by commas or spaces. Required, because a key that works from
 * anywhere is the first thing an attacker with a copy of it would use. A range of "any" (/0)
 * is refused for the same reason. Host names and wildcards are not accepted: they would be
 * resolved on the server and are easy to get wrong.
 */
export function parseAllowedSource(
  value: string,
): { ok: true; value: string; entries: string[] } | { ok: false; problem: SourceProblem } {
  const parts = value
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return { ok: false, problem: "empty" };
  if (parts.length > 8) return { ok: false, problem: "tooMany" };
  const entries: string[] = [];
  for (const part of parts) {
    const [ip, prefix, extra] = part.split("/");
    if (extra !== undefined || !ip) return { ok: false, problem: "invalid" };
    const kind = isIP(ip);
    if (kind === 0 || ip.includes("%")) return { ok: false, problem: "invalid" };
    if (prefix !== undefined) {
      if (!/^\d{1,3}$/.test(prefix)) return { ok: false, problem: "invalid" };
      const bits = Number(prefix);
      if (bits > (kind === 4 ? 32 : 128)) return { ok: false, problem: "invalid" };
      if (bits === 0) return { ok: false, problem: "any" };
    }
    entries.push(kind === 6 ? part.toLowerCase() : part);
  }
  return { ok: true, value: [...new Set(entries)].join(","), entries };
}

export interface HostInput {
  address: string;
  name: string;
  port: number;
  sshUser: string;
}

export type HostInputError = {
  field: "address" | "name" | "port" | "sshUser";
  /** A code the web app translates, e.g. `address_reserved`. */
  code: string;
};

/**
 * Validates and normalises what an admin typed (or a CSV row held) for one server. The name
 * defaults to the address, the port to 22 and the user to the account the setup script creates.
 */
export function validateHostInput(raw: {
  address: string;
  name?: string | null;
  port?: string | number | null;
  sshUser?: string | null;
}): { ok: true; value: HostInput } | { ok: false; errors: HostInputError[] } {
  const errors: HostInputError[] = [];
  const address = checkHostAddress(raw.address);
  if (!address.ok) errors.push({ field: "address", code: `address_${address.problem}` });

  const rawName = (raw.name ?? "").trim();
  const name = rawName === "" ? (address.ok ? address.address : "") : checkHostName(rawName);
  if (name === null || (rawName !== "" && name === "")) errors.push({ field: "name", code: "name_invalid" });

  const rawPort = typeof raw.port === "string" ? raw.port.trim() : raw.port;
  const port =
    rawPort === undefined || rawPort === null || rawPort === "" ? DEFAULT_SSH_PORT : parsePort(rawPort);
  if (port === null) errors.push({ field: "port", code: "port_range" });

  const sshUser = (raw.sshUser ?? "").trim() || DEFAULT_SSH_USER;
  if (!SSH_USER_PATTERN.test(sshUser)) errors.push({ field: "sshUser", code: "user_invalid" });

  if (errors.length > 0 || !address.ok || name === null || port === null) return { ok: false, errors };
  return { ok: true, value: { address: address.address, name, port, sshUser } };
}

/* -------------------------------------------------------------------------- */
/* CSV import                                                                  */
/* -------------------------------------------------------------------------- */

export interface CsvHostRow {
  /** 1-based line of the file, for messages. */
  line: number;
  address: string;
  name: string;
  port: string;
}

const MAX_CSV_BYTES = 256 * 1024;
const MAX_CSV_CELL = 1000;

/** Splits CSV text into rows of cells (RFC 4180 quoting). Stops early when a limit is hit. */
function csvRecords(
  text: string,
  delimiter: string,
  maxRecords: number,
): { line: number; cells: string[] }[] {
  const records: { line: number; cells: string[] }[] = [];
  let cells: string[] = [];
  let cell = "";
  let quoted = false;
  let line = 1;
  let startLine = 1;
  let wasQuoted = false;
  const endCell = () => {
    cells.push(cell.slice(0, MAX_CSV_CELL));
    cell = "";
    wasQuoted = false;
  };
  const endRecord = () => {
    endCell();
    if (cells.some((c) => c.trim() !== "")) records.push({ line: startLine, cells });
    cells = [];
  };
  for (let i = 0; i < text.length && records.length <= maxRecords; i++) {
    const ch = text[i] as string;
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i++;
        } else quoted = false;
      } else {
        if (ch === "\n") line++;
        cell += ch;
      }
    } else if (ch === '"' && cell === "" && !wasQuoted) {
      quoted = true;
      wasQuoted = true;
    } else if (ch === delimiter) endCell();
    else if (ch === "\n") {
      endRecord();
      line++;
      startLine = line;
    } else if (ch !== "\r") cell += ch;
  }
  if (cell !== "" || cells.length > 0) endRecord();
  return records;
}

export type CsvResult =
  | { ok: true; rows: CsvHostRow[] }
  | { ok: false; problem: "tooLarge" | "tooManyRows" | "empty" };

/**
 * Reads the CSV of an import: `address,name,port`. A header row is optional (columns are then
 * found by their names `address` or `host`, `name`, `port`, in any order). Comma and semicolon
 * both work, because spreadsheet programs in many countries write semicolons. Extra columns
 * and empty lines are ignored.
 */
export function parseHostCsv(text: string, maxRows = MAX_IMPORT_ROWS): CsvResult {
  if (text.length > MAX_CSV_BYTES) return { ok: false, problem: "tooLarge" };
  const body = text.replace(/^﻿/, "");
  const firstLine = body.split("\n", 1)[0] ?? "";
  const delimiter = firstLine.includes(";") && !firstLine.includes(",") ? ";" : ",";
  const records = csvRecords(body, delimiter, maxRows + 1);
  if (records.length === 0) return { ok: false, problem: "empty" };

  const header = records[0]?.cells.map((c) => c.trim().toLowerCase()) ?? [];
  const hasHeader = header.some((c) => ["address", "host", "hostname"].includes(c));
  const column = (names: string[], fallback: number) => {
    if (!hasHeader) return fallback;
    const at = header.findIndex((c) => names.includes(c));
    return at;
  };
  const addressAt = column(["address", "host", "hostname"], 0);
  const nameAt = column(["name", "display name", "label"], 1);
  const portAt = column(["port"], 2);
  const data = hasHeader ? records.slice(1) : records;
  if (data.length === 0) return { ok: false, problem: "empty" };
  if (data.length > maxRows) return { ok: false, problem: "tooManyRows" };
  return {
    ok: true,
    rows: data.map((r) => ({
      line: r.line,
      address: (r.cells[addressAt] ?? "").trim(),
      name: nameAt >= 0 ? (r.cells[nameAt] ?? "").trim() : "",
      port: portAt >= 0 ? (r.cells[portAt] ?? "").trim() : "",
    })),
  };
}

/* -------------------------------------------------------------------------- */
/* SSH host keys                                                               */
/* -------------------------------------------------------------------------- */

/** Name under which the pinned key is stored in the temporary known_hosts file (HostKeyAlias). */
export const HOST_KEY_ALIAS = "garnetops-host";

export const HOST_KEY_TYPES = [
  "ssh-ed25519",
  "ecdsa-sha2-nistp521",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp256",
  "ssh-rsa",
] as const;
export type HostKeyType = (typeof HOST_KEY_TYPES)[number];

export interface ScannedHostKey {
  type: HostKeyType;
  /** Base64 key blob, as in known_hosts. */
  key: string;
  fingerprint: string;
}

/** Bit length of the modulus of an ssh-rsa key blob, or 0 if the blob is malformed. */
function rsaBits(blob: Buffer): number {
  let offset = 0;
  const next = (): Buffer | null => {
    if (offset + 4 > blob.length) return null;
    const length = blob.readUInt32BE(offset);
    if (length > blob.length - offset - 4) return null;
    const part = blob.subarray(offset + 4, offset + 4 + length);
    offset += 4 + length;
    return part;
  };
  next(); // key type
  next(); // exponent
  const modulus = next();
  if (!modulus || modulus.length === 0) return 0;
  const start = modulus[0] === 0 ? 1 : 0;
  const first = modulus[start];
  if (first === undefined) return 0;
  return (modulus.length - start) * 8 - Math.clz32(first) + 24;
}

/**
 * Reads the output of `ssh-keyscan`: one `host type key` line per key. Only key types we
 * can pin are kept, the blob must name the type it is filed under, and RSA keys under 2048
 * bits are dropped. The keys come back best first (Ed25519, then ECDSA, then RSA).
 */
export function parseKeyscan(output: string): { keys: ScannedHostKey[]; weak: boolean } {
  let weak = false;
  const found = new Map<HostKeyType, ScannedHostKey>();
  for (const line of output
    .slice(0, 64 * 1024)
    .split("\n")
    .slice(0, 50)) {
    const m =
      /^\S{1,300} (ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) ([A-Za-z0-9+/]{16,8000}={0,2})\s*$/.exec(
        line,
      );
    if (!m) continue;
    const type = m[1] as HostKeyType;
    const blob = Buffer.from(m[2] as string, "base64");
    const nameLength = blob.length >= 4 ? blob.readUInt32BE(0) : 0;
    if (blob.subarray(4, 4 + nameLength).toString("latin1") !== type) continue;
    if (type === "ssh-rsa" && rsaBits(blob) < 2048) {
      weak = true;
      continue;
    }
    if (!found.has(type))
      found.set(type, { type, key: m[2] as string, fingerprint: fingerprint(m[2] as string) });
  }
  return {
    keys: HOST_KEY_TYPES.flatMap((type) => {
      const key = found.get(type);
      return key ? [key] : [];
    }),
    weak,
  };
}

/** The best key of a scan, or why there is none. */
export function pickHostKey(output: string): { key: ScannedHostKey } | { key: null; weak: boolean } {
  const { keys, weak } = parseKeyscan(output);
  const key = keys[0];
  return key ? { key } : { key: null, weak };
}

/** The known_hosts line that pins exactly one key. */
export function knownHostsLine(type: string, key: string): string {
  return `${HOST_KEY_ALIAS} ${type} ${key}\n`;
}

/* -------------------------------------------------------------------------- */
/* The inventory report                                                        */
/* -------------------------------------------------------------------------- */

/** First line of a report; a different line means the wrapper on the server is not ours. */
export const REPORT_HEADER = "GARNETOPS-INVENTORY 1";
const SECTIONS = [
  "os-release",
  "kernel",
  "machine",
  "dpkg",
  "rpm",
  "apk",
  "apk-v",
  "updates-apt",
  "updates-dnf",
  "updates-apk",
] as const;

export type PackageType = "deb" | "rpm" | "apk";

export interface HostPackageInput {
  type: PackageType;
  name: string;
  /** deb and apk: the package version; rpm: `[epoch:]version-release`. */
  version: string;
  arch: string | null;
  /** Source package (deb), source RPM (rpm) or origin (apk), when known. */
  origin: string | null;
  /** deb: version of the source package when it differs. */
  originVersion: string | null;
  /** rpm only. */
  epoch: number | null;
  /** The version an update would install; null if the package is up to date. */
  upgradableTo: string | null;
  /** True if the update comes from a security repository (apt only). */
  securityUpdate: boolean;
}

export interface OsInfo {
  id: string | null;
  idLike: string[];
  versionId: string | null;
  codename: string | null;
  name: string | null;
  prettyName: string | null;
}

export interface InventoryReport {
  os: OsInfo;
  kernel: string | null;
  arch: string | null;
  packages: HostPackageInput[];
  /** Updates that match an installed package. */
  pendingUpdates: number;
  /** Lines that were dropped because they did not look like what they should be. */
  skipped: number;
}

export type InventoryParseCode = "empty" | "format" | "truncated" | "tooManyPackages";
export class InventoryParseError extends Error {
  readonly code: InventoryParseCode;
  constructor(code: InventoryParseCode) {
    super(`Inventory report is not usable: ${code}`);
    this.code = code;
  }
}

const RE = {
  debName: /^[a-z0-9][a-z0-9+.-]{0,127}$/,
  debVersion: /^[A-Za-z0-9.+~:-]{1,128}$/,
  arch: /^[A-Za-z0-9_-]{1,32}$/,
  rpmName: /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/,
  rpmPart: /^[A-Za-z0-9._+~^]{1,128}$/,
  srcRpm: /^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,250}\.rpm$/,
  apkName: /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/,
  apkVersion: /^[0-9][A-Za-z0-9._+~-]{0,100}$/,
  id: /^[a-z0-9][a-z0-9._-]{0,63}$/,
  versionId: /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/,
  kernel: /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}$/,
};

// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

function printable(value: string, max: number): string | null {
  const text = value.replace(CONTROL, "").trim().slice(0, max);
  return text === "" ? null : text;
}

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) return v.slice(1, -1);
  return v;
}

/** The fields of /etc/os-release that matter; every one is validated, none is trusted. */
function parseOsRelease(lines: string[]): OsInfo {
  const values = new Map<string, string>();
  for (const line of lines.slice(0, 100)) {
    const m = /^([A-Z_]{1,40})=(.{0,400})$/.exec(line);
    if (m && !values.has(m[1] as string)) values.set(m[1] as string, unquote(m[2] as string));
  }
  const id = (values.get("ID") ?? "").toLowerCase();
  const like = (values.get("ID_LIKE") ?? "").toLowerCase().split(/\s+/);
  const versionId = values.get("VERSION_ID") ?? "";
  const codename = (values.get("VERSION_CODENAME") ?? "").toLowerCase();
  return {
    id: RE.id.test(id) ? id : null,
    idLike: like.filter((l) => RE.id.test(l)).slice(0, 5),
    versionId: RE.versionId.test(versionId) ? versionId : null,
    codename: RE.id.test(codename) ? codename : null,
    name: printable(values.get("NAME") ?? "", 100),
    prettyName: printable(values.get("PRETTY_NAME") ?? "", 150),
  };
}

function cells(line: string, count: number): string[] | null {
  const parts = line.split("\t");
  if (parts.length < count || parts.length > count + 2) return null;
  return parts.map((p) => p.trim());
}

function parseDpkg(lines: string[], out: HostPackageInput[]): number {
  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === "") continue;
    const c = cells(line, 6);
    if (!c) {
      skipped++;
      continue;
    }
    const [name, version, arch, status, source, sourceVersion] = c as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    // `ii` installed, `hi` installed and on hold; `rc` (configuration left behind) is not installed.
    if (status[1] !== "i") continue;
    if (!RE.debName.test(name) || !RE.debVersion.test(version) || !RE.arch.test(arch)) {
      skipped++;
      continue;
    }
    out.push({
      type: "deb",
      name,
      version,
      arch,
      origin: RE.debName.test(source) && source !== name ? source : null,
      originVersion: RE.debVersion.test(sourceVersion) && sourceVersion !== version ? sourceVersion : null,
      epoch: null,
      upgradableTo: null,
      securityUpdate: false,
    });
  }
  return skipped;
}

function parseRpm(lines: string[], out: HostPackageInput[]): number {
  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === "") continue;
    const c = cells(line, 6);
    if (!c) {
      skipped++;
      continue;
    }
    const [name, epochText, version, release, arch, sourceRpm] = c as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    if (name === "gpg-pubkey") continue; // imported keys are listed as packages
    const epoch =
      epochText === "(none)" || epochText === "" ? 0 : /^\d{1,6}$/.test(epochText) ? Number(epochText) : -1;
    if (
      !RE.rpmName.test(name) ||
      epoch < 0 ||
      !RE.rpmPart.test(version) ||
      !RE.rpmPart.test(release) ||
      !RE.arch.test(arch)
    ) {
      skipped++;
      continue;
    }
    out.push({
      type: "rpm",
      name,
      version: `${epoch > 0 ? `${epoch}:` : ""}${version}-${release}`,
      arch,
      origin: RE.srcRpm.test(sourceRpm) ? sourceRpm : null,
      originVersion: null,
      epoch,
      upgradableTo: null,
      securityUpdate: false,
    });
  }
  return skipped;
}

/** Splits `name-1.2.3-r0` into name and version (apk's naming: the version starts at a digit after a dash). */
function splitApkNameVersion(text: string): { name: string; version: string } | null {
  const m = /^(.+?)-([0-9][A-Za-z0-9._+~]*-r[0-9]+)$/.exec(text);
  if (!m || !RE.apkName.test(m[1] as string) || !RE.apkVersion.test(m[2] as string)) return null;
  return { name: m[1] as string, version: m[2] as string };
}

/** `apk list -I`: `name-version arch {origin} (license) [installed]`. */
function parseApkList(lines: string[], out: HostPackageInput[]): number {
  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === "") continue;
    const m = /^(\S{1,300}) (\S{1,32})(?: \{(\S{1,128})\})?(?: .*)?$/.exec(line);
    const nv = m ? splitApkNameVersion(m[1] as string) : null;
    if (!m || !nv || !RE.arch.test(m[2] as string)) {
      skipped++;
      continue;
    }
    const origin = m[3] && RE.apkName.test(m[3]) && m[3] !== nv.name ? m[3] : null;
    out.push({
      type: "apk",
      ...nv,
      arch: m[2] as string,
      origin,
      originVersion: null,
      epoch: null,
      upgradableTo: null,
      securityUpdate: false,
    });
  }
  return skipped;
}

/** `apk info -v`: `name-version`, used only when `apk list` printed nothing. */
function parseApkInfo(lines: string[], out: HostPackageInput[], arch: string | null): number {
  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === "") continue;
    const nv = splitApkNameVersion(line.trim());
    if (!nv) {
      skipped++;
      continue;
    }
    out.push({
      type: "apk",
      ...nv,
      arch,
      origin: null,
      originVersion: null,
      epoch: null,
      upgradableTo: null,
      securityUpdate: false,
    });
  }
  return skipped;
}

interface Update {
  type: PackageType;
  name: string;
  arch: string | null;
  to: string;
  security: boolean;
}

/** `apt list --upgradable`: `name/suite[,suite] new-version arch [upgradable from: old]`. */
function parseAptUpdates(lines: string[], skipped: { n: number }): Update[] {
  const updates: Update[] = [];
  for (const line of lines) {
    if (
      line.trim() === "" ||
      line.startsWith("Listing") ||
      line.startsWith("WARNING") ||
      line.startsWith("N:")
    )
      continue;
    const m = /^([a-z0-9][a-z0-9+.-]{0,127})\/(\S{1,300}) (\S{1,128}) (\S{1,32})(?: \[.*\])?$/.exec(line);
    if (!m || !RE.debVersion.test(m[3] as string) || !RE.arch.test(m[4] as string)) {
      skipped.n++;
      continue;
    }
    updates.push({
      type: "deb",
      name: m[1] as string,
      arch: m[4] as string,
      to: m[3] as string,
      security: /security/i.test(m[2] as string),
    });
  }
  return updates;
}

/** `dnf check-update`: `name.arch  version-release  repository`, then possibly an "Obsoleting Packages" block. */
function parseDnfUpdates(lines: string[], skipped: { n: number }): Update[] {
  const updates: Update[] = [];
  for (const line of lines) {
    if (/^Obsoleting Packages/i.test(line)) break;
    if (line.trim() === "" || /^(Last metadata|Security:|Loaded plugins|Loading)/i.test(line)) continue;
    const m = /^(\S{1,200})\.([A-Za-z0-9_]{1,32}) +(\S{1,128}) +\S{1,128}\s*$/.exec(line);
    if (!m || !RE.rpmName.test(m[1] as string) || !/^[A-Za-z0-9._+~^:-]{1,128}$/.test(m[3] as string)) {
      skipped.n++;
      continue;
    }
    updates.push({
      type: "rpm",
      name: m[1] as string,
      arch: m[2] as string,
      to: m[3] as string,
      security: false,
    });
  }
  return updates;
}

/** `apk version -l '<'`: `name-installed  <  available`, after a header line. */
function parseApkUpdates(lines: string[], skipped: { n: number }): Update[] {
  const updates: Update[] = [];
  for (const line of lines) {
    if (line.trim() === "" || /^Installed:/.test(line)) continue;
    const m = /^(\S{1,300}) +< +(\S{1,100})\s*$/.exec(line);
    const nv = m ? splitApkNameVersion(m[1] as string) : null;
    if (!m || !nv || !RE.apkVersion.test(m[2] as string)) {
      skipped.n++;
      continue;
    }
    updates.push({ type: "apk", name: nv.name, arch: null, to: m[2] as string, security: false });
  }
  return updates;
}

/**
 * Parses the report printed by the wrapper (see host-setup.ts). The report is a header line,
 * sections introduced by `@@section <name>` lines and a final `@@end`; a report without its
 * end was cut off and is refused as a whole, so a truncated list never looks like a clean server.
 */
export function parseInventoryReport(text: string, maxPackages = MAX_PACKAGES_PER_HOST): InventoryReport {
  if (text.trim() === "") throw new InventoryParseError("empty");
  const lines = text.split("\n");
  if ((lines[0] ?? "").trim() !== REPORT_HEADER) throw new InventoryParseError("format");

  const sections = new Map<string, string[]>();
  let current: string[] | null = null;
  let ended = false;
  let skipped = 0;
  for (let i = 1; i < lines.length; i++) {
    const line = (lines[i] as string).replace(/\r$/, "");
    if (line === "@@end") {
      ended = true;
      break;
    }
    if (line.startsWith("@@section ")) {
      const name = line.slice("@@section ".length).trim();
      if ((SECTIONS as readonly string[]).includes(name) && !sections.has(name)) {
        current = [];
        sections.set(name, current);
      } else {
        current = null; // unknown or repeated section: ignored
        skipped++;
      }
      continue;
    }
    current?.push(line);
  }
  if (!ended) throw new InventoryParseError("truncated");

  const kernel = (sections.get("kernel")?.[0] ?? "").trim();
  const machine = (sections.get("machine")?.[0] ?? "").trim();
  const arch = RE.arch.test(machine) ? machine : null;

  const packages: HostPackageInput[] = [];
  skipped += parseDpkg(sections.get("dpkg") ?? [], packages);
  skipped += parseRpm(sections.get("rpm") ?? [], packages);
  const apkLines = sections.get("apk") ?? [];
  skipped += apkLines.some((l) => l.trim() !== "")
    ? parseApkList(apkLines, packages)
    : parseApkInfo(sections.get("apk-v") ?? [], packages, arch);

  // The same package can appear twice (multi-arch, repeated lines): keep one entry per type, name, version and arch.
  const unique = new Map<string, HostPackageInput>();
  for (const p of packages) {
    const key = `${p.type}\u0000${p.name}\u0000${p.version}\u0000${p.arch ?? ""}`;
    if (!unique.has(key)) unique.set(key, p);
  }
  if (unique.size > maxPackages) throw new InventoryParseError("tooManyPackages");
  const list = [...unique.values()].sort(
    (a, b) =>
      a.name.localeCompare(b.name) ||
      a.version.localeCompare(b.version) ||
      (a.arch ?? "").localeCompare(b.arch ?? ""),
  );

  const counter = { n: 0 };
  const updates = [
    ...parseAptUpdates(sections.get("updates-apt") ?? [], counter),
    ...parseDnfUpdates(sections.get("updates-dnf") ?? [], counter),
    ...parseApkUpdates(sections.get("updates-apk") ?? [], counter),
  ];
  skipped += counter.n;
  const byName = new Map<string, HostPackageInput[]>();
  for (const p of list) {
    const key = `${p.type}\u0000${p.name}`;
    byName.set(key, [...(byName.get(key) ?? []), p]);
  }
  const matched = new Set<string>();
  for (const u of updates) {
    for (const p of byName.get(`${u.type}\u0000${u.name}`) ?? []) {
      if (u.arch && p.arch && u.arch !== p.arch) continue;
      p.upgradableTo = u.to;
      p.securityUpdate = u.security;
      matched.add(`${p.type}\u0000${p.name}`);
    }
  }

  return {
    os: parseOsRelease(sections.get("os-release") ?? []),
    kernel: RE.kernel.test(kernel) ? kernel : null,
    arch,
    packages: list,
    pendingUpdates: matched.size,
    skipped,
  };
}

/* -------------------------------------------------------------------------- */
/* SBOM for grype                                                              */
/* -------------------------------------------------------------------------- */

/** purl namespace of the distribution, by os-release ID. */
const PURL_NAMESPACE: Record<string, string> = {
  rhel: "redhat",
  ol: "oraclelinux",
  amzn: "amazon",
  sles: "suse",
  "opensuse-leap": "opensuse",
  "opensuse-tumbleweed": "opensuse",
};

const enc = (value: string) => encodeURIComponent(value);

function purlOf(p: HostPackageInput, os: OsInfo): string {
  const distroId = os.id ?? "linux";
  const namespace = p.type === "apk" ? "alpine" : (PURL_NAMESPACE[distroId] ?? distroId);
  const qualifiers: string[] = [];
  if (p.arch) qualifiers.push(`arch=${enc(p.arch)}`);
  if (p.type === "rpm" && p.epoch) qualifiers.push(`epoch=${p.epoch}`);
  if (os.id) qualifiers.push(`distro=${enc(os.versionId ? `${os.id}-${os.versionId}` : os.id)}`);
  if (p.origin)
    qualifiers.push(
      `upstream=${enc(p.type === "deb" && p.originVersion ? `${p.origin}@${p.originVersion}` : p.origin)}`,
    );
  const version = p.type === "rpm" ? p.version.replace(/^\d+:/, "") : p.version;
  return `pkg:${p.type}/${enc(namespace)}/${enc(p.name)}@${enc(version)}${qualifiers.length ? `?${qualifiers.join("&")}` : ""}`;
}

function metadataOf(p: HostPackageInput): { metadataType: string; metadata: Record<string, unknown> } {
  if (p.type === "deb") {
    return {
      metadataType: "dpkg-db-entry",
      metadata: {
        package: p.name,
        source: p.origin ?? "",
        version: p.version,
        sourceVersion: p.originVersion ?? "",
        architecture: p.arch ?? "",
        files: [],
      },
    };
  }
  if (p.type === "rpm") {
    const release = /-([^-]+)$/.exec(p.version.replace(/^\d+:/, ""))?.[1] ?? "";
    const version = p.version.replace(/^\d+:/, "").replace(/-[^-]+$/, "");
    return {
      metadataType: "rpm-db-entry",
      metadata: {
        name: p.name,
        version,
        epoch: p.epoch || null,
        architecture: p.arch ?? "",
        release,
        sourceRpm: p.origin ?? "",
        size: 0,
        vendor: "",
        modularityLabel: "",
        files: [],
      },
    };
  }
  return {
    metadataType: "apk-db-entry",
    metadata: {
      package: p.name,
      originPackage: p.origin ?? p.name,
      version: p.version,
      architecture: p.arch ?? "",
      files: [],
    },
  };
}

/**
 * A syft-json SBOM of the server's installed packages, in the shape syft itself writes for a
 * scanned root file system (checked with `syft convert`): artifacts with purl and package
 * metadata, and the distribution. grype matches it like any other SBOM, with the distribution's
 * own security data and the source package names that distributions publish advisories for.
 */
export function buildHostSbom(input: {
  name: string;
  os: OsInfo;
  packages: HostPackageInput[];
}): Record<string, unknown> {
  const { os } = input;
  const databasePath = (t: PackageType) =>
    t === "deb"
      ? "/var/lib/dpkg/status"
      : t === "rpm"
        ? "/var/lib/rpm/rpmdb.sqlite"
        : "/lib/apk/db/installed";
  return {
    artifacts: input.packages.map((p) => ({
      id: createHash("sha256")
        .update(`${p.type}|${p.name}|${p.version}|${p.arch ?? ""}`)
        .digest("hex")
        .slice(0, 16),
      name: p.name,
      version: p.version,
      type: p.type,
      foundBy: `${p.type === "deb" ? "dpkg" : p.type}-db-cataloger`,
      locations: [{ path: databasePath(p.type) }],
      licenses: [],
      language: "",
      cpes: [],
      purl: purlOf(p, os),
      ...metadataOf(p),
    })),
    artifactRelationships: [],
    files: [],
    source: {
      id: "garnetops-host",
      name: input.name,
      version: "",
      type: "directory",
      metadata: { path: "/" },
    },
    distro: {
      prettyName: os.prettyName ?? os.name ?? "",
      name: os.name ?? os.id ?? "",
      id: os.id ?? "",
      ...(os.idLike.length ? { idLike: os.idLike } : {}),
      version: os.versionId ?? "",
      versionID: os.versionId ?? "",
      ...(os.codename ? { versionCodename: os.codename } : {}),
    },
    descriptor: { name: "garnetops", version: "1" },
    schema: {
      version: "16.1.11",
      url: "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.11.json",
    },
  };
}
