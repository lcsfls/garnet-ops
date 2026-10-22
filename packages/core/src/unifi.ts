/**
 * UniFi (ADR 0022): validation of what an admin types, the requests the client may send to the official
 * local UniFi Network API, and defensive parsers for every answer.
 *
 * Everything the console returns is hostile input: the parsers read only the fields they know, check each
 * against a pattern or a range, cap every size and count, and drop what does not fit instead of failing the
 * whole sync. Clients are never read beyond their number: no names, no MAC addresses, no addresses (privacy,
 * ADR 0022). Nothing here executes, evaluates or interpolates what the console sent.
 */
import { z } from "zod";
import { checkHostAddress } from "./hosts.ts";

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

export const UNIFI_DEFAULT_PORT = 443;
/** Consoles per organisation. */
export const MAX_UNIFI_CONNECTIONS = 5;
export const MAX_SITES_PER_CONNECTION = 100;
export const MAX_DEVICES_PER_SITE = 1000;
export const MAX_DEVICES_PER_CONNECTION = 2000;
/** The official API pages with `limit`; 200 is its documented maximum. */
export const PAGE_SIZE = 200;
export const MAX_PAGES = 20;
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const CONNECT_TIMEOUT_MS = 10_000;
export const REQUEST_TIMEOUT_MS = 20_000;
/** Pause between two requests: a sync is sequential and polite. */
export const REQUEST_GAP_MS = 25;
/** A sync stops after this many requests ... */
export const MAX_REQUESTS_PER_SYNC = 3000;
/** ... or this long. */
export const SYNC_BUDGET_MINUTES = 10;
/** How often the worker syncs every connected console. */
export const UNIFI_SYNC_INTERVAL_MINUTES = 15;
/** A device must be seen offline by this many consecutive syncs before anybody is told (debounce). */
export const OFFLINE_NOTIFY_AFTER_SYNCS = 2;

/* -------------------------------------------------------------------------- */
/* What an admin types                                                         */
/* -------------------------------------------------------------------------- */

export type UrlProblem = "empty" | "tooLong" | "invalid" | "notHttps" | "credentials" | "path" | "address";
export type UrlCheck =
  | { ok: true; url: string; host: string; port: number }
  | { ok: false; problem: UrlProblem };

/**
 * Checks and normalises the address of a UniFi console: `https://host[:port]`, nothing else. Plain http, user
 * names, paths, queries and fragments are refused; the host goes through the same checks as a server address
 * (no loopback, link-local or metadata addresses, no numeric tricks such as `127.1`). Private addresses are
 * allowed: consoles live in the customer's network. The port defaults to 443.
 */
export function checkUnifiUrl(value: string): UrlCheck {
  const text = value.trim();
  if (text.length === 0) return { ok: false, problem: "empty" };
  if (text.length > 300) return { ok: false, problem: "tooLong" };
  if (!/^https:\/\//i.test(text)) return { ok: false, problem: "notHttps" };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { ok: false, problem: "invalid" };
  }
  if (url.username || url.password) return { ok: false, problem: "credentials" };
  if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) {
    return { ok: false, problem: "path" };
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const address = checkHostAddress(host);
  if (!address.ok) return { ok: false, problem: "address" };
  const port = url.port ? Number(url.port) : UNIFI_DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, problem: "invalid" };
  const shown = address.kind === "ipv6" ? `[${address.address}]` : address.address;
  return { ok: true, url: `https://${shown}:${port}`, host: address.address, port };
}

/** The key created under Settings, Control Plane, Integrations of the console: printable, no blanks. */
export const API_KEY_PATTERN = /^[A-Za-z0-9_\-+/=.]{16,200}$/;

/** A display name: printable text, 1 to 80 characters. */
export function checkConnectionName(value: string): string | null {
  const name = value.trim();
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (name.length === 0 || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

/* -------------------------------------------------------------------------- */
/* Where the official API lives                                                */
/* -------------------------------------------------------------------------- */

/**
 * The official local API sits behind a different prefix on a UniFi OS console (UDM, UCG, Cloud Key Gen2+: the
 * Network application is proxied) and on a self-hosted Network Application. `auto` tries the UniFi OS prefix
 * first and the other on a 404; the sync stores what it found.
 */
export const API_BASES = {
  "unifi-os": "/proxy/network/integration",
  "network-app": "/integration",
} as const;
export type ApiBase = keyof typeof API_BASES;
export const API_BASE_CHOICES = ["auto", "unifi-os", "network-app"] as const;
export type ApiBaseChoice = (typeof API_BASE_CHOICES)[number];

const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
export const isUuid = (value: string) => new RegExp(`^${UUID}$`).test(value);

/**
 * Every path the integration reads from the official API, relative to the base, and nothing else (ADR 0022).
 * The HTTP client refuses any other path and any method but GET, so a bug elsewhere cannot make it call
 * something that changes state or reads more than the inventory. The clients list is read with `limit=1` for
 * its total only.
 */
export const OFFICIAL_READ_PATHS: readonly RegExp[] = [
  /^\/v1\/info$/,
  /^\/v1\/sites$/,
  new RegExp(`^/v1/sites/${UUID}/devices$`),
  new RegExp(`^/v1/sites/${UUID}/devices/${UUID}/statistics/latest$`),
  new RegExp(`^/v1/sites/${UUID}/clients$`),
];
export const isOfficialReadPath = (path: string) => OFFICIAL_READ_PATHS.some((p) => p.test(path));

/** The only query parameters the client sends: paging, as plain integers. */
export function isOfficialQuery(query: Record<string, string>): boolean {
  return Object.entries(query).every(
    ([key, value]) =>
      (key === "limit" || key === "offset") && /^\d{1,6}$/.test(value) && Number(value) <= 100_000,
  );
}

/* -------------------------------------------------------------------------- */
/* Primitive parsers                                                           */
/* -------------------------------------------------------------------------- */

// Control characters, line and paragraph separators and bidirectional overrides (Trojan Source style tricks).
// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** Free text from the console as safe plain text: control characters removed, blanks collapsed, cut at `max`. */
export function cleanText(value: string, max: number): string {
  return value.replace(CONTROL, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

const text = (max: number) =>
  z
    .string()
    .transform((v) => cleanText(v, max))
    .optional()
    .catch(undefined);

const num = z
  .preprocess(
    (v) => (typeof v === "string" && v.trim() !== "" ? Number(v) : v),
    z.number().finite().min(0).max(1e15),
  )
  .optional()
  .catch(undefined);

const bool = z.boolean().optional().catch(undefined);

/** Parses each item of a list on its own and drops the ones that do not fit. */
function parseList<S extends z.ZodTypeAny>(
  schema: S,
  data: unknown,
  cap: number,
): { items: z.infer<S>[]; dropped: number } {
  if (!Array.isArray(data)) return { items: [], dropped: 0 };
  const items: z.infer<S>[] = [];
  let dropped = Math.max(0, data.length - cap);
  for (const entry of data.slice(0, cap)) {
    const r = schema.safeParse(entry);
    if (r.success) items.push(r.data);
    else dropped++;
  }
  return { items, dropped };
}

const asRecord = (v: unknown): Record<string, unknown> | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/* -------------------------------------------------------------------------- */
/* /v1/info, /v1/sites                                                         */
/* -------------------------------------------------------------------------- */

/** The application version from `/v1/info`, or null if the answer is not the UniFi Network API's. */
export function parseInfo(body: unknown): string | null {
  const record = asRecord(body);
  const raw = record?.applicationVersion;
  if (typeof raw !== "string") return null;
  const v = cleanText(raw, 40);
  return /^\d+(?:\.\d+){0,3}(?:[-+~.][A-Za-z0-9.+~-]*)?$/.test(v) ? v : null;
}

export interface UfSite {
  id: string;
  /** The short name the internal API uses in its paths ("default"); null when the console does not tell. */
  internalReference: string | null;
  name: string;
}

/** A page of a list answer: `{ offset, limit, count, totalCount, data: [...] }`. */
export interface PageInfo {
  data: unknown[];
  totalCount: number | null;
}

/** The envelope of every list answer of the official API. An answer without a `data` list is not one. */
export function parsePage(body: unknown): PageInfo | null {
  const record = asRecord(body);
  if (!record || !Array.isArray(record.data)) return null;
  const total = num.parse(record.totalCount);
  return { data: record.data, totalCount: total === undefined ? null : Math.round(total) };
}

const siteItem = z.object({
  id: z.string().refine(isUuid),
  internalReference: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,64}$/)
    .optional()
    .catch(undefined),
  name: text(80),
});

export function parseSites(data: unknown[]): { sites: UfSite[]; dropped: number } {
  const { items, dropped } = parseList(siteItem, data, MAX_SITES_PER_CONNECTION);
  return {
    sites: items.map((s) => ({
      id: s.id.toLowerCase(),
      internalReference: s.internalReference ?? null,
      name: s.name || s.internalReference || "Site",
    })),
    dropped,
  };
}

/* -------------------------------------------------------------------------- */
/* Devices                                                                     */
/* -------------------------------------------------------------------------- */

export const DEVICE_STATES = ["online", "offline", "other"] as const;
export type DeviceState = (typeof DEVICE_STATES)[number];

export interface UfDevice {
  id: string;
  name: string;
  model: string | null;
  mac: string | null;
  ip: string | null;
  state: DeviceState;
  /** The console's own state word (`ONLINE`, `UPDATING` ...), upper case letters only, for display. */
  rawState: string;
  firmwareVersion: string | null;
  /** True when the console says a newer firmware is available; null when it does not say. */
  firmwareUpdatable: boolean | null;
  /** The newest firmware version, only if the console names one. */
  latestFirmware: string | null;
}

/** The device state words of the official API, grouped. Offline is only what the console calls offline. */
const OFFLINE_STATES = new Set(["OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"]);
export function deviceStateOf(raw: string): DeviceState {
  if (raw === "ONLINE") return "online";
  return OFFLINE_STATES.has(raw) ? "offline" : "other";
}

const MAC = /^[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/;
const version = z
  .string()
  .transform((v) => cleanText(v, 64))
  .refine((v) => VERSION.test(v))
  .optional()
  .catch(undefined);

const deviceItem = z.object({
  id: z.string().refine(isUuid),
  name: text(120),
  model: text(80),
  macAddress: z
    .string()
    .refine((v) => MAC.test(v.trim()))
    .optional()
    .catch(undefined),
  ipAddress: z
    .string()
    .transform((v) => v.trim())
    .refine((v) => /^[0-9a-fA-F:.]{2,45}$/.test(v))
    .optional()
    .catch(undefined),
  state: z
    .string()
    .transform((v) => cleanText(v, 40).toUpperCase())
    .optional()
    .catch(undefined),
  firmwareVersion: version,
  firmwareUpdatable: bool,
  // Not part of the documented schema; read if a console sends it.
  latestFirmwareVersion: version,
});

export function parseDevices(data: unknown[]): { devices: UfDevice[]; dropped: number } {
  const { items, dropped } = parseList(deviceItem, data, MAX_DEVICES_PER_SITE);
  return {
    devices: items.map((d) => {
      const rawState = d.state && /^[A-Z_]{1,40}$/.test(d.state) ? d.state : "UNKNOWN";
      return {
        id: d.id.toLowerCase(),
        name: d.name || d.model || "Device",
        model: d.model || null,
        mac: d.macAddress ? d.macAddress.trim().toUpperCase().replace(/-/g, ":") : null,
        ip: d.ipAddress ?? null,
        state: deviceStateOf(rawState),
        rawState,
        firmwareVersion: d.firmwareVersion ?? null,
        firmwareUpdatable: d.firmwareUpdatable ?? null,
        latestFirmware: d.latestFirmwareVersion ?? null,
      };
    }),
    dropped,
  };
}

/** Uptime in seconds from `/devices/{id}/statistics/latest`, or null. */
export function parseUptime(body: unknown): number | null {
  const record = asRecord(body);
  const value = num.parse(record?.uptimeSec);
  return value === undefined || value > 3_153_600_000 ? null : Math.round(value);
}

/** The number of clients of a site: the `totalCount` of a one-entry page. Nothing else about clients is read. */
export function parseClientTotal(body: unknown): number | null {
  const page = parsePage(body);
  if (!page || page.totalCount === null || page.totalCount > 10_000_000) return null;
  return page.totalCount;
}

/* -------------------------------------------------------------------------- */
/* Firmware                                                                    */
/* -------------------------------------------------------------------------- */

export type FirmwareStatus = "updateAvailable" | "current" | "unknown";

/**
 * What GarnetOps can say about a device's firmware (ADR 0022): the console tells whether a newer version
 * exists, nothing more. It is a maintenance hint, never a vulnerability finding: grype cannot match network
 * firmware, so a device is never called "vulnerable".
 */
export function firmwareStatus(device: { firmwareUpdatable: boolean | null }): FirmwareStatus {
  if (device.firmwareUpdatable === true) return "updateAvailable";
  if (device.firmwareUpdatable === false) return "current";
  return "unknown";
}

/** The flags of a device row: what deserves a look. Offline is only a device the console calls offline. */
export type DeviceFlag = "offline" | "updateAvailable";
export function deviceFlags(device: { state: DeviceState; firmwareUpdatable: boolean | null }): DeviceFlag[] {
  const flags: DeviceFlag[] = [];
  if (device.state === "offline") flags.push("offline");
  if (firmwareStatus(device) === "updateAvailable") flags.push("updateAvailable");
  return flags;
}

/* -------------------------------------------------------------------------- */
/* Notifications                                                               */
/* -------------------------------------------------------------------------- */

export interface DeviceNotifyState {
  state: DeviceState;
  /** Consecutive syncs that saw the device offline, including this one (0 when online). */
  offlineSyncs: number;
  offlineNotified: boolean;
  firmwareUpdatable: boolean | null;
  firmwareVersion: string | null;
  firmwareNotifiedVersion: string | null;
}

/**
 * Whether to tell people now (ADR 0022, ADR 0019): a device is reported offline once, after it was offline in
 * `OFFLINE_NOTIFY_AFTER_SYNCS` syncs in a row, and not again until it has been online; a firmware update is
 * reported once per device and firmware version that is installed while an update is available.
 */
export function notifyDecision(d: DeviceNotifyState): { offline: boolean; firmware: boolean } {
  return {
    offline: d.state === "offline" && !d.offlineNotified && d.offlineSyncs >= OFFLINE_NOTIFY_AFTER_SYNCS,
    firmware:
      d.firmwareUpdatable === true &&
      d.firmwareVersion !== null &&
      d.firmwareNotifiedVersion !== d.firmwareVersion,
  };
}
