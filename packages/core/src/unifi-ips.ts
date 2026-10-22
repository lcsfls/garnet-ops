/**
 * UniFi IPS / threat events, a preview (ADR 0022).
 *
 * The official UniFi Network API does not expose intrusion prevention events. The console's internal API does,
 * and it can change with any UniFi release, so everything about it lives here, in one place, and the feature is
 * off by default and marked "preview" in the interface and in the documentation.
 *
 * It needs a separate local console user with a read-only role. The client logs in (the only POST requests it may
 * ever send are the console's login and logout paths, exactly), reads one page of events with a GET, and logs out
 * again. The session cookie and the CSRF token live in the worker's memory for the seconds a poll takes and are
 * never stored.
 *
 * Everything an event says is written by whoever attacks the network: signature and category are cleaned and
 * cut, shown as plain text and never sent to a model. The payload of the attack is never read.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { cleanText } from "./unifi.ts";

/* -------------------------------------------------------------------------- */
/* Limits and rhythm                                                           */
/* -------------------------------------------------------------------------- */

export const IPS_INTERVAL_SECONDS = { min: 30, max: 600, default: 60 } as const;
export const isIpsInterval = (n: unknown): n is number =>
  typeof n === "number" &&
  Number.isInteger(n) &&
  n >= IPS_INTERVAL_SECONDS.min &&
  n <= IPS_INTERVAL_SECONDS.max;

/** A poll asks for at most this many events. */
export const IPS_PAGE_LIMIT = 100;
/** Events kept per connection; older ones are deleted after every poll that stores something. */
export const IPS_KEEP_PER_CONNECTION = 20_000;
/** A poll answer larger than this is refused; 100 events are a few hundred kilobytes at most. */
export const IPS_MAX_BYTES = 2 * 1024 * 1024;
export const IPS_SIGNATURE_MAX = 200;
export const IPS_CATEGORY_MAX = 80;

/* -------------------------------------------------------------------------- */
/* The console's login and the one read                                        */
/* -------------------------------------------------------------------------- */

export type IpsFlavor = "unifi-os" | "network-app";

/** The paths of the internal API per kind of console. These are assumptions about an unofficial API (ADR 0022). */
export const IPS_PATHS: Record<IpsFlavor, { prefix: string; login: string; logout: string }> = {
  "unifi-os": { prefix: "/proxy/network", login: "/api/auth/login", logout: "/api/auth/logout" },
  "network-app": { prefix: "", login: "/api/login", logout: "/api/logout" },
};

const SITE_REF = "[A-Za-z0-9_-]{1,64}";
const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const isSiteRef = (value: string) => new RegExp(`^${SITE_REF}$`).test(value);

/**
 * The only requests the IPS client may send: GET of the events of one site with a numeric `start`, `end` and
 * `_limit`, and POST of the login and logout path of the console, with nothing in the query. Anything else is
 * refused before a connection is opened.
 */
export function isIpsRequest(
  flavor: IpsFlavor,
  method: string,
  path: string,
  query: Record<string, string> = {},
): boolean {
  const paths = IPS_PATHS[flavor];
  if (method === "POST")
    return (path === paths.login || path === paths.logout) && Object.keys(query).length === 0;
  if (method !== "GET") return false;
  if (!new RegExp(`^${escapeRegex(paths.prefix)}/api/s/${SITE_REF}/stat/ips/event$`).test(path)) return false;
  return Object.entries(query).every(
    ([key, value]) => (key === "start" || key === "end" || key === "_limit") && /^\d{1,16}$/.test(value),
  );
}

/* -------------------------------------------------------------------------- */
/* The IPS user                                                                */
/* -------------------------------------------------------------------------- */

/** User names that are the console's administrator accounts by habit: refused (ADR 0022). */
const FORBIDDEN_USERNAMES = new Set([
  "admin",
  "administrator",
  "root",
  "ubnt",
  "ui",
  "unifi",
  "owner",
  "superadmin",
  "super",
  "ubiquiti",
]);

export type UsernameProblem = "invalid" | "forbidden";
export function checkIpsUsername(
  value: string,
): { ok: true; value: string } | { ok: false; problem: UsernameProblem } {
  const name = value.trim();
  if (!/^[A-Za-z0-9._@+-]{1,64}$/.test(name)) return { ok: false, problem: "invalid" };
  const local = name.toLowerCase().split("@")[0] ?? "";
  if (FORBIDDEN_USERNAMES.has(name.toLowerCase()) || FORBIDDEN_USERNAMES.has(local)) {
    return { ok: false, problem: "forbidden" };
  }
  return { ok: true, value: name };
}

/** Printable characters including blanks; the console sets the minimum length. */
export const IPS_PASSWORD_PATTERN = /^[\x20-\x7e]{8,200}$/;

/** At most this many rights are kept, and each label is cut; the list is shown to the admin who acknowledges it. */
export const IPS_RIGHTS_MAX = 20;
const IPS_RIGHT_LENGTH = 48;

/**
 * The rights beyond viewing that the login answer reports, as short sorted labels: `owner`, `super_admin`, and
 * `role: <name>` for every role whose name is not a view-only one. Empty means the answer reports nothing beyond
 * viewing. The shapes differ by console and version, so this is best effort: UniFi OS reports `isOwner` /
 * `isSuperAdmin` and roles, the Network application `is_super` and a role. An answer in a shape this does not know
 * reports nothing, and the documentation says so; any role name that is not recognisably view-only counts.
 */
export function parseLoginResponse(body: unknown): { rights: string[] } {
  const roots: unknown[] = [body];
  const top =
    body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (top) {
    roots.push(top.user);
    if (Array.isArray(top.data)) roots.push(...top.data.slice(0, 3));
    else roots.push(top.data);
  }
  const rights = new Set<string>();
  const addRole = (value: unknown) => {
    const raw =
      typeof value === "string"
        ? value
        : value && typeof value === "object" && typeof (value as { name?: unknown }).name === "string"
          ? (value as { name: string }).name
          : null;
    if (raw === null) return;
    const name = cleanText(raw, IPS_RIGHT_LENGTH);
    if (name && !isViewOnlyRoleName(name)) rights.add(`role: ${name}`);
  };
  for (const root of roots) {
    if (!root || typeof root !== "object" || Array.isArray(root)) continue;
    const r = root as Record<string, unknown>;
    if (r.isOwner === true) rights.add("owner");
    if (r.isSuperAdmin === true || r.is_super === true) rights.add("super_admin");
    addRole(r.role);
    addRole(r.roleName);
    addRole(r.role_name);
    if (Array.isArray(r.roles)) for (const role of r.roles.slice(0, 10)) addRole(role);
  }
  return { rights: [...rights].sort().slice(0, IPS_RIGHTS_MAX) };
}

/** Role names that mean viewing only: "view only", "read only", "readonly", "viewer". */
export function isViewOnlyRoleName(name: string): boolean {
  return /^(?:(?:view|read)[ _-]?only|viewer)$/i.test(name.trim());
}

/**
 * Whether the preview may poll: no rights beyond viewing are reported, or an admin has acknowledged exactly the list
 * that is reported now. A different list (more, fewer or other rights) is not covered; the worker also clears the
 * acknowledgement whenever the reported list changes.
 */
export function ipsRightsAcknowledged(rights: readonly string[], acknowledged: readonly string[]): boolean {
  if (rights.length === 0) return true;
  const a = [...new Set(rights)].sort();
  const b = [...new Set(acknowledged)].sort();
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/** The same list, order and duplicates aside. */
export function sameRights(a: readonly string[], b: readonly string[]): boolean {
  const x = [...new Set(a)].sort();
  const y = [...new Set(b)].sort();
  return x.length === y.length && x.every((value, i) => value === y[i]);
}

/* -------------------------------------------------------------------------- */
/* Events                                                                      */
/* -------------------------------------------------------------------------- */

export type IpsAction = "blocked" | "alerted";

/** `drop`, `blocked`, `block`, `reject` and `deny` are blocked; everything else (`alert`, `allowed`) was observed only. */
export function normalizeAction(value: unknown): IpsAction {
  if (typeof value !== "string") return "alerted";
  return /^(drop|dropped|block|blocked|reject|rejected|deny|denied)$/i.test(value.trim())
    ? "blocked"
    : "alerted";
}

export interface IpsEvent {
  /** The console's event id, or a hash of the event's own fields: reading it twice stores it once. */
  docId: string;
  at: Date;
  /** The source address as text, lower case (the same form the Wazuh feed stores). */
  ip: string;
  action: IpsAction;
  /** Cleaned plain text, at most 200 characters. Attacker-influenced. */
  signature: string;
  category: string | null;
  /** Port of the attacked service; the destination address is never read. */
  destPort: number | null;
  proto: string | null;
}

const MIN_TIME = Date.parse("2010-01-01T00:00:00Z");

/** A time in milliseconds, seconds or ISO text; null for anything implausible. */
function eventTime(record: Record<string, unknown>): Date | null {
  for (const key of ["timestamp", "time", "ts", "datetime", "date"]) {
    const v = record[key];
    let ms: number | null = null;
    if (typeof v === "number" && Number.isFinite(v)) ms = v > 1e11 ? v : v * 1000;
    else if (typeof v === "string" && /^\d{9,13}$/.test(v.trim())) {
      const n = Number(v);
      ms = n > 1e11 ? n : n * 1000;
    } else if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T/.test(v.trim())) ms = Date.parse(v.trim());
    if (ms !== null && Number.isFinite(ms) && ms > MIN_TIME && ms < Date.now() + 86_400_000) {
      return new Date(Math.round(ms));
    }
  }
  return null;
}

function firstString(record: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const v = record[key];
    if (typeof v === "string" && v.trim() !== "") return v;
  }
  return null;
}

function parseEvent(entry: unknown): IpsEvent | null {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const r = entry as Record<string, unknown>;
  const at = eventTime(r);
  const rawIp = firstString(r, ["src_ip", "srcip", "source_ip"]);
  if (!at || !rawIp || isIP(rawIp.trim()) === 0) return null;
  const ip = rawIp.trim().toLowerCase();
  const signature = cleanText(
    firstString(r, ["inner_alert_signature", "msg", "signature"]) ?? "",
    IPS_SIGNATURE_MAX,
  );
  const category = cleanText(
    firstString(r, ["inner_alert_category", "catname", "category"]) ?? "",
    IPS_CATEGORY_MAX,
  );
  const portRaw = r.dest_port ?? r.dst_port;
  const port = typeof portRaw === "string" && /^\d{1,5}$/.test(portRaw) ? Number(portRaw) : portRaw;
  const destPort =
    typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
  const protoRaw = firstString(r, ["proto"]);
  const proto =
    protoRaw && /^[A-Za-z0-9_-]{1,16}$/.test(protoRaw.trim()) ? protoRaw.trim().toLowerCase() : null;
  const action = normalizeAction(r.inner_alert_action ?? r.action);
  const id = typeof r._id === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(r._id) ? r._id : null;
  const docId =
    id ??
    createHash("sha256")
      .update(`${at.getTime()}|${ip}|${signature}|${destPort ?? ""}|${action}`)
      .digest("hex")
      .slice(0, 32);
  return { docId, at, ip, action, signature, category: category || null, destPort, proto };
}

export interface ParsedIpsEvents {
  /** Oldest first. */
  events: IpsEvent[];
  dropped: number;
  /** The page was full, so more may be waiting. */
  fullPage: boolean;
  /** The newest time seen, also for events that were dropped (so the cursor can move on). */
  latest: Date | null;
}

/**
 * Parses the answer of the events endpoint: `{ data: [...] }` or a plain list. An answer that is neither is
 * `null` (the endpoint is not what we expect, and the poll fails instead of storing nothing silently).
 */
export function parseIpsEvents(body: unknown, limit = IPS_PAGE_LIMIT): ParsedIpsEvents | null {
  let list: unknown;
  if (Array.isArray(body)) list = body;
  else if (body && typeof body === "object" && Array.isArray((body as { data?: unknown }).data)) {
    list = (body as { data: unknown[] }).data;
  } else return null;
  const entries = (list as unknown[]).slice(0, limit);
  const events: IpsEvent[] = [];
  let dropped = Math.max(0, (list as unknown[]).length - limit);
  for (const entry of entries) {
    const event = parseEvent(entry);
    if (event) events.push(event);
    else dropped++;
  }
  events.sort((a, b) => a.at.getTime() - b.at.getTime());
  const latest = events.length > 0 ? (events[events.length - 1] as IpsEvent).at : null;
  return { events, dropped, fullPage: (list as unknown[]).length >= limit, latest };
}

/* -------------------------------------------------------------------------- */
/* Status                                                                      */
/* -------------------------------------------------------------------------- */

export type IpsState = "live" | "waiting" | "paused" | "off";
export type IpsPausedReason = "disabled" | "certificate" | "credentials" | "no-sync" | "rights";

export interface IpsStatusInput {
  /** The admin switched the preview on. */
  enabled: boolean;
  /** The connection itself is switched on. */
  connectionEnabled: boolean;
  /** The certificate is confirmed and has not changed. */
  certificateOk: boolean;
  /** A user name and a sealed password exist. */
  hasCredentials: boolean;
  /** A sync has run, so the sites and the kind of console are known. */
  synced: boolean;
  /** The rights beyond viewing that the last login reported, and the list an admin acknowledged. */
  rights: readonly string[];
  rightsAcknowledged: readonly string[];
  lastPollAt: Date | null;
  lastError: string | null;
  intervalSeconds: number;
  now: Date;
}

export interface IpsStatus {
  state: IpsState;
  reason: IpsPausedReason | null;
  error: string | null;
}

/**
 * What the page says about the preview, derived from the facts: "off" (not switched on), "paused" (the connection is
 * blocked: switched off, a certificate to confirm, no credentials, no sync yet, rights beyond viewing not acknowledged), "waiting" (nothing polled yet, the
 * last poll failed, or the worker has not polled for much longer than its interval) or "live".
 */
export function ipsStatus(input: IpsStatusInput): IpsStatus {
  const status = (state: IpsState, reason: IpsPausedReason | null = null, error: string | null = null) => ({
    state,
    reason,
    error,
  });
  if (!input.enabled) return status("off");
  if (!input.connectionEnabled) return status("paused", "disabled");
  if (!input.certificateOk) return status("paused", "certificate");
  if (!input.hasCredentials) return status("paused", "credentials");
  if (!input.synced) return status("paused", "no-sync");
  if (!ipsRightsAcknowledged(input.rights, input.rightsAcknowledged)) return status("paused", "rights");
  if (!input.lastPollAt) return status("waiting");
  if (input.lastError) return status("waiting", null, input.lastError);
  const stale = input.now.getTime() - input.lastPollAt.getTime() > input.intervalSeconds * 3000 + 60_000;
  return stale ? status("waiting") : status("live");
}
