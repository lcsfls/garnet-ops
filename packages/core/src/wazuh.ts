/**
 * Wazuh (ADR 0015): validation of what an admin types, the requests the clients may send, the
 * query templates for the indexer, the privilege check of the two service users, and defensive
 * parsers for every answer of the manager API and the indexer.
 *
 * Everything Wazuh returns is hostile input: alert content (rule descriptions, file paths, log
 * lines, source addresses) is written by whoever can make a monitored system log something. The
 * parsers read only the fields they know, check each against a pattern or a range, cap sizes and
 * counts, and drop what does not fit instead of failing the whole sync. Nothing here executes,
 * evaluates or interpolates what Wazuh sent, and no query is ever built from outside input: the
 * indexer queries are fixed templates that take an enumerated window and nothing else.
 *
 * Field names and index patterns of Wazuh are an external contract we do not control. They live
 * in the adapters below, one per major version, so a change in a release touches one place.
 */
import { isIP } from "node:net";
import { z } from "zod";
import { checkHostAddress } from "./hosts.ts";

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

export const WAZUH_MANAGER_PORT = 55000;
export const WAZUH_INDEXER_PORT = 9200;
/** One connection per organisation today (the tables carry the connection id so more can follow). */
export const MAX_WAZUH_CONNECTIONS = 1;
/** Agents kept per connection; more are ignored and the sync says so. */
export const MAX_AGENTS = 5000;
/** Agents asked for per request of the manager API (its own maximum is 500). */
export const AGENTS_PAGE_SIZE = 500;
/** An answer larger than this is refused. The biggest normal answer (vulnerability counts per agent) is far below it. */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const CONNECT_TIMEOUT_MS = 10_000;
export const REQUEST_TIMEOUT_MS = 20_000;
/** The indexer is told to stop an aggregation after this long (`timeout` in the request body). */
export const INDEXER_SEARCH_TIMEOUT = "20s";
/** Pause between two requests: a sync is sequential and polite. */
export const REQUEST_GAP_MS = 25;
export const MAX_REQUESTS_PER_SYNC = 200;
export const SYNC_BUDGET_MINUTES = 5;
export const WAZUH_SYNC_INTERVAL_MINUTES = 15;

export const TOP_AGENTS = 10;
export const MAX_TACTICS = 20;
export const MAX_SOURCE_IPS = 100;
export const MAX_FIM_EVENTS = 25;
export const MAX_GROUPS_PER_AGENT = 20;
export const MAX_GROUPS_PER_SOURCE = 5;
/** Agents named per source address on the attack overview (ADR 0016). */
export const MAX_AGENTS_PER_SOURCE = 5;

/* -------------------------------------------------------------------------- */
/* What an admin types                                                         */
/* -------------------------------------------------------------------------- */

export type UrlProblem = "empty" | "tooLong" | "invalid" | "notHttps" | "credentials" | "path" | "address";
export type UrlCheck =
  | { ok: true; url: string; host: string; port: number }
  | { ok: false; problem: UrlProblem };

/**
 * Checks and normalises the address of the manager API or the indexer: `https://host[:port]`,
 * nothing else. Plain http, user names, paths, queries and fragments are refused; the host goes
 * through the same checks as a server address (no loopback, link-local or metadata addresses,
 * no numeric tricks such as `127.1`).
 */
export function checkWazuhUrl(value: string, defaultPort: number): UrlCheck {
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
  const port = url.port ? Number(url.port) : defaultPort;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, problem: "invalid" };
  const shown = address.kind === "ipv6" ? `[${address.address}]` : address.address;
  return { ok: true, url: `https://${shown}:${port}`, host: address.address, port };
}

/** The default accounts of a Wazuh installation can do everything; they are refused as service users. */
const PRIVILEGED_USERS = new Set(["admin", "wazuh", "wazuh-wui", "kibanaserver"]);

export type UsernameProblem = "invalid" | "privileged";

export function checkWazuhUsername(
  value: string,
): { ok: true; value: string } | { ok: false; problem: UsernameProblem } {
  const name = value.trim();
  if (!/^[A-Za-z0-9._@-]{1,64}$/.test(name)) return { ok: false, problem: "invalid" };
  if (PRIVILEGED_USERS.has(name.toLowerCase())) return { ok: false, problem: "privileged" };
  return { ok: true, value: name };
}

/** A password: 8 to 200 characters, no control characters. Wazuh decides about strength. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
export const WAZUH_PASSWORD_PATTERN = /^[^\u0000-\u001f\u007f-\u009f]{8,200}$/;

/** A display name: printable text, 1 to 80 characters. */
export function checkConnectionName(value: string): string | null {
  const name = value.trim();
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (name.length === 0 || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

/**
 * The address of the customer's Wazuh dashboard, shown as an external link. GarnetOps never
 * requests it. http and https only (never `javascript:` or `data:`), no credentials, no fragment.
 */
export function checkDashboardUrl(value: string): { ok: true; url: string } | { ok: false } {
  const text = value.trim();
  if (text.length === 0 || text.length > 400 || !/^https?:\/\//i.test(text)) return { ok: false };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { ok: false };
  }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password || url.hash) {
    return { ok: false };
  }
  if (!url.hostname || /[\s<>"'`\\]/.test(text)) return { ok: false };
  return { ok: true, url: url.href };
}

/**
 * The address agents use to reach the manager (`WAZUH_MANAGER`): a host name or an IP address,
 * nothing else. It ends up inside a shell command, so the check is a whitelist of characters;
 * the command templates quote it as well.
 */
export function checkEnrollmentHost(value: string): { ok: true; value: string } | { ok: false } {
  const text = value.trim();
  if (text.length === 0 || text.length > 253) return { ok: false };
  if (isIP(text) !== 0) return { ok: true, value: text.toLowerCase() };
  if (
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(
      text,
    )
  ) {
    return { ok: false };
  }
  return { ok: true, value: text.toLowerCase() };
}

/** A custom certificate authority: PEM text with one to five certificates, at most 24 KB. */
export function checkCaPem(
  value: string,
  parse: (pem: string) => boolean,
): { ok: true; pem: string; count: number } | { ok: false } {
  const text = value.replace(/\r\n/g, "\n").trim();
  if (text.length === 0 || text.length > 24_000) return { ok: false };
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\n]+?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0 || blocks.length > 5) return { ok: false };
  // Nothing but certificates: any other text (a private key by mistake!) is refused.
  const rest = text.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\n]+?-----END CERTIFICATE-----/g, "");
  if (rest.trim() !== "") return { ok: false };
  if (!blocks.every(parse)) return { ok: false };
  return { ok: true, pem: `${blocks.join("\n")}\n`, count: blocks.length };
}

/* -------------------------------------------------------------------------- */
/* Certificates                                                                */
/* -------------------------------------------------------------------------- */

export { FINGERPRINT_PATTERN, normalizeFingerprint } from "./proxmox.ts";

/* -------------------------------------------------------------------------- */
/* Severity                                                                    */
/* -------------------------------------------------------------------------- */

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];
export type SeverityCounts = Record<Severity, number>;

/**
 * Wazuh rule levels (0 to 15) on our four-step scale (ADR 0015). Level 0 is "ignored" in Wazuh
 * and never raises an alert, so it has no severity here. Levels above 15 do not exist; they are
 * treated as 15 rather than dropped, because dropping an alert is worse than trusting a bound.
 *
 *  12 to 15   critical
 *   9 to 11   high
 *   6 to  8   medium
 *   1 to  5   low
 */
export function severityForLevel(level: number): Severity | null {
  if (!Number.isFinite(level) || level < 1) return null;
  if (level >= 12) return "critical";
  if (level >= 9) return "high";
  if (level >= 6) return "medium";
  return "low";
}

export const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0 });

/* -------------------------------------------------------------------------- */
/* Adapters: one per major version, the only place that knows Wazuh's names     */
/* -------------------------------------------------------------------------- */

export type AdapterId = "wazuh4" | "wazuh5";

export interface WazuhAdapter {
  id: AdapterId;
  /** Shown as "preview" in the UI until Wazuh 5.0 is generally available (ADR 0002). */
  preview: boolean;
  /** The two indices the indexer user reads, and nothing else (ADR 0015). */
  alertIndex: string;
  vulnerabilityIndex: string;
  /** Fields of an alert document. */
  fields: {
    timestamp: string;
    level: string;
    tactic: string;
    groups: string;
    agentId: string;
    agentName: string;
    sourceIp: string;
    fimPath: string;
    fimEvent: string;
  };
  /** Fields of a vulnerability state document. */
  vulnerabilityFields: { agentId: string; severity: string };
}

const SHARED_FIELDS: WazuhAdapter["fields"] = {
  timestamp: "@timestamp",
  level: "rule.level",
  tactic: "rule.mitre.tactic",
  groups: "rule.groups",
  agentId: "agent.id",
  agentName: "agent.name",
  sourceIp: "data.srcip",
  fimPath: "syscheck.path",
  fimEvent: "syscheck.event",
};

export const ADAPTERS: Record<AdapterId, WazuhAdapter> = {
  wazuh4: {
    id: "wazuh4",
    preview: false,
    alertIndex: "wazuh-alerts-*",
    vulnerabilityIndex: "wazuh-states-vulnerabilities-*",
    fields: SHARED_FIELDS,
    vulnerabilityFields: { agentId: "agent.id", severity: "vulnerability.severity" },
  },
  // Built against the release candidates of Wazuh 5 and not yet run against a general release.
  wazuh5: {
    id: "wazuh5",
    preview: true,
    alertIndex: "wazuh-alerts-*",
    vulnerabilityIndex: "wazuh-states-vulnerabilities-*",
    fields: SHARED_FIELDS,
    vulnerabilityFields: { agentId: "agent.id", severity: "vulnerability.severity" },
  },
};

export interface WazuhVersion {
  /** As the manager reports it, without a leading "v". */
  version: string;
  major: number;
  minor: number;
}

/** The adapter for a manager version, or null for a major version GarnetOps does not read. */
export function adapterFor(version: WazuhVersion): WazuhAdapter | null {
  if (version.major === 4) return ADAPTERS.wazuh4;
  if (version.major === 5) return ADAPTERS.wazuh5;
  return null;
}

/* -------------------------------------------------------------------------- */
/* Requests the clients may send                                               */
/* -------------------------------------------------------------------------- */

/** The only things asked of the manager API. `/agents/{id}/key` and every other path are refused. */
export const AGENT_SELECT =
  "id,name,ip,registerIP,os.name,os.version,os.platform,os.arch,version,status,lastKeepAlive,group,dateAdd";

export const MANAGER_LOGIN_PATH = "/security/user/authenticate";

/** Query of one page of the agent list; the offset is the only variable and must be a number. */
export function agentsQuery(offset: number): Record<string, string> {
  const safe = Number.isInteger(offset) && offset >= 0 && offset <= 1_000_000 ? offset : 0;
  return { limit: String(AGENTS_PAGE_SIZE), offset: String(safe), select: AGENT_SELECT, sort: "+id" };
}

const AGENTS_QUERY_KEYS: Record<string, (v: string) => boolean> = {
  limit: (v) => v === String(AGENTS_PAGE_SIZE),
  offset: (v) => /^\d{1,7}$/.test(v),
  select: (v) => v === AGENT_SELECT,
  sort: (v) => v === "+id",
};

/**
 * Method and path allow-list of the manager client (ADR 0015). GET only, except the login, which
 * the API defines as POST. The list is: the version, the agent list, and the permissions of the
 * user itself. No other path, in particular nothing under `/agents/{id}`, `/security` other than
 * the two entries, `/active-response`, `/manager/configuration`, `/cluster` or `/logtest`.
 */
export function isManagerRequestAllowed(
  method: string,
  path: string,
  query: Record<string, string>,
): boolean {
  const keys = Object.keys(query);
  if (method === "POST") return path === MANAGER_LOGIN_PATH && keys.length === 0;
  if (method !== "GET") return false;
  if (path === "/" || path === "/security/users/me/policies") return keys.length === 0;
  if (path === "/agents") return keys.every((k) => AGENTS_QUERY_KEYS[k]?.(query[k] ?? "") === true);
  return false;
}

/** The indexer paths that may be read with GET: the version, and the roles of the user itself. */
const INDEXER_GET_PATHS = new Set([
  "/",
  "/_plugins/_security/authinfo",
  "/_plugins/_security/api/permissionsinfo",
]);

/**
 * Method and path allow-list of the indexer client: GET of the three paths above, and POST of
 * `_search` and `_count` on the two indices the user reads. The body of a POST is built by the
 * templates below, never from input; the client has no way to take a body from anywhere else.
 */
export function isIndexerRequestAllowed(
  method: string,
  path: string,
  query: Record<string, string>,
): boolean {
  if (Object.keys(query).length > 0) return false;
  if (method === "GET") return INDEXER_GET_PATHS.has(path);
  if (method === "POST") {
    return Object.values(ADAPTERS).some(
      (a) =>
        path === `/${a.alertIndex}/_search` ||
        path === `/${a.alertIndex}/_count` ||
        path === `/${a.vulnerabilityIndex}/_search`,
    );
  }
  return false;
}

/* -------------------------------------------------------------------------- */
/* Query templates for the indexer                                              */
/* -------------------------------------------------------------------------- */

export const WINDOWS = ["24h", "7d", "30d"] as const;
export type Window = (typeof WINDOWS)[number];
export const WINDOW_RANGE: Record<Window, { from: string; previousFrom: string }> = {
  "24h": { from: "now-24h", previousFrom: "now-48h" },
  "7d": { from: "now-7d", previousFrom: "now-14d" },
  "30d": { from: "now-30d", previousFrom: "now-60d" },
};

/**
 * Rule groups that mark authentication failures and attacks. Their source addresses are kept for
 * the attack overview (a later item). The list is fixed code, not configuration.
 */
export const ATTACK_GROUPS = [
  "authentication_failed",
  "authentication_failures",
  "invalid_login",
  "attack",
  "attacks",
  "web_scan",
  "recon",
  "sql_injection",
  "exploit_attempt",
  "automatic_attack",
] as const;

/** The only questions that are ever put to the indexer. Every one takes at most an enumerated window. */
export type IndexerQuery =
  | { kind: "alertsReadable" }
  | { kind: "alertStats"; window: Window }
  | { kind: "alertStatsPrevious"; window: Window }
  | { kind: "fimLatest" }
  | { kind: "vulnerabilityStats" };

export interface IndexerRequest {
  method: "POST";
  path: string;
  body: Record<string, unknown>;
}

const range = (field: string, from: string, to?: string) => ({
  range: { [field]: { gte: from, ...(to ? { lt: to } : {}) } },
});

/** Builds the request for one question. Pure; the result is the only body the client can send. */
export function buildIndexerRequest(adapter: WazuhAdapter, query: IndexerQuery): IndexerRequest {
  if ("window" in query && !Object.hasOwn(WINDOW_RANGE, query.window)) throw new Error("Unknown window");
  const f = adapter.fields;
  const alerts = `/${adapter.alertIndex}`;
  const base = { size: 0, timeout: INDEXER_SEARCH_TIMEOUT };
  switch (query.kind) {
    case "alertsReadable":
      return {
        method: "POST",
        path: `${alerts}/_count`,
        body: { query: { bool: { filter: [range(f.timestamp, "now-24h")] } } },
      };
    case "alertStats": {
      const { from } = WINDOW_RANGE[query.window];
      return {
        method: "POST",
        path: `${alerts}/_search`,
        body: {
          ...base,
          track_total_hits: true,
          query: { bool: { filter: [range(f.timestamp, from, "now")] } },
          aggs: {
            levels: { terms: { field: f.level, size: 20 } },
            tactics: { terms: { field: f.tactic, size: MAX_TACTICS } },
            agents: {
              terms: { field: f.agentId, size: TOP_AGENTS },
              aggs: { name: { terms: { field: f.agentName, size: 1 } } },
            },
            fim: { filter: { term: { [f.groups]: "syscheck" } } },
            sources: {
              filter: {
                bool: {
                  filter: [{ terms: { [f.groups]: [...ATTACK_GROUPS] } }, { exists: { field: f.sourceIp } }],
                },
              },
              aggs: {
                ips: {
                  terms: { field: f.sourceIp, size: MAX_SOURCE_IPS },
                  aggs: {
                    groups: { terms: { field: f.groups, size: 12 } },
                    first: { min: { field: f.timestamp } },
                    last: { max: { field: f.timestamp } },
                    agents: {
                      terms: { field: f.agentId, size: MAX_AGENTS_PER_SOURCE },
                      aggs: { name: { terms: { field: f.agentName, size: 1 } } },
                    },
                  },
                },
              },
            },
            // All attack and authentication-failure alerts, with or without a source address (ADR 0016).
            attacks: {
              filter: { terms: { [f.groups]: [...ATTACK_GROUPS] } },
              aggs: {
                distinct: { cardinality: { field: f.sourceIp } },
                agents: {
                  terms: { field: f.agentId, size: TOP_AGENTS },
                  aggs: { name: { terms: { field: f.agentName, size: 1 } } },
                },
              },
            },
          },
        },
      };
    }
    case "alertStatsPrevious": {
      const { from, previousFrom } = WINDOW_RANGE[query.window];
      return {
        method: "POST",
        path: `${alerts}/_search`,
        body: {
          ...base,
          track_total_hits: true,
          query: { bool: { filter: [range(f.timestamp, previousFrom, from)] } },
          aggs: {
            levels: { terms: { field: f.level, size: 20 } },
            attacks: {
              filter: { terms: { [f.groups]: [...ATTACK_GROUPS] } },
              aggs: {
                distinct: { cardinality: { field: f.sourceIp } },
                ips: { terms: { field: f.sourceIp, size: MAX_SOURCE_IPS } },
              },
            },
          },
        },
      };
    }
    case "fimLatest":
      return {
        method: "POST",
        path: `${alerts}/_search`,
        body: {
          size: MAX_FIM_EVENTS,
          timeout: INDEXER_SEARCH_TIMEOUT,
          track_total_hits: false,
          sort: [{ [f.timestamp]: { order: "desc", unmapped_type: "date" } }],
          _source: [f.timestamp, f.agentId, f.agentName, f.fimPath, f.fimEvent, f.level],
          query: { bool: { filter: [range(f.timestamp, "now-7d"), { term: { [f.groups]: "syscheck" } }] } },
        },
      };
    case "vulnerabilityStats": {
      const v = adapter.vulnerabilityFields;
      return {
        method: "POST",
        path: `/${adapter.vulnerabilityIndex}/_search`,
        body: {
          ...base,
          track_total_hits: false,
          aggs: {
            agents: {
              terms: { field: v.agentId, size: MAX_AGENTS },
              aggs: { severity: { terms: { field: v.severity, size: 8 } } },
            },
          },
        },
      };
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Primitive parsers                                                           */
/* -------------------------------------------------------------------------- */

// Control characters, line and paragraph separators and bidirectional overrides (Trojan Source style tricks).
// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** Free text from Wazuh as plain text: control and bidirectional characters removed, trimmed, cut at `max`. */
export function clean(value: string, max: number): string {
  return value
    .replace(/[\t\r\n]+/g, " ")
    .replace(CONTROL, "")
    .trim()
    .slice(0, max);
}

const text = (max: number) =>
  z
    .string()
    .transform((v) => clean(v, max))
    .optional()
    .catch(undefined);

const asRecord = (v: unknown): Record<string, unknown> | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** A non-negative integer count, or 0. */
function count(v: unknown): number {
  const n = typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 1e12 ? Math.floor(n) : 0;
}

/** A date between 2000 and 2100; null for anything else (Wazuh uses far-future placeholders). */
function plausibleDate(v: unknown): Date | null {
  if (typeof v !== "string" && typeof v !== "number") return null;
  const d = new Date(v);
  const t = d.getTime();
  return Number.isFinite(t) && t >= 946_684_800_000 && t <= 4_102_444_800_000 ? d : null;
}

/** The `data` member of a manager API answer, or the answer itself if it has none. */
function dataOf(body: unknown): unknown {
  const rec = asRecord(body);
  return rec && "data" in rec ? rec.data : body;
}

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

/* -------------------------------------------------------------------------- */
/* Manager API                                                                 */
/* -------------------------------------------------------------------------- */

/** The token of `POST /security/user/authenticate`, or null if the answer has none. Kept in memory only. */
export function parseLoginToken(body: unknown): string | null {
  const data = asRecord(dataOf(body));
  const token = data?.token;
  return typeof token === "string" && /^[A-Za-z0-9._-]{20,8192}$/.test(token) ? token : null;
}

/** The version from `GET /` of the manager, or null if the answer is not the Wazuh API's. */
export function parseApiInfo(body: unknown): WazuhVersion | null {
  const data = asRecord(dataOf(body));
  if (!data || typeof data.api_version !== "string") return null;
  const m = /^v?(\d{1,3})\.(\d{1,3})(?:\.(\d{1,4}))?(?:[-+][A-Za-z0-9.+-]{0,20})?$/.exec(
    data.api_version.trim(),
  );
  if (!m) return null;
  const patch = m[3] ? `.${m[3]}` : "";
  return { version: `${m[1]}.${m[2]}${patch}`, major: Number(m[1]), minor: Number(m[2]) };
}

export const AGENT_STATUSES = ["active", "disconnected", "never_connected", "pending", "unknown"] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

export interface WazuhAgentInfo {
  agentId: string;
  name: string;
  ip: string | null;
  osName: string | null;
  osVersion: string | null;
  osPlatform: string | null;
  arch: string | null;
  version: string | null;
  status: AgentStatus;
  lastKeepAliveAt: Date | null;
  groups: string[];
  registeredAt: Date | null;
  /** Agent 000 is the manager itself. */
  isManager: boolean;
}

const agentItem = z.object({
  id: z.string().regex(/^\d{1,8}$/),
  name: text(128),
  ip: text(64),
  registerIP: text(64),
  os: z
    .object({ name: text(80), version: text(80), platform: text(40), arch: text(30) })
    .optional()
    .catch(undefined),
  version: text(40),
  status: text(30),
  lastKeepAlive: z.string().optional().catch(undefined),
  group: z.array(z.unknown()).optional().catch(undefined),
  dateAdd: z.string().optional().catch(undefined),
});

const GROUP_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const orNull = (v: string | undefined) => (v ? v : null);

export function parseAgents(body: unknown): { items: WazuhAgentInfo[]; dropped: number; total: number } {
  const data = asRecord(dataOf(body));
  const { items, dropped } = parseList(agentItem, data?.affected_items, AGENTS_PAGE_SIZE);
  const ipOf = (a: (typeof items)[number]) =>
    a.ip && isIP(a.ip) ? a.ip : a.registerIP && isIP(a.registerIP) ? a.registerIP : null;
  return {
    items: items.map((a) => {
      const status = (AGENT_STATUSES as readonly string[]).includes(a.status ?? "")
        ? (a.status as AgentStatus)
        : "unknown";
      return {
        agentId: a.id,
        name: a.name || (a.id === "000" ? "manager" : `agent-${a.id}`),
        ip: ipOf(a),
        osName: orNull(a.os?.name),
        osVersion: orNull(a.os?.version),
        osPlatform: orNull(a.os?.platform),
        arch: orNull(a.os?.arch),
        version: a.version ? a.version.replace(/^Wazuh\s+v?/i, "") : null,
        status,
        lastKeepAliveAt: plausibleDate(a.lastKeepAlive),
        groups: (a.group ?? [])
          .filter((g): g is string => typeof g === "string" && GROUP_NAME.test(g))
          .slice(0, MAX_GROUPS_PER_AGENT),
        registeredAt: plausibleDate(a.dateAdd),
        isManager: a.id === "000" || /^0+$/.test(a.id),
      };
    }),
    dropped,
    total: count(data?.total_affected_items),
  };
}

/* -------------------------------------------------------------------------- */
/* Privileges of the two service users                                         */
/* -------------------------------------------------------------------------- */

/** Verbs of a Wazuh RBAC action that only read. Everything else is a privilege beyond reading. */
const READ_VERBS = new Set(["read", "status"]);

/**
 * The RBAC actions of the API user (from `GET /security/users/me/policies`) that are not reads,
 * for example `agent:restart`, `security:create` or `*:*`, prefixed with `api:`. The answer is a
 * map from action to resources to `allow`/`deny`; an action counts when at least one resource is
 * allowed. Returns null when the answer is not in that shape, because "unknown" must never be
 * treated as "nothing extra" (the sync then stops).
 */
export function extraManagerPrivileges(body: unknown): string[] | null {
  const data = asRecord(dataOf(body));
  if (!data) return null;
  const extra = new Set<string>();
  for (const [action, resources] of Object.entries(data)) {
    const rec = asRecord(resources);
    if (!rec) return null;
    const allowed = Object.values(rec).some((effect) => effect === "allow");
    if (!allowed) continue;
    const verb = action.split(":").slice(1).join(":");
    if (action.includes("*") || !READ_VERBS.has(verb)) extra.add(`api:${clean(action, 80)}`);
  }
  return [...extra].sort().slice(0, 100);
}

/**
 * Roles of the indexer user that are known to be administrative. GarnetOps can see the role names
 * of the user (not what a custom role allows), so it flags the built-in powerful roles and access
 * to the security REST API. A custom role with write access is not detected; the documentation
 * says so and gives the exact role to use.
 */
export const POWERFUL_INDEXER_ROLES = [
  "all_access",
  "security_manager",
  "manage_snapshots",
  "cluster_manager",
  "kibana_server",
  "wazuh_ui_admin",
  "wazuh_admin",
  "admin",
] as const;

export function extraIndexerPrivileges(authinfo: unknown, permissions: unknown | null): string[] | null {
  const info = asRecord(authinfo);
  if (!info || !Array.isArray(info.roles)) return null;
  const extra = new Set<string>();
  for (const role of info.roles) {
    if (typeof role !== "string") continue;
    if ((POWERFUL_INDEXER_ROLES as readonly string[]).includes(role.toLowerCase())) {
      extra.add(`indexer:role:${clean(role, 60)}`);
    }
  }
  const perms = asRecord(permissions);
  if (perms?.has_api_access === true) extra.add("indexer:security-api");
  return [...extra].sort().slice(0, 100);
}

/** Whether every extra privilege found is covered by what an admin acknowledged. */
export function privilegesAcknowledged(extra: readonly string[], acknowledged: readonly string[]): boolean {
  const known = new Set(acknowledged);
  return extra.every((p) => known.has(p));
}

/* -------------------------------------------------------------------------- */
/* Indexer                                                                     */
/* -------------------------------------------------------------------------- */

/** The version of the indexer from `GET /`, or null if the answer is not an OpenSearch-style indexer's. */
export function parseIndexerInfo(body: unknown): string | null {
  const rec = asRecord(body);
  const version = asRecord(rec?.version);
  if (!rec || !version || typeof version.number !== "string") return null;
  const looksLikeIndexer =
    typeof rec.cluster_name === "string" ||
    (typeof rec.tagline === "string" && /opensearch/i.test(rec.tagline));
  if (!looksLikeIndexer) return null;
  const v = clean(version.number, 30);
  return /^\d+(?:\.\d+){0,3}(?:[-+.][A-Za-z0-9.+-]*)?$/.test(v) ? v : null;
}

export interface NamedCount {
  name: string;
  count: number;
}
export interface AgentCount {
  agentId: string;
  name: string;
  count: number;
}
export interface SourceIp {
  ip: string;
  count: number;
  groups: string[];
  /** Time of the first and the last alert in the window; null if the indexer did not say. */
  firstSeen: Date | null;
  lastSeen: Date | null;
  /** The agents that were targeted most by this address (at most 5). */
  agents: AgentCount[];
}
/** All attack and authentication-failure alerts of a window (ADR 0016). */
export interface AttackStats {
  alerts: number;
  /** Distinct source addresses, approximate (the indexer's cardinality aggregation). */
  distinctSources: number;
  agents: AgentCount[];
}
export interface PreviousAttackStats {
  alerts: number;
  distinctSources: number;
  /** Source addresses of the previous period with their alert counts, for the change in countries. */
  sources: { ip: string; count: number }[];
}
export interface WindowStats {
  total: number;
  bySeverity: SeverityCounts;
  tactics: NamedCount[];
  agents: AgentCount[];
  fim: number;
  sources: SourceIp[];
  /** Null when the answer has no `attacks` aggregation (an older query or a role that cannot read it). */
  attack: AttackStats | null;
}

const buckets = (agg: unknown): unknown[] => {
  const list = asRecord(agg)?.buckets;
  return Array.isArray(list) ? list : [];
};

function severityCounts(agg: unknown): SeverityCounts {
  const counts = emptyCounts();
  for (const b of buckets(agg)) {
    const rec = asRecord(b);
    if (!rec) continue;
    const level = typeof rec.key === "number" ? rec.key : Number(rec.key);
    const severity = severityForLevel(level > 15 ? 15 : level);
    if (severity) counts[severity] += count(rec.doc_count);
  }
  return counts;
}

function total(body: unknown): number {
  const hits = asRecord(asRecord(body)?.hits);
  const t = hits?.total;
  return count(typeof t === "number" ? t : asRecord(t)?.value);
}

const TACTIC = /^[\p{L}\p{N} _&'./-]{1,60}$/u;
const RULE_GROUP = /^[A-Za-z0-9._-]{1,60}$/;

/** Alert aggregations of one window. Null when the answer has no aggregations at all (an error or another index). */
export function parseAlertStats(body: unknown): WindowStats | null {
  const aggs = asRecord(asRecord(body)?.aggregations);
  if (!aggs || !asRecord(aggs.levels)) return null;
  const tactics: NamedCount[] = [];
  for (const b of buckets(aggs.tactics)) {
    const rec = asRecord(b);
    const name = typeof rec?.key === "string" ? clean(rec.key, 60) : "";
    if (rec && name && TACTIC.test(name)) tactics.push({ name, count: count(rec.doc_count) });
  }
  const agents = agentBuckets(aggs.agents, TOP_AGENTS);
  const sources: SourceIp[] = [];
  const sourceAgg = asRecord(aggs.sources);
  for (const b of buckets(sourceAgg?.ips)) {
    const rec = asRecord(b);
    const ip = typeof rec?.key === "string" ? rec.key.trim() : "";
    if (!rec || !isIP(ip)) continue;
    const groups: string[] = [];
    for (const g of buckets(rec.groups)) {
      const key = asRecord(g)?.key;
      if (
        typeof key === "string" &&
        RULE_GROUP.test(key) &&
        (ATTACK_GROUPS as readonly string[]).includes(key)
      ) {
        groups.push(key);
      }
    }
    sources.push({
      ip,
      count: count(rec.doc_count),
      groups: groups.slice(0, MAX_GROUPS_PER_SOURCE),
      firstSeen: plausibleDate(asRecord(rec.first)?.value),
      lastSeen: plausibleDate(asRecord(rec.last)?.value),
      agents: agentBuckets(rec.agents, MAX_AGENTS_PER_SOURCE),
    });
  }
  const attacks = asRecord(aggs.attacks);
  return {
    total: total(body),
    bySeverity: severityCounts(aggs.levels),
    tactics: tactics.slice(0, MAX_TACTICS),
    agents,
    fim: count(asRecord(aggs.fim)?.doc_count),
    sources: sources.slice(0, MAX_SOURCE_IPS),
    attack: attacks
      ? {
          alerts: count(attacks.doc_count),
          distinctSources: count(asRecord(attacks.distinct)?.value),
          agents: agentBuckets(attacks.agents, TOP_AGENTS),
        }
      : null,
  };
}

/** Agent buckets (`agent.id` with the first `agent.name`): invalid ids are dropped, names are cleaned and cut. */
function agentBuckets(agg: unknown, cap: number): AgentCount[] {
  const out: AgentCount[] = [];
  for (const b of buckets(agg)) {
    const rec = asRecord(b);
    const id = String(rec?.key ?? "");
    if (!rec || !/^\d{1,8}$/.test(id)) continue;
    const nameKey = asRecord(buckets(rec.name)[0])?.key;
    out.push({
      agentId: id,
      name: typeof nameKey === "string" && clean(nameKey, 128) ? clean(nameKey, 128) : `agent-${id}`,
      count: count(rec.doc_count),
    });
  }
  return out.slice(0, cap);
}

/** The previous period of a window: the counts by severity and, for the attack overview, its attack numbers. */
export function parsePreviousStats(
  body: unknown,
): { total: number; bySeverity: SeverityCounts; attack: PreviousAttackStats | null } | null {
  const aggs = asRecord(asRecord(body)?.aggregations);
  if (!aggs || !asRecord(aggs.levels)) return null;
  const attacks = asRecord(aggs.attacks);
  let attack: PreviousAttackStats | null = null;
  if (attacks) {
    const sources: { ip: string; count: number }[] = [];
    for (const b of buckets(asRecord(attacks.ips))) {
      const rec = asRecord(b);
      const ip = typeof rec?.key === "string" ? rec.key.trim() : "";
      if (rec && isIP(ip)) sources.push({ ip, count: count(rec.doc_count) });
    }
    attack = {
      alerts: count(attacks.doc_count),
      distinctSources: count(asRecord(attacks.distinct)?.value),
      sources: sources.slice(0, MAX_SOURCE_IPS),
    };
  }
  return { total: total(body), bySeverity: severityCounts(aggs.levels), attack };
}

export interface FimEvent {
  at: Date;
  agentId: string;
  agentName: string;
  /** Plain text. Attacker controlled: never a link, never HTML, never sent to the model. */
  path: string;
  event: "added" | "modified" | "deleted" | "other";
  level: number | null;
}

const nested = (source: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((o, k) => asRecord(o)?.[k], source);

/**
 * The latest file integrity events. Documents may carry their fields nested (`syscheck.path` as
 * `{syscheck: {path}}`) or flat; both are read. Events without a valid time or path are dropped.
 */
export function parseFimEvents(body: unknown, adapter: WazuhAdapter): FimEvent[] {
  const hits = asRecord(asRecord(body)?.hits)?.hits;
  if (!Array.isArray(hits)) return [];
  const f = adapter.fields;
  const out: FimEvent[] = [];
  for (const hit of hits.slice(0, MAX_FIM_EVENTS)) {
    const source = asRecord(asRecord(hit)?._source);
    if (!source) continue;
    const pick = (field: string) => (field in source ? source[field] : nested(source, field));
    const at = plausibleDate(pick(f.timestamp));
    const rawPath = pick(f.fimPath);
    const path = typeof rawPath === "string" ? clean(rawPath, 500) : "";
    if (!at || !path) continue;
    const id = String(pick(f.agentId) ?? "");
    const name = pick(f.agentName);
    const event = pick(f.fimEvent);
    const level = Number(pick(f.level));
    out.push({
      at,
      agentId: /^\d{1,8}$/.test(id) ? id : "",
      agentName: typeof name === "string" && clean(name, 128) ? clean(name, 128) : "",
      path,
      event: event === "added" || event === "modified" || event === "deleted" ? event : "other",
      level: Number.isFinite(level) && level >= 0 && level <= 15 ? Math.floor(level) : null,
    });
  }
  return out;
}

/** Vulnerability states per agent id, by severity. Null when the answer has no aggregation. */
export function parseVulnerabilityStats(body: unknown): Map<string, SeverityCounts> | null {
  const aggs = asRecord(asRecord(body)?.aggregations);
  if (!aggs || !asRecord(aggs.agents)) return null;
  const result = new Map<string, SeverityCounts>();
  for (const b of buckets(aggs.agents)) {
    const rec = asRecord(b);
    const id = String(rec?.key ?? "");
    if (!rec || !/^\d{1,8}$/.test(id)) continue;
    const counts = emptyCounts();
    for (const s of buckets(rec.severity)) {
      const sr = asRecord(s);
      const key = typeof sr?.key === "string" ? sr.key.toLowerCase() : "";
      if ((SEVERITIES as readonly string[]).includes(key)) counts[key as Severity] += count(sr?.doc_count);
    }
    result.set(id, counts);
  }
  return result;
}

/* -------------------------------------------------------------------------- */
/* What is stored: the snapshot                                                */
/* -------------------------------------------------------------------------- */

export interface WindowSnapshot {
  /** When the indexer was asked (ISO time). Older than the last sync means this window could not be read since. */
  readAt: string;
  total: number;
  bySeverity: SeverityCounts;
  /** The period of the same length before this one; null if it could not be read. */
  previous: { total: number; bySeverity: SeverityCounts } | null;
  tactics: NamedCount[];
  agents: AgentCount[];
  fim: number;
}

export interface Snapshot {
  windows: Partial<Record<Window, WindowSnapshot>>;
  /** Vulnerability states from the indexer, summed over the agents; null if not readable. */
  vulnerabilities: (SeverityCounts & { agentsAffected: number; readAt: string }) | null;
}

const countsSchema = z.object({
  critical: z.number().int().nonnegative().catch(0),
  high: z.number().int().nonnegative().catch(0),
  medium: z.number().int().nonnegative().catch(0),
  low: z.number().int().nonnegative().catch(0),
});
const windowSchema = z.object({
  readAt: z.string().catch(""),
  total: z.number().int().nonnegative().catch(0),
  bySeverity: countsSchema,
  previous: z
    .object({ total: z.number().int().nonnegative().catch(0), bySeverity: countsSchema })
    .nullable()
    .catch(null),
  tactics: z.array(z.object({ name: z.string(), count: z.number().int().nonnegative() })).catch([]),
  agents: z
    .array(z.object({ agentId: z.string(), name: z.string(), count: z.number().int().nonnegative() }))
    .catch([]),
  fim: z.number().int().nonnegative().catch(0),
});
export const snapshotSchema = z.object({
  windows: z.object({
    "24h": windowSchema.optional().catch(undefined),
    "7d": windowSchema.optional().catch(undefined),
    "30d": windowSchema.optional().catch(undefined),
  }),
  vulnerabilities: countsSchema
    .extend({ agentsAffected: z.number().int().nonnegative().catch(0), readAt: z.string().catch("") })
    .nullable()
    .catch(null),
});

/** Reads a stored snapshot defensively; an unknown or damaged value is an empty snapshot. */
export function readSnapshot(value: unknown): Snapshot {
  const r = snapshotSchema.safeParse(value);
  return r.success ? r.data : { windows: {}, vulnerabilities: null };
}

/** Sums the per-agent vulnerability counts of an indexer answer. */
export function sumVulnerabilities(
  perAgent: Map<string, SeverityCounts>,
  readAt: string,
): NonNullable<Snapshot["vulnerabilities"]> {
  const sum = emptyCounts();
  let affected = 0;
  for (const c of perAgent.values()) {
    let any = false;
    for (const s of SEVERITIES) {
      sum[s] += c[s];
      if (c[s] > 0) any = true;
    }
    if (any) affected++;
  }
  return { ...sum, agentsAffected: affected, readAt };
}

/* -------------------------------------------------------------------------- */
/* Linking agents to servers                                                   */
/* -------------------------------------------------------------------------- */

export interface HostCandidate {
  id: string;
  name: string;
  address: string;
}

export type SuggestionReason = "address" | "name" | "hostname";

const shortName = (name: string) => name.toLowerCase().split(".")[0] ?? "";

/**
 * Suggests the existing server that is probably the machine behind an agent: the same address,
 * the same name, or the same host name without domain. Only an unambiguous match is suggested
 * (two servers with the same short name suggest nothing), and an admin confirms every link.
 * Servers that are linked to another agent already are not candidates.
 */
export function suggestHost(
  agent: Pick<WazuhAgentInfo, "name" | "ip" | "isManager">,
  hosts: readonly HostCandidate[],
): { hostId: string; reason: SuggestionReason } | null {
  if (agent.isManager) return null;
  const pick = (matches: HostCandidate[], reason: SuggestionReason) =>
    matches.length === 1 && matches[0] ? { hostId: matches[0].id, reason } : null;
  if (agent.ip) {
    const found = pick(
      hosts.filter((h) => h.address === agent.ip),
      "address",
    );
    if (found) return found;
  }
  const lower = agent.name.toLowerCase();
  const exact = pick(
    hosts.filter((h) => h.name.toLowerCase() === lower),
    "name",
  );
  if (exact) return exact;
  const short = shortName(agent.name);
  if (short.length < 2) return null;
  return pick(
    hosts.filter((h) => shortName(h.name) === short),
    "hostname",
  );
}

/** `connectionId:agentId`, the `source_ref` of a server created from an agent (`host.source = "wazuh"`). */
export const wazuhSourceRef = (connectionId: string, agentId: string) => `${connectionId}:${agentId}`;

export function parseWazuhSourceRef(value: string): { connectionId: string; agentId: string } | null {
  const m = /^([a-z]{2,6}_[A-Za-z0-9]{8,40}):(\d{1,8})$/.exec(value);
  return m ? { connectionId: m[1] as string, agentId: m[2] as string } : null;
}
