/**
 * Proxmox VE (ADR 0012): validation of what an admin types, the paths the client may read,
 * the privilege check of the API token, and defensive parsers for every answer of the REST API.
 *
 * Everything Proxmox returns is hostile input: the parsers read only the fields they know,
 * check every field against a pattern or a range, cap every size and count, and drop what does
 * not fit instead of failing the whole sync. Free text of the guests (descriptions, notes,
 * cloud-init data) is never read at all. Nothing here executes, evaluates or interpolates
 * what Proxmox sent.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { checkHostAddress } from "./hosts.ts";
import { isForbiddenAddress } from "./notifications.ts";
import type { GuestStatus } from "./proxmox-flags.ts";

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

export const PROXMOX_DEFAULT_PORT = 8006;
/** Connections per organisation. */
export const MAX_PROXMOX_CLUSTERS = 10;
/** Guests kept per cluster; more are ignored and the sync says so. */
export const MAX_GUESTS_PER_CLUSTER = 2000;
export const MAX_NODES_PER_CLUSTER = 100;
export const MAX_STORAGES_PER_CLUSTER = 500;
/** An answer larger than this is refused (the biggest normal answers are well below 1 MB). */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const CONNECT_TIMEOUT_MS = 10_000;
export const REQUEST_TIMEOUT_MS = 20_000;
/** Pause between two requests: a sync is sequential and polite. */
export const REQUEST_GAP_MS = 25;
/** A sync stops after this many requests ... */
export const MAX_REQUESTS_PER_SYNC = 6000;
/** ... or this long. */
export const SYNC_BUDGET_MINUTES = 10;

/* -------------------------------------------------------------------------- */
/* What an admin types                                                         */
/* -------------------------------------------------------------------------- */

export type UrlProblem = "empty" | "tooLong" | "invalid" | "notHttps" | "credentials" | "path" | "address";
export type UrlCheck =
  | { ok: true; url: string; host: string; port: number }
  | { ok: false; problem: UrlProblem };

/**
 * Checks and normalises the API address of a Proxmox server: `https://host[:port]`, nothing
 * else. Plain http, user names, paths, queries and fragments are refused; the host goes
 * through the same checks as a server address (no loopback, link-local or metadata addresses,
 * no numeric tricks such as `127.1`). The port defaults to 8006.
 */
export function checkProxmoxUrl(value: string): UrlCheck {
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
  const port = url.port ? Number(url.port) : PROXMOX_DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, problem: "invalid" };
  const shown = address.kind === "ipv6" ? `[${address.address}]` : address.address;
  return { ok: true, url: `https://${shown}:${port}`, host: address.address, port };
}

export type TokenIdProblem = "invalid" | "root";

/**
 * An API token ID as Proxmox writes it: `user@realm!tokenid`. Tokens of `root@…` are refused
 * on purpose: GarnetOps needs a dedicated user with the role PVEAuditor, never the
 * administrator (ADR 0012).
 */
export function checkTokenId(
  value: string,
): { ok: true; value: string } | { ok: false; problem: TokenIdProblem } {
  const id = value.trim();
  if (!/^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z0-9._-]{2,64}$/.test(id)) {
    return { ok: false, problem: "invalid" };
  }
  if (/^root@/i.test(id)) return { ok: false, problem: "root" };
  return { ok: true, value: id };
}

/** The secret of a token: printable ASCII without blanks. Proxmox issues a UUID; we are not stricter than needed. */
export const TOKEN_SECRET_PATTERN = /^[\x21-\x7e]{8,200}$/;

/** A display name: printable text, 1 to 80 characters. */
export function checkClusterName(value: string): string | null {
  const name = value.trim();
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (name.length === 0 || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return null;
  return name;
}

/* -------------------------------------------------------------------------- */
/* Certificates                                                                */
/* -------------------------------------------------------------------------- */

/** SHA-256 of a DER certificate as Proxmox and browsers show it: upper-case hex pairs separated by colons. */
export function certificateFingerprint(der: Uint8Array): string {
  return (createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g) as string[]).join(":");
}

export const FINGERPRINT_PATTERN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

/** Upper-cases a fingerprint an admin or an API client sent; null if it is not SHA-256 in colon form. */
export function normalizeFingerprint(value: string): string | null {
  const f = value.trim().toUpperCase();
  return FINGERPRINT_PATTERN.test(f) ? f : null;
}

/** Subject or issuer of a certificate on one line, without control characters, at most 300 characters. */
export function certificateName(value: string | undefined): string {
  return clean(value ?? "", 300).replace(/\s*\n\s*/g, ", ");
}

/* -------------------------------------------------------------------------- */
/* Paths the client may read                                                   */
/* -------------------------------------------------------------------------- */

const NODE = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})";
const VMID = "[1-9][0-9]{0,8}";
const STORAGE = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}";

/**
 * Every path the integration reads, and nothing else (ADR 0012). The HTTP client refuses any
 * other path, so a bug elsewhere cannot make it call something that changes state or reads
 * more than the inventory. `/access/permissions` is the token's own permissions, read to
 * warn about a token that can do more than read.
 */
export const READ_PATHS: readonly RegExp[] = [
  /^\/version$/,
  /^\/cluster\/status$/,
  /^\/cluster\/resources$/,
  /^\/cluster\/ha\/resources$/,
  /^\/cluster\/backup$/,
  /^\/access\/permissions$/,
  new RegExp(`^/nodes/${NODE}/status$`),
  new RegExp(`^/nodes/${NODE}/apt/update$`),
  new RegExp(`^/nodes/${NODE}/(?:qemu|lxc)/${VMID}/(?:config|snapshot)$`),
  new RegExp(`^/nodes/${NODE}/qemu/${VMID}/agent/network-get-interfaces$`),
  new RegExp(`^/nodes/${NODE}/lxc/${VMID}/interfaces$`),
  new RegExp(`^/nodes/${NODE}/storage/${STORAGE}/content$`),
];

/** The only query the client sends: the backup listing of a storage. */
export const READ_QUERIES: Record<string, string> = { content: "backup" };

export const isReadPath = (path: string) => READ_PATHS.some((p) => p.test(path));

export const isNodeName = (value: string) => new RegExp(`^${NODE}$`).test(value);
export const isStorageName = (value: string) => new RegExp(`^${STORAGE}$`).test(value);

/* -------------------------------------------------------------------------- */
/* Primitive parsers                                                           */
/* -------------------------------------------------------------------------- */

// Control characters, line and paragraph separators and bidirectional overrides (Trojan Source style tricks).
// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** Free text from Proxmox as safe plain text: control characters removed, trimmed, cut at `max`. */
function clean(value: string, max: number): string {
  return value.replace(CONTROL, "").trim().slice(0, max);
}

const text = (max: number) =>
  z
    .string()
    .transform((v) => clean(v, max))
    .optional()
    .catch(undefined);

/** Numbers arrive as numbers or as digit strings. */
const num = z
  .preprocess(
    (v) => (typeof v === "string" && v.trim() !== "" ? Number(v) : v),
    z.number().finite().min(0).max(1e18),
  )
  .optional()
  .catch(undefined);

/** Booleans arrive as 0/1, "0"/"1" or true/false. */
const flag = z
  .preprocess(
    (v) => (v === "1" || v === 1 || v === true ? true : v === "0" || v === 0 || v === false ? false : v),
    z.boolean(),
  )
  .optional()
  .catch(undefined);

/** `{ "data": ... }` is the envelope of every answer. */
export function unwrap(body: unknown): unknown {
  if (body && typeof body === "object" && !Array.isArray(body) && "data" in body) {
    return (body as { data: unknown }).data;
  }
  throw new Error("no data member");
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

const asRecord = (v: unknown): Record<string, unknown> | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

const vmidOf = (v: unknown): number | null => {
  const n = typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 999_999_999 ? n : null;
};

/** Seconds since 1970 as a date; null for anything that is not a plausible time. */
function epoch(v: unknown): Date | null {
  const n = typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  if (typeof n !== "number" || !Number.isFinite(n) || n < 946_684_800 || n > 4_102_444_800) return null;
  return new Date(n * 1000);
}

/* -------------------------------------------------------------------------- */
/* /version, /cluster/status                                                   */
/* -------------------------------------------------------------------------- */

/** The product version from `/version`, or null if the answer is not Proxmox VE's. */
export function parseVersion(data: unknown): string | null {
  const r = z.object({ version: z.string() }).safeParse(data);
  if (!r.success) return null;
  const v = clean(r.data.version, 40);
  return /^\d+(?:\.\d+){0,3}(?:[-+~.][A-Za-z0-9.+~-]*)?$/.test(v) ? v : null;
}

export interface ClusterStatus {
  /** Cluster name; null for a stand-alone node. */
  name: string | null;
  quorate: boolean | null;
  /** Node name to online state, as the cluster reports it. */
  nodes: Map<string, boolean>;
}

const statusItem = z.object({
  type: z.string(),
  name: text(80),
  online: flag,
  quorate: flag,
});

export function parseClusterStatus(data: unknown): ClusterStatus {
  const { items } = parseList(statusItem, data, 500);
  const cluster = items.find((i) => i.type === "cluster");
  const nodes = new Map<string, boolean>();
  for (const item of items) {
    if (item.type === "node" && item.name && isNodeName(item.name)) nodes.set(item.name, item.online ?? true);
  }
  return {
    name: cluster?.name || null,
    quorate: cluster ? (cluster.quorate ?? null) : null,
    nodes,
  };
}

/* -------------------------------------------------------------------------- */
/* /cluster/resources                                                          */
/* -------------------------------------------------------------------------- */

export interface PxNode {
  name: string;
  online: boolean;
  cpu: number | null;
  cpus: number | null;
  mem: number | null;
  maxMem: number | null;
  disk: number | null;
  maxDisk: number | null;
  uptime: number | null;
}

export interface PxGuest {
  vmid: number;
  type: "qemu" | "lxc";
  name: string;
  node: string;
  status: GuestStatus;
  cpu: number | null;
  cpus: number | null;
  mem: number | null;
  maxMem: number | null;
  disk: number | null;
  maxDisk: number | null;
  uptime: number | null;
  template: boolean;
  tags: string[];
  pool: string | null;
  /** The HA state Proxmox reports on the resource; the HA resource list refines it. */
  haState: string | null;
}

export interface PxStorage {
  name: string;
  node: string;
  type: string | null;
  content: string[];
  shared: boolean;
  status: string | null;
  used: number | null;
  total: number | null;
}

const resourceItem = z.object({
  type: z.string(),
  node: text(63),
  vmid: z.unknown().optional(),
  name: text(120),
  status: text(30),
  cpu: num,
  maxcpu: num,
  mem: num,
  maxmem: num,
  disk: num,
  maxdisk: num,
  uptime: num,
  template: flag,
  tags: text(400),
  pool: text(64),
  hastate: text(30),
  storage: text(64),
  plugintype: text(30),
  content: text(200),
  shared: flag,
});

const GUEST_STATUS: Record<string, GuestStatus> = {
  running: "running",
  stopped: "stopped",
  paused: "paused",
  suspended: "paused",
};

/** Splits Proxmox's tag list (`a;b`, older versions `a,b`) into at most 20 short, plain tags. */
export function parseTags(value: string | undefined): string[] {
  if (!value) return [];
  const tags = value
    .split(/[;,\s]+/)
    .map((t) => clean(t, 40))
    .filter((t) => /^[\p{L}\p{N}][\p{L}\p{N}._+-]*$/u.test(t));
  return [...new Set(tags)].slice(0, 20);
}

export function parseResources(data: unknown): {
  nodes: PxNode[];
  guests: PxGuest[];
  storages: PxStorage[];
  dropped: number;
  guestsTruncated: boolean;
} {
  const { items, dropped: bad } = parseList(resourceItem, data, MAX_GUESTS_PER_CLUSTER * 2 + 700);
  const nodes: PxNode[] = [];
  const guests: PxGuest[] = [];
  const storages: PxStorage[] = [];
  let dropped = bad;
  let guestsTruncated = false;
  for (const r of items) {
    if (r.type === "node") {
      if (!r.node || !isNodeName(r.node) || nodes.length >= MAX_NODES_PER_CLUSTER) {
        dropped++;
        continue;
      }
      nodes.push({
        name: r.node,
        online: r.status === "online",
        cpu: r.cpu ?? null,
        cpus: r.maxcpu ?? null,
        mem: r.mem ?? null,
        maxMem: r.maxmem ?? null,
        disk: r.disk ?? null,
        maxDisk: r.maxdisk ?? null,
        uptime: r.uptime ?? null,
      });
    } else if (r.type === "qemu" || r.type === "lxc") {
      const vmid = vmidOf(r.vmid);
      if (vmid === null || !r.node || !isNodeName(r.node)) {
        dropped++;
        continue;
      }
      if (guests.length >= MAX_GUESTS_PER_CLUSTER) {
        guestsTruncated = true;
        continue;
      }
      guests.push({
        vmid,
        type: r.type,
        name: r.name || `${r.type === "qemu" ? "VM" : "CT"} ${vmid}`,
        node: r.node,
        status: GUEST_STATUS[r.status ?? ""] ?? "other",
        cpu: r.cpu ?? null,
        cpus: r.maxcpu ?? null,
        mem: r.mem ?? null,
        maxMem: r.maxmem ?? null,
        disk: r.disk ?? null,
        maxDisk: r.maxdisk ?? null,
        uptime: r.uptime ?? null,
        template: r.template ?? false,
        tags: parseTags(r.tags),
        pool: r.pool && /^[A-Za-z0-9_.-]{1,64}$/.test(r.pool) ? r.pool : null,
        haState: r.hastate && /^[a-z_-]{1,30}$/.test(r.hastate) ? r.hastate : null,
      });
    } else if (r.type === "storage") {
      if (!r.storage || !isStorageName(r.storage) || !r.node || !isNodeName(r.node)) {
        dropped++;
        continue;
      }
      if (storages.length >= MAX_STORAGES_PER_CLUSTER) {
        dropped++;
        continue;
      }
      storages.push({
        name: r.storage,
        node: r.node,
        type: r.plugintype && /^[a-z0-9_-]{1,30}$/.test(r.plugintype) ? r.plugintype : null,
        content: (r.content ?? "")
          .split(",")
          .map((c) => c.trim())
          .filter((c) => /^[a-z0-9_-]{1,20}$/.test(c))
          .slice(0, 10),
        shared: r.shared ?? false,
        status: r.status && /^[a-z]{1,20}$/.test(r.status) ? r.status : null,
        used: r.disk ?? null,
        total: r.maxdisk ?? null,
      });
    }
    // Pools, SDN zones and everything else are not read.
  }
  // Guests of the same id twice (a migration in flight) keep the first entry.
  const seen = new Set<number>();
  const unique: PxGuest[] = [];
  for (const guest of guests) {
    if (seen.has(guest.vmid)) continue;
    seen.add(guest.vmid);
    unique.push(guest);
  }
  return { nodes, guests: unique, storages, dropped, guestsTruncated };
}

/* -------------------------------------------------------------------------- */
/* Node status and pending updates                                             */
/* -------------------------------------------------------------------------- */

export interface PxNodeStatus {
  cpu: number | null;
  cpus: number | null;
  mem: number | null;
  maxMem: number | null;
  rootUsed: number | null;
  rootTotal: number | null;
  uptime: number | null;
  /** Proxmox VE version of the node, e.g. `8.2.4`. */
  pveVersion: string | null;
  kernel: string | null;
}

export function parseNodeStatus(data: unknown): PxNodeStatus | null {
  const r = z
    .object({
      cpu: num,
      uptime: num,
      memory: z.object({ used: num, total: num }).optional().catch(undefined),
      rootfs: z.object({ used: num, total: num }).optional().catch(undefined),
      cpuinfo: z.object({ cpus: num }).optional().catch(undefined),
      pveversion: text(120),
      kversion: text(160),
    })
    .safeParse(data);
  if (!r.success) return null;
  const d = r.data;
  const pve = /^pve-manager\/(\d+(?:\.\d+){0,3})(?:[-+~][\w.+~-]*)?(?:\/|$)/.exec(d.pveversion ?? "")?.[1];
  return {
    cpu: d.cpu ?? null,
    cpus: d.cpuinfo?.cpus ?? null,
    mem: d.memory?.used ?? null,
    maxMem: d.memory?.total ?? null,
    rootUsed: d.rootfs?.used ?? null,
    rootTotal: d.rootfs?.total ?? null,
    uptime: d.uptime ?? null,
    pveVersion: pve ?? null,
    kernel: d.kversion ? d.kversion.replace(/^Linux\s+/, "").split(/\s+#/)[0] || null : null,
  };
}

/** Number of packages a node's last `apt update` found upgradable; null if the answer is not a list. */
export function parseAptUpdates(data: unknown): number | null {
  if (!Array.isArray(data)) return null;
  return Math.min(data.length, 100_000);
}

/* -------------------------------------------------------------------------- */
/* HA, backup jobs, backups                                                    */
/* -------------------------------------------------------------------------- */

/** HA state by guest id, from `/cluster/ha/resources` (`sid` is `vm:100` or `ct:101`). */
export function parseHaResources(data: unknown): Map<number, string> {
  const { items } = parseList(z.object({ sid: text(40), state: text(30) }), data, 5000);
  const map = new Map<number, string>();
  for (const i of items) {
    const m = /^(?:vm|ct):(\d{1,9})$/.exec(i.sid ?? "");
    const vmid = m ? vmidOf(m[1]) : null;
    if (vmid !== null && i.state && /^[a-z_-]{1,30}$/.test(i.state)) map.set(vmid, i.state);
  }
  return map;
}

export interface BackupJob {
  enabled: boolean;
  all: boolean;
  vmids: Set<number>;
  exclude: Set<number>;
  pool: string | null;
}

const idList = (v: string | undefined): Set<number> =>
  new Set(
    (v ?? "")
      .split(",")
      .map((x) => vmidOf(x.trim()))
      .filter((x): x is number => x !== null),
  );

export function parseBackupJobs(data: unknown): BackupJob[] {
  const { items } = parseList(
    z.object({ enabled: flag, all: flag, vmid: text(5000), exclude: text(5000), pool: text(64) }),
    data,
    1000,
  );
  return items.map((j) => ({
    enabled: j.enabled ?? true,
    all: j.all ?? false,
    vmids: idList(j.vmid),
    exclude: idList(j.exclude),
    pool: j.pool && /^[A-Za-z0-9_.-]{1,64}$/.test(j.pool) ? j.pool : null,
  }));
}

/** Whether an enabled backup job includes the guest. Approximate: node and schedule are not considered. */
export function coveredByBackupJob(jobs: BackupJob[], guest: Pick<PxGuest, "vmid" | "pool">): boolean {
  return jobs.some(
    (j) =>
      j.enabled &&
      !j.exclude.has(guest.vmid) &&
      (j.all || j.vmids.has(guest.vmid) || (j.pool !== null && j.pool === guest.pool)),
  );
}

/** The newest backup time per guest id from a storage's backup listing (`ctime` is seconds since 1970). */
export function parseBackupContent(data: unknown): Map<number, Date> {
  const { items } = parseList(
    z.object({ vmid: z.unknown().optional(), ctime: z.unknown().optional() }),
    data,
    50_000,
  );
  const newest = new Map<number, Date>();
  for (const i of items) {
    const vmid = vmidOf(i.vmid);
    const at = epoch(i.ctime);
    if (vmid === null || !at) continue;
    const prior = newest.get(vmid);
    if (!prior || prior < at) newest.set(vmid, at);
  }
  return newest;
}

/* -------------------------------------------------------------------------- */
/* Guest details                                                               */
/* -------------------------------------------------------------------------- */

export interface PxGuestConfig {
  ostype: string | null;
  template: boolean | null;
  /** QEMU: the guest agent is switched on, so asking it for addresses can work. */
  agent: boolean;
  /** Addresses written into the configuration (static LXC and cloud-init settings). */
  ips: string[];
}

/** Addresses of a guest, public and private, but never loopback, link-local or multicast. Four first, at most 8. */
export function cleanAddresses(values: string[]): string[] {
  const out: string[] = [];
  for (const raw of values) {
    const v = raw.trim().replace(/%.*$/, "").toLowerCase();
    if (isIP(v) === 0 || isForbiddenAddress(v) || out.includes(v)) continue;
    out.push(v);
  }
  return [...out.filter((a) => isIP(a) === 4), ...out.filter((a) => isIP(a) === 6)].slice(0, 8);
}

/** `ip=192.0.2.10/24,gw=…` pieces of a net/ipconfig value: the static addresses. */
function staticAddresses(value: string): string[] {
  const found: string[] = [];
  for (const piece of value.split(",")) {
    const m = /^ip6?=([^/,]+)(?:\/\d{1,3})?$/.exec(piece.trim());
    if (m?.[1]) found.push(m[1]);
  }
  return found;
}

/**
 * The few fields of a guest configuration the integration uses. The rest, which can hold
 * descriptions, cloud-init passwords, SSH keys and mount paths, is dropped here and never stored.
 */
export function parseGuestConfig(data: unknown): PxGuestConfig | null {
  const c = asRecord(data);
  if (!c) return null;
  const str = (key: string, max: number) => (typeof c[key] === "string" ? clean(c[key] as string, max) : "");
  const ostype = str("ostype", 30);
  const ips: string[] = [];
  for (const [key, value] of Object.entries(c)) {
    if (/^(?:net|ipconfig)\d{1,2}$/.test(key) && typeof value === "string") {
      ips.push(...staticAddresses(clean(value, 600)));
    }
  }
  const agent = c.agent;
  return {
    ostype: /^[A-Za-z0-9._-]{1,30}$/.test(ostype) ? ostype : null,
    template: c.template === 1 || c.template === "1" || c.template === true ? true : null,
    agent:
      agent === 1 ||
      agent === "1" ||
      agent === true ||
      (typeof agent === "string" && /(?:^|,)(?:enabled=)?1(?:,|$)/.test(agent)),
    ips: cleanAddresses(ips),
  };
}

/** Addresses from the QEMU guest agent (`network-get-interfaces`). */
export function parseAgentInterfaces(data: unknown): string[] {
  const result = asRecord(data)?.result;
  const out: string[] = [];
  if (Array.isArray(result)) {
    for (const nic of result.slice(0, 64)) {
      const n = asRecord(nic);
      if (!n || n.name === "lo") continue;
      const list = n["ip-addresses"];
      if (!Array.isArray(list)) continue;
      for (const a of list.slice(0, 32)) {
        const address = asRecord(a)?.["ip-address"];
        if (typeof address === "string") out.push(address);
      }
    }
  }
  return cleanAddresses(out);
}

/** Addresses from the interface list of a container. */
export function parseLxcInterfaces(data: unknown): string[] {
  const out: string[] = [];
  if (Array.isArray(data)) {
    for (const nic of data.slice(0, 64)) {
      const n = asRecord(nic);
      if (!n || n.name === "lo") continue;
      for (const key of ["inet", "inet6"]) {
        const v = n[key];
        if (typeof v === "string") out.push(v.split("/")[0] ?? "");
      }
    }
  }
  return cleanAddresses(out);
}

export interface SnapshotInfo {
  count: number;
  newest: Date | null;
  oldest: Date | null;
}

/** Snapshots of a guest; the pseudo entry `current` ("You are here") is not one. Names and descriptions are not read. */
export function parseSnapshots(data: unknown): SnapshotInfo | null {
  if (!Array.isArray(data)) return null;
  let count = 0;
  let newest: Date | null = null;
  let oldest: Date | null = null;
  for (const entry of data.slice(0, 5000)) {
    const e = asRecord(entry);
    if (!e || e.name === "current") continue;
    count++;
    const at = epoch(e.snaptime);
    if (!at) continue;
    if (!newest || at > newest) newest = at;
    if (!oldest || at < oldest) oldest = at;
  }
  return { count, newest, oldest };
}

/* -------------------------------------------------------------------------- */
/* /access/permissions: is the token more than an auditor?                     */
/* -------------------------------------------------------------------------- */

/** `Sys.Audit`, `VM.Audit`, `Datastore.Audit`, `Pool.Audit`, `SDN.Audit`, `VM.GuestAgent.Audit`, `Mapping.Audit`: read-only. */
export const AUDIT_PRIVILEGE = /^[A-Za-z]+(?:\.[A-Za-z]+)*\.Audit$/;

export const isAuditPrivilege = (privilege: string) => AUDIT_PRIVILEGE.test(privilege);

/**
 * The privileges of the token (from `/access/permissions`, a map of path to privilege) that
 * are not read-only audit privileges. Empty means: the token can read, and nothing else. A
 * privilege name that does not look like one is reported as it is cut, never ignored.
 */
export function extraPrivileges(data: unknown): string[] {
  const paths = asRecord(data);
  if (!paths) return [];
  const found = new Set<string>();
  let count = 0;
  for (const privileges of Object.values(paths)) {
    const map = asRecord(privileges);
    if (!map) continue;
    for (const name of Object.keys(map)) {
      if (++count > 20_000) break;
      const privilege = clean(name, 64);
      if (privilege && !isAuditPrivilege(privilege)) found.add(privilege);
    }
  }
  return [...found].sort();
}

/** True if the token has at least one privilege, i.e. the permissions answer is not empty. */
export function hasAnyPrivilege(data: unknown): boolean {
  const paths = asRecord(data);
  return Boolean(paths && Object.values(paths).some((p) => Object.keys(asRecord(p) ?? {}).length > 0));
}

/** The extra privileges have all been acknowledged by an admin. */
export function privilegesAcknowledged(extra: string[], acknowledged: string[]): boolean {
  const known = new Set(acknowledged);
  return extra.every((p) => known.has(p));
}
