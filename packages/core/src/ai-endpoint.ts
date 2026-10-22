/**
 * Where the model may live (ADR 0013). The customer's own model server is the normal case, but
 * plain http carries the vulnerability list in cleartext, so it is only accepted where nobody
 * on a network can read it: on the same host or Docker network as the worker (the address lies
 * inside a subnet of one of the worker's own network interfaces) and inside a VPN overlay
 * (100.64.0.0/10, encrypted by WireGuard). Other private addresses (RFC 1918 LAN, IPv6 ULA)
 * need https. A public address means finding data leaves the network: https only, and only
 * after an admin acknowledged that host. Loopback, link-local (cloud metadata), unspecified and
 * multicast are never allowed: loopback of a GarnetOps container is the container itself,
 * never the model.
 *
 * The same rules run twice: when settings are saved (API, advisory) and on every connection
 * (worker, authoritative, because DNS can change between the two).
 */
import { isIP } from "node:net";

export type AddressScope = "private" | "public" | "forbidden";

function v4Bytes(address: string): number[] | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : Number.NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

/** Sixteen bytes of an IPv6 address in any notation (compressed, embedded IPv4), or null. */
function v6Bytes(address: string): number[] | null {
  let text = address.toLowerCase().split("%")[0] as string;
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text)?.[1];
  if (tail) {
    const v4 = v4Bytes(tail);
    if (!v4) return null;
    text = `${text.slice(0, -tail.length)}${(((v4[0] as number) << 8) | (v4[1] as number)).toString(16)}:${(((v4[2] as number) << 8) | (v4[3] as number)).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? (halves[0] as string).split(":") : [];
  const rest = halves.length === 2 && halves[1] ? (halves[1] as string).split(":") : [];
  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array<string>(missing).fill("0"), ...rest];
  } else groups = head;
  if (groups.length !== 8) return null;
  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    const n = Number.parseInt(group, 16);
    bytes.push(n >> 8, n & 255);
  }
  return bytes;
}

/** Whether the first `bits` bits of two equally long byte arrays are the same. */
function samePrefix(a: number[], b: number[], bits: number): boolean {
  for (let i = 0; i < a.length && bits > 0; i += 1) {
    const take = Math.min(8, bits);
    const mask = (0xff << (8 - take)) & 0xff;
    if (((a[i] as number) & mask) !== ((b[i] as number) & mask)) return false;
    bits -= take;
  }
  return true;
}

/** The four IPv4 bytes of an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), or null. */
function mappedV4(b: number[] | null): number[] | null {
  if (!b) return null;
  const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 255 && b[11] === 255;
  return mapped ? b.slice(12) : null;
}

/**
 * Whether an address lies inside a network in CIDR notation (`192.0.2.0/24`, `2001:db8::/64`).
 * An IPv4 network also matches the IPv4-mapped form of its addresses (`::ffff:192.0.2.7`); an
 * IPv6 network never matches a plain IPv4 address. Host bits in the network part are ignored
 * (`172.18.0.5/16` is `172.18.0.0/16`). Anything that does not parse is not inside.
 */
export function inNetwork(address: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash < 1) return false;
  const base = cidr.slice(0, slash);
  const length = cidr.slice(slash + 1);
  if (!/^\d{1,3}$/.test(length)) return false;
  const bits = Number(length);
  const netKind = isIP(base);
  const addrKind = isIP(address);
  if (netKind === 4) {
    if (bits > 32) return false;
    const net = v4Bytes(base);
    let target: number[] | null = null;
    if (addrKind === 4) target = v4Bytes(address);
    else if (addrKind === 6) target = mappedV4(v6Bytes(address));
    return net !== null && target !== null && samePrefix(net, target, bits);
  }
  if (netKind === 6) {
    if (bits > 128 || addrKind !== 6) return false;
    const net = v6Bytes(base);
    const target = v6Bytes(address);
    return net !== null && target !== null && samePrefix(net, target, bits);
  }
  return false;
}

/** The VPN overlay range (RFC 6598 shared address space) used by NetBird and Tailscale. */
const OVERLAY_NETWORK = "100.64.0.0/10";

/** Whether an address is in the VPN overlay range 100.64.0.0/10, also in IPv4-mapped notation. */
export function isOverlayAddress(address: string): boolean {
  return inNetwork(address, OVERLAY_NETWORK);
}

function isLoopback(address: string): boolean {
  return classifyAddress(address, true) === "private" && classifyAddress(address, false) === "forbidden";
}

function classifyV4(b: number[], allowLoopback: boolean): AddressScope {
  const [a, c] = [b[0] as number, b[1] as number];
  if (a === 127) return allowLoopback ? "private" : "forbidden";
  if (a === 0) return "forbidden"; // "this network", includes 0.0.0.0
  if (a === 169 && c === 254) return "forbidden"; // link-local, cloud metadata
  if (a >= 224) return "forbidden"; // multicast, reserved, broadcast
  if (a === 100 && c === 100 && b[2] === 100 && b[3] === 200) return "forbidden"; // Alibaba Cloud metadata
  if (a === 10) return "private";
  if (a === 172 && c >= 16 && c <= 31) return "private";
  if (a === 192 && c === 168) return "private";
  // Shared address space (RFC 6598), used by overlay networks such as NetBird and Tailscale.
  if (a === 100 && c >= 64 && c <= 127) return "private";
  return "public";
}

/**
 * Classifies one resolved address. `allowLoopback` exists for tests only and is never passed
 * by production code.
 */
export function classifyAddress(address: string, allowLoopback = false): AddressScope {
  const kind = isIP(address);
  if (kind === 4) {
    const b = v4Bytes(address);
    return b ? classifyV4(b, allowLoopback) : "forbidden";
  }
  if (kind === 6) {
    const b = v6Bytes(address);
    if (!b) return "forbidden";
    const prefix10 = b.slice(0, 10).every((x) => x === 0);
    // IPv4-mapped (::ffff:a.b.c.d): the IPv4 rules apply.
    if (prefix10 && b[10] === 255 && b[11] === 255) return classifyV4(b.slice(12), allowLoopback);
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4 address.
    if (
      b[0] === 0x00 &&
      b[1] === 0x64 &&
      b[2] === 0xff &&
      b[3] === 0x9b &&
      b.slice(4, 12).every((x) => x === 0)
    ) {
      return classifyV4(b.slice(12), allowLoopback);
    }
    if (b[0] === 0x20 && b[1] === 0x02) return classifyV4(b.slice(2, 6), allowLoopback);
    if (b.slice(0, 15).every((x) => x === 0)) {
      // :: (unspecified) and ::1 (loopback)
      return b[15] === 1 && allowLoopback ? "private" : "forbidden";
    }
    if (b[0] === 0) return "forbidden"; // the rest of 0000::/8: IPv4-compatible and reserved
    if (b[0] === 0xff) return "forbidden"; // multicast
    if (b[0] === 0xfe && ((b[1] as number) & 0xc0) === 0x80) return "forbidden"; // link-local fe80::/10
    if (b[0] === 0xfe && ((b[1] as number) & 0xc0) === 0xc0) return "forbidden"; // site-local fec0::/10
    if (b[0] === 0xfd && b[1] === 0x00 && b[2] === 0x0e && b[3] === 0xc2) return "forbidden"; // AWS IMDS over IPv6
    if (((b[0] as number) & 0xfe) === 0xfc) return "private"; // unique local fc00::/7
    return "public";
  }
  return "forbidden";
}

export interface EndpointDecision {
  ok: boolean;
  /** Where the endpoint is: all addresses private, or at least one public. Set when ok or when it is external. */
  scope: "private" | "external" | null;
  /** Why it is refused. */
  error:
    | "address-refused"
    | "insecure-private"
    | "insecure-external"
    | "external-not-acknowledged"
    | "unresolvable"
    | null;
}

/**
 * The decision for an endpoint given every address its host name resolves to.
 * `acknowledged` is true when an admin confirmed this host as an external endpoint.
 * `localNetworks` are the subnets of the network interfaces of the machine that makes the
 * connection (CIDR); over http a private address is only accepted inside one of them or in the
 * VPN overlay range. `allowLoopback` (tests only) also treats loopback as the same host.
 */
export function decideEndpoint(
  protocol: "http:" | "https:",
  addresses: string[],
  acknowledged: boolean,
  options: { allowLoopback?: boolean; localNetworks?: string[] } = {},
): EndpointDecision {
  if (addresses.length === 0) return { ok: false, scope: null, error: "unresolvable" };
  const scopes = addresses.map((a) => classifyAddress(a, options.allowLoopback));
  if (scopes.includes("forbidden")) return { ok: false, scope: null, error: "address-refused" };
  if (scopes.every((s) => s === "private")) {
    if (protocol === "https:") return { ok: true, scope: "private", error: null };
    const localNetworks = options.localNetworks ?? [];
    const sameHostOrOverlay = addresses.every(
      (a) =>
        isOverlayAddress(a) ||
        localNetworks.some((cidr) => inNetwork(a, cidr)) ||
        (options.allowLoopback === true && isLoopback(a)),
    );
    if (!sameHostOrOverlay) return { ok: false, scope: "private", error: "insecure-private" };
    return { ok: true, scope: "private", error: null };
  }
  if (protocol !== "https:") return { ok: false, scope: "external", error: "insecure-external" };
  if (!acknowledged) return { ok: false, scope: "external", error: "external-not-acknowledged" };
  return { ok: true, scope: "external", error: null };
}

/**
 * Why a base URL cannot be used, judged without a network lookup; null if it looks fine.
 * Accepts http(s) URLs for the server's `/v1` root: no credentials, query or fragment.
 */
export function aiBaseUrlProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Not a URL";
  }
  if (url.protocol !== "https:" && url.protocol !== "http:")
    return "Only http:// and https:// addresses are allowed";
  if (url.username || url.password) return "No user name or password in the address (use the API key field)";
  if (url.search || url.hash) return "No query or fragment in the address";
  if (!url.hostname) return "The address has no host";
  if (url.pathname.length > 100 || !/^[A-Za-z0-9/._~-]*$/.test(url.pathname)) return "The path is not valid";
  if (url.pathname.split("/").includes("..")) return "The path is not valid";
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) {
    return "Loopback is the GarnetOps container itself, not your model server. Use the address of the machine that runs it";
  }
  if (isIP(host)) {
    const scope = classifyAddress(host);
    if (scope === "forbidden")
      return "This address is not allowed (loopback, link-local, metadata or reserved)";
    if (scope === "public" && url.protocol !== "https:") return "A public address needs https://";
  }
  return null;
}

/** The base URL without a trailing slash, as it is stored and extended with `/chat/completions`. */
export function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** The host with its port, as an acknowledgement is bound to it (`llm.example.lan:8000`). */
export function endpointHost(value: string): string {
  return new URL(value).host.toLowerCase();
}
