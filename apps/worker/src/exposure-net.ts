/**
 * The network side of external exposure monitoring (ADR 0023): DNS lookups, TLS handshakes, one HTTP GET of `/`, the proof file
 * of the verification, and the TCP connection checks of stage 2.
 *
 * What makes this safe to run against names an admin typed:
 * - Names are resolved here, every answer is checked, and a connection goes to the checked address (the name only travels as SNI
 *   and Host header). If any answer of a name is not a public address, nothing is connected to that name at all.
 * - Only GET, only `/` (and the proof file), no cookies, no forms, no crawling. Redirects are followed at most three times, only to
 *   the same site or to a verified asset, only on the default ports. TLS is verified against the system store (the TLS probe
 *   records the verdict; it never trusts anything).
 * - Stage 2 only connects and reads what a service sends first. No function in this file writes to a TCP socket; the only bytes a
 *   port ever receives from us are the TLS handshake of the TLS ports. The socket's `write` is not called anywhere (a test pins it).
 * - Everything a remote system answers is cut, cleaned and stored as text.
 */
import { X509Certificate } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, connect as tcpConnect } from "node:net";
import {
  checkServerIdentity,
  type DetailedPeerCertificate,
  type PeerCertificate,
  type TLSSocket,
  connect as tlsConnect,
} from "node:tls";
import { certificateFingerprint } from "@garnetops/core/certificates";
import {
  ACTIVE_LIMITS,
  CAPTURED_HEADERS,
  type CertInfo,
  type DnsSnapshot,
  dmarcPolicy,
  type HttpSnapshot,
  MAX_ADDRESSES_PER_ASSET,
  MAX_HTTP_BODY_BYTES,
  MAX_REDIRECTS,
  MAX_VERIFY_FILE_BYTES,
  type PlainHttpSnapshot,
  type PortResult,
  type PortSpec,
  plainText,
  registrableDomain,
  sanitizeBanner,
  spfPolicy,
  spfRecords,
  type TlsSnapshot,
} from "@garnetops/core/exposure";
import { addressAllowed } from "@garnetops/core/exposure-assets";
import { metaGenerators } from "@garnetops/core/software";

/* -------------------------------------------------------------------------- */
/* Environment                                                                 */
/* -------------------------------------------------------------------------- */

/** The resolver calls this module uses. `node:dns/promises` `Resolver` has all of them; tests pass a fake. */
export interface DnsLike {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolveCname(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<{ priority: number; exchange: string }[]>;
  resolveNs(name: string): Promise<string[]>;
  resolveCaa(name: string): Promise<{ critical: number; [tag: string]: string | number | undefined }[]>;
  resolveTxt(name: string): Promise<string[][]>;
  reverse(address: string): Promise<string[]>;
}

/** What a test can replace. Production passes nothing but the resolver. */
export interface NetEnv {
  dns: DnsLike;
  /** Tests only: loopback and documentation ranges count as addresses a run may connect to. */
  allowTestRanges?: boolean;
  /** Tests only: a trust anchor for a local HTTPS server. */
  ca?: string;
  /** Tests only: where "port 443" and "port 80" of stage 1 really are. */
  httpsPort?: number;
  httpPort?: number;
  /** Tests only: shorter waits. */
  connectTimeoutMs?: number;
  bannerReadMs?: number;
  /** Tests only: a hook that sees the moment each stage 2 attempt starts. */
  onAttempt?: (port: number, address: string) => void;
  /** A resolver that asks one name server and nothing else; tests pass a fake. */
  dnsAt?: (server: string) => DnsLike;
}

/** The system resolver with short time-outs. */
export function systemResolver(): DnsLike {
  return new Resolver({ timeout: 3000, tries: 2 }) as unknown as DnsLike;
}

/** A resolver that asks only `server` (an address), for the zone's own name servers. */
export function serverResolver(server: string): DnsLike {
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  resolver.setServers([server]);
  return resolver as unknown as DnsLike;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const allowed = (env: NetEnv, address: string) => addressAllowed(address, env.allowTestRanges === true);

/* -------------------------------------------------------------------------- */
/* DNS                                                                         */
/* -------------------------------------------------------------------------- */

/** "no data" answers are an empty list; any other failure is `undefined`, which the rules treat as "unknown". */
async function ask<T>(call: () => Promise<T[]>): Promise<T[] | undefined> {
  try {
    return await call();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
    return code === "ENODATA" || code === "ENOTFOUND" || code === "NODATA" ? [] : undefined;
  }
}

export interface Resolved {
  /** Public addresses to look at (at most four). Empty when the name has none or any answer was not public. */
  addresses: string[];
  nonPublic: string[];
  a: string[];
  aaaa: string[];
  failed: ("a" | "aaaa")[];
}

/** Resolves a name or takes an address literal, and applies the address policy to every answer. */
export async function resolveAssetAddresses(env: NetEnv, name: string): Promise<Resolved> {
  const literal = name.replace(/^\[|\]$/g, "");
  if (isIP(literal) !== 0) {
    return allowed(env, literal)
      ? { addresses: [literal], nonPublic: [], a: [], aaaa: [], failed: [] }
      : { addresses: [], nonPublic: [literal], a: [], aaaa: [], failed: [] };
  }
  const [a, aaaa] = await Promise.all([ask(() => env.dns.resolve4(name)), ask(() => env.dns.resolve6(name))]);
  const failed: ("a" | "aaaa")[] = [];
  if (a === undefined) failed.push("a");
  if (aaaa === undefined) failed.push("aaaa");
  const v4 = [...new Set(a ?? [])];
  const v6 = [...new Set(aaaa ?? [])];
  const every = [...v4, ...v6];
  const nonPublic = every.filter((address) => !allowed(env, address));
  // One answer that is not public taints the whole name: DNS rebinding and split-horizon tricks get nothing to connect to.
  if (nonPublic.length > 0) return { addresses: [], nonPublic, a: v4, aaaa: v6, failed };
  const addresses = [
    ...v4.slice(0, MAX_ADDRESSES_PER_ASSET - 1),
    ...v6,
    ...v4.slice(MAX_ADDRESSES_PER_ASSET - 1),
  ].slice(0, MAX_ADDRESSES_PER_ASSET);
  return { addresses, nonPublic: [], a: v4, aaaa: v6, failed };
}

const text = (value: string, max = 255) => plainText(value, max);

/** Records of a domain asset for the DNS tab and the DNS rules. Lookups that fail are listed, not guessed. */
export async function readDns(env: NetEnv, name: string, resolved: Resolved): Promise<DnsSnapshot> {
  const base = registrableDomain(name);
  const [cname, mx, ns, txt, dmarcTxt] = await Promise.all([
    ask(() => env.dns.resolveCname(name)),
    ask(() => env.dns.resolveMx(name)),
    ask(() => env.dns.resolveNs(name)),
    ask(() => env.dns.resolveTxt(name)),
    ask(() => env.dns.resolveTxt(`_dmarc.${name}`)),
  ]);
  const failed: DnsSnapshot["failed"] = [...resolved.failed];
  if (txt === undefined) failed.push("txt");

  // DMARC applies from the organisational domain when the name has no policy of its own (RFC 7489).
  let dmarcRecords = dmarcTxt;
  if (dmarcRecords !== undefined && dmarcPolicy(dmarcRecords) === null && base !== name) {
    dmarcRecords = (await ask(() => env.dns.resolveTxt(`_dmarc.${base}`))) ?? undefined;
  }
  if (dmarcRecords === undefined) failed.push("dmarc");

  // CAA climbs from the name towards the registrable domain (RFC 8659); the first name with any CAA record decides.
  let caa: { critical: boolean; tag: string; value: string }[] = [];
  let caaFailed = false;
  let climbing = name;
  for (let depth = 0; depth < 6; depth += 1) {
    const found = await ask(() => env.dns.resolveCaa(climbing));
    if (found === undefined) {
      caaFailed = true;
      break;
    }
    if (found.length > 0) {
      caa = found.slice(0, 10).map((record) => {
        const tag =
          Object.keys(record).find(
            (key) => key !== "critical" && key !== "contactemail" && key !== "contactphone",
          ) ?? "unknown";
        return {
          critical: Number(record.critical) === 128,
          tag: text(tag, 20),
          value: text(String(record[tag] ?? ""), 120),
        };
      });
      break;
    }
    if (climbing === base || !climbing.includes(".")) break;
    climbing = climbing.slice(climbing.indexOf(".") + 1);
  }
  if (caaFailed) failed.push("caa");

  const spf = spfRecords(txt ?? []);
  const dmarcList = (dmarcRecords ?? []).map((strings) => strings.join("").trim());
  const dmarcRecord = dmarcList.find((record) => /^v=DMARC1\s*(;|$)/i.test(record));
  return {
    failed,
    a: resolved.a,
    aaaa: resolved.aaaa,
    cname: (cname ?? []).slice(0, 5).map((c) => text(c)),
    mx: (mx ?? [])
      .slice(0, 10)
      .map((m) => ({ priority: Number(m.priority) || 0, exchange: text(m.exchange) }))
      .sort((x, y) => x.priority - y.priority),
    ns: (ns ?? []).slice(0, 10).map((n) => text(n)),
    caa,
    caaFound: caa.length > 0,
    spf: { records: spf.length, policy: spfPolicy(spf[0]), record: spf[0] ? text(spf[0], 300) : null },
    dmarc: {
      found: dmarcPolicy(dmarcRecords ?? []) !== null,
      policy: dmarcPolicy(dmarcRecords ?? []),
      record: dmarcRecord ? text(dmarcRecord, 300) : null,
    },
    dnssec: "unknown",
  };
}

/** Reverse names of public addresses, for display next to an address asset. At most five, cleaned. */
export async function readPtr(env: NetEnv, addresses: readonly string[]): Promise<string[]> {
  const names = new Set<string>();
  for (const address of addresses) {
    const found = await ask(() => env.dns.reverse(address));
    for (const name of found ?? []) names.add(text(name));
    if (names.size >= 5) break;
  }
  return [...names].slice(0, 5);
}

/** At most this many name server addresses are asked for the verification record before giving up on them. */
const MAX_ZONE_SERVERS_ASKED = 3;

/**
 * The zone `name` lies in and its name servers: the NS answer of the name or of its nearest parent that has one. A top-level
 * domain counts only with `topLevel` (the parent of a domain, for its DS records).
 */
export async function zoneOf(
  env: NetEnv,
  name: string,
  topLevel = false,
): Promise<{ zone: string; servers: string[] } | null> {
  const labels = name.split(".");
  for (let i = 0; i < labels.length - (topLevel ? 0 : 1); i++) {
    const zone = labels.slice(i).join(".");
    const ns = await ask(() => env.dns.resolveNs(zone));
    if (ns === undefined) return null;
    if (ns.length > 0) return { zone, servers: ns.slice(0, 4) };
  }
  return null;
}

/** The public addresses of a zone's name servers, at most `max`. */
export async function serverAddresses(
  env: NetEnv,
  servers: readonly string[],
  max: number,
): Promise<string[]> {
  const out: string[] = [];
  for (const host of servers) {
    out.push(...(await resolveAssetAddresses(env, host)).addresses);
    if (out.length >= max) break;
  }
  return out.slice(0, max);
}

/**
 * The verification record as the zone's own name servers answer it. Asking them directly sees a record the moment it is
 * published: a recursive resolver may still hold the "not there" of an earlier check (negative caching), and a resolver with
 * an internal view of the organisation's own domain (split horizon) never sees the public record at all. Only public
 * addresses are asked, with one TXT query each. `undefined` when no name server could be asked.
 */
async function readTxtAtZone(env: NetEnv, name: string): Promise<string[][] | undefined> {
  const at = env.dnsAt ?? serverResolver;
  const zone = await zoneOf(env, name);
  for (const address of zone ? await serverAddresses(env, zone.servers, MAX_ZONE_SERVERS_ASKED) : []) {
    const answer = await ask(() => at(address).resolveTxt(name));
    if (answer !== undefined) return answer;
  }
  return undefined;
}

/**
 * The TXT answer for the verification record, from the zone's name servers and the system resolver together: the record
 * counts if either sees it, so a network that blocks direct DNS still verifies through its resolver. `undefined` is a failed
 * lookup on both ways, an empty list is "not there".
 */
export async function readTxt(env: NetEnv, name: string): Promise<string[][] | undefined> {
  const [direct, system] = await Promise.all([readTxtAtZone(env, name), ask(() => env.dns.resolveTxt(name))]);
  if (direct === undefined) return system;
  if (system === undefined) return direct;
  return [...direct, ...system];
}

/* -------------------------------------------------------------------------- */
/* TLS                                                                         */
/* -------------------------------------------------------------------------- */

const REFUSED =
  /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|EADDRNOTAVAIL|ENOTFOUND|EAI_AGAIN)$/;

function tlsError(error: unknown): "refused" | "timeout" | "handshake" {
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT" || code === "ETIMEOUT") return "timeout";
  if (REFUSED.test(code)) return "refused";
  return "handshake";
}

function dnName(value: string): string {
  const parts = value.split("\n").map((line) => line.trim());
  const cn = parts.find((part) => part.startsWith("CN="));
  return text(cn ? cn.slice(3) : parts.join(", "), 200);
}

function certInfo(peer: PeerCertificate): CertInfo | null {
  if (!peer?.raw || peer.raw.length === 0) return null;
  try {
    const x509 = new X509Certificate(peer.raw);
    const key = x509.publicKey;
    const details = key.asymmetricKeyDetails;
    let selfSigned = false;
    try {
      selfSigned = x509.subject === x509.issuer && x509.verify(x509.publicKey);
    } catch {
      selfSigned = false;
    }
    const sans = (x509.subjectAltName ?? "")
      .split(",")
      .map((entry) => entry.trim().replace(/^IP Address:/, "IP:"))
      .filter((entry) => entry.length > 0)
      .slice(0, 20)
      .map((entry) => text(entry, 120));
    return {
      subject: dnName(x509.subject),
      issuer: dnName(x509.issuer),
      sans,
      validFrom: new Date(x509.validFrom).toISOString(),
      validTo: new Date(x509.validTo).toISOString(),
      fingerprint: certificateFingerprint(peer.raw),
      keyType: key.asymmetricKeyType ?? null,
      keyBits:
        details?.modulusLength ?? (key.asymmetricKeyType === "ec" ? curveBits(details?.namedCurve) : null),
      selfSigned,
    };
  } catch {
    return null;
  }
}

function curveBits(curve: string | undefined): number | null {
  const bits = /(\d{3})/.exec(curve ?? "")?.[1];
  return bits ? Number(bits) : null;
}

function chainLength(peer: DetailedPeerCertificate): number {
  let length = 0;
  let current: DetailedPeerCertificate | undefined = peer;
  const seen = new Set<string>();
  while (current?.raw && length < 10) {
    const id = current.fingerprint256 ?? String(length);
    if (seen.has(id)) break;
    seen.add(id);
    length += 1;
    current = current.issuerCertificate;
  }
  return length;
}

export interface TlsProbeOptions {
  address: string;
  port: number;
  /** The name to ask for (SNI) and to check the certificate against; null when the asset is an address. */
  servername: string | null;
  /** Also judge a certificate for its name when only an address is known. */
  timeoutMs?: number;
  /** For the legacy probes only. */
  version?: "TLSv1" | "TLSv1.1";
  ca?: string | undefined;
}

/**
 * One TLS handshake, the way any client makes it: the verdict on the chain, the negotiated protocol and cipher, and the leaf
 * certificate. With `version` set it asks for exactly TLS 1.0 or TLS 1.1 and answers only whether that was accepted. Nothing is sent
 * after the handshake; the socket is closed.
 */
export function tlsProbe(options: TlsProbeOptions): Promise<TlsSnapshot> {
  const legacy = options.version !== undefined;
  return new Promise((resolve) => {
    let done = false;
    const base: TlsSnapshot = {
      address: options.address,
      port: options.port,
      ok: false,
      error: null,
      protocol: null,
      cipher: null,
      trusted: null,
      trustError: null,
      nameMatches: null,
      cert: null,
      chainLength: 0,
      legacy: null,
    };
    let socket: TLSSocket | undefined;
    const finish = (snapshot: TlsSnapshot) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket?.destroy();
      resolve(snapshot);
    };
    const timer = setTimeout(() => finish({ ...base, error: "timeout" }), options.timeoutMs ?? 8000);
    try {
      socket = tlsConnect({
        host: options.address,
        port: options.port,
        // SNI must be a name, never an address (RFC 6066).
        ...(options.servername ? { servername: options.servername } : {}),
        // The verdict is recorded, not enforced: a probe has to see a bad certificate to report it.
        rejectUnauthorized: false,
        minVersion: legacy ? options.version : "TLSv1.2",
        ...(legacy ? { maxVersion: options.version, ciphers: "ALL:@SECLEVEL=0" } : {}),
        ...(options.ca ? { ca: options.ca } : {}),
      });
    } catch {
      return finish({ ...base, error: "handshake" });
    }
    socket.once("error", (error) => finish({ ...base, error: tlsError(error) }));
    socket.once("secureConnect", () => {
      const sock = socket as TLSSocket;
      if (legacy) return finish({ ...base, ok: true, protocol: sock.getProtocol() });
      const peer = sock.getPeerCertificate(true);
      const cert = certInfo(peer);
      let authorized = sock.authorized;
      const authError = sock.authorizationError ? String(sock.authorizationError) : null;
      let nameMatches: boolean | null = null;
      if (options.servername && peer?.raw) {
        nameMatches = checkServerIdentity(options.servername, peer) === undefined;
      }
      // For an address there is no name to match: a certificate that is only wrong for the address is judged by its chain.
      if (!options.servername && !authorized && authError === "ERR_TLS_CERT_ALTNAME_INVALID")
        authorized = true;
      finish({
        ...base,
        ok: true,
        protocol: sock.getProtocol(),
        cipher: sock.getCipher()?.name ?? null,
        trusted: authorized,
        trustError: authorized ? null : text(authError ?? "unknown", 60),
        nameMatches,
        cert,
        chainLength: chainLength(peer),
      });
    });
  });
}

/**
 * The complete TLS look at one address on port 443: the handshake, and (once per asset) whether TLS 1.0 and TLS 1.1 are accepted.
 * The two extra handshakes are what any scanner-shy client does when it falls back; they send no data.
 */
export async function tlsFull(
  env: NetEnv,
  options: TlsProbeOptions & { withLegacy: boolean },
): Promise<TlsSnapshot> {
  const main = await tlsProbe({ ...options, ca: env.ca });
  if (!main.ok || !options.withLegacy) return main;
  const [tls10, tls11] = await Promise.all(
    (["TLSv1", "TLSv1.1"] as const).map((version) => tlsProbe({ ...options, version, ca: env.ca })),
  );
  return { ...main, legacy: { tls10: tls10?.ok ?? null, tls11: tls11?.ok ?? null } };
}

/* -------------------------------------------------------------------------- */
/* HTTP                                                                        */
/* -------------------------------------------------------------------------- */

export interface HttpGetOptions {
  scheme: "https" | "http";
  address: string;
  port: number;
  /** Host header and SNI; null for an address. */
  host: string | null;
  path: string;
  /** Verify the certificate chain and name (names), or only the chain (addresses). */
  verify: boolean;
  ca?: string | undefined;
  timeoutMs?: number;
  /** How many bytes of the body are read before the connection is closed. */
  maxBody: number;
}

export type HttpGetResult =
  | {
      ok: true;
      status: number;
      headers: Record<string, string>;
      location: string | null;
      body: Buffer;
      truncated: boolean;
    }
  | { ok: false; error: "refused" | "timeout" | "tls" | "protocol" };

/**
 * One GET with the checked address as the connection target. Headers are captured from a fixed list, cleaned; the body is read up
 * to `maxBody` bytes and then the connection is closed. No cookies are sent or kept, no redirect is followed here.
 */
export function httpGet(options: HttpGetOptions): Promise<HttpGetResult> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result: HttpGetResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      req.destroy();
      resolve(result);
    };
    const hostHeader =
      options.host ?? (isIP(options.address) === 6 ? `[${options.address}]` : options.address);
    const common = {
      host: options.address,
      port: options.port,
      path: options.path,
      method: "GET",
      agent: false,
      headers: {
        host:
          options.port === (options.scheme === "https" ? 443 : 80)
            ? hostHeader
            : `${hostHeader}:${options.port}`,
        "user-agent": "GarnetOps-Exposure-Check/1",
        accept: "text/html,text/plain;q=0.9,*/*;q=0.5",
        connection: "close",
      },
    };
    const req =
      options.scheme === "https"
        ? httpsRequest({
            ...common,
            ...(options.host ? { servername: options.host } : {}),
            minVersion: "TLSv1.2",
            rejectUnauthorized: options.verify,
            ...(options.ca ? { ca: options.ca } : {}),
            // An address has no name to match: the chain is still verified.
            ...(!options.host ? { checkServerIdentity: () => undefined } : {}),
          })
        : httpRequest(common);
    const timer = setTimeout(() => finish({ ok: false, error: "timeout" }), options.timeoutMs ?? 12_000);
    req.on("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code ?? "";
      if (code === "ETIMEDOUT") return finish({ ok: false, error: "timeout" });
      if (REFUSED.test(code)) return finish({ ok: false, error: "refused" });
      if (/CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO/.test(code) || /certificate|SSL|TLS/i.test(error.message)) {
        return finish({ ok: false, error: "tls" });
      }
      return finish({ ok: false, error: "protocol" });
    });
    req.on("response", (res) => {
      const headers: Record<string, string> = {};
      for (const name of CAPTURED_HEADERS) {
        const value = res.headers[name];
        if (value !== undefined) headers[name] = plainText(Array.isArray(value) ? value.join(", ") : value);
      }
      const location = res.headers.location ? plainText(res.headers.location, 500) : null;
      const chunks: Buffer[] = [];
      let size = 0;
      const status = res.statusCode ?? 0;
      const end = (truncated: boolean) =>
        finish({ ok: true, status, headers, location, body: Buffer.concat(chunks), truncated });
      if (options.maxBody <= 0) return end(true);
      res.on("data", (chunk: Buffer) => {
        const room = options.maxBody - size;
        if (room > 0) chunks.push(chunk.subarray(0, room));
        size += chunk.length;
        if (size > options.maxBody) end(true);
      });
      res.on("end", () => end(false));
      res.on("error", () => end(true));
    });
    req.end();
  });
}

/** Where a page request goes: the checked address, the name for SNI and Host, the real port. */
export interface PageTarget {
  host: string;
  /** The checked addresses of this host, in the order they are tried. */
  addresses: string[];
}

/**
 * GET `/` of an asset over HTTPS, following at most three redirects to the same site or a verified asset on the default ports
 * (every followed host is resolved and checked again). Records the status, the final URL, the redirects that were seen and whether
 * they were followed, and the captured headers. The body is read up to 64 KiB; only its generator tags are kept.
 */
export async function fetchHomepage(
  env: NetEnv,
  asset: { name: string; isAddress: boolean },
  firstAddresses: readonly string[],
  verifiedHosts: ReadonlySet<string>,
  mayFollow: (from: string, to: string, verified: ReadonlySet<string>) => boolean,
): Promise<HttpSnapshot> {
  const start =
    asset.isAddress && asset.name.includes(":") ? `https://[${asset.name}]/` : `https://${asset.name}/`;
  const snapshot: HttpSnapshot = {
    address: null,
    url: start,
    finalUrl: null,
    status: null,
    redirects: [],
    headers: {},
    error: null,
  };
  let current = new URL(start);
  let addresses = [...firstAddresses];
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const scheme = current.protocol === "https:" ? "https" : "http";
    const host = current.hostname.replace(/^\[|\]$/g, "");
    const isName = isIP(host) === 0;
    const port = scheme === "https" ? (env.httpsPort ?? 443) : (env.httpPort ?? 80);
    let result: HttpGetResult = { ok: false, error: "refused" };
    let used: string | null = null;
    for (const address of addresses) {
      result = await httpGet({
        scheme,
        address,
        port,
        host: isName ? host : null,
        path: `${current.pathname}${current.search}`,
        // A name is verified completely. An address is verified against the chain only.
        verify: scheme === "https",
        ca: env.ca,
        maxBody: MAX_HTTP_BODY_BYTES,
      });
      if (result.ok || result.error !== "refused") {
        used = address;
        break;
      }
    }
    if (!result.ok) {
      snapshot.error = result.error;
      snapshot.address = used;
      return snapshot;
    }
    snapshot.address = used;
    snapshot.status = result.status;
    snapshot.headers = result.headers;
    // The page itself is dropped; only what it says about its software stays (ADR 0038).
    snapshot.generators = metaGenerators(result.body.toString("utf8"));
    snapshot.finalUrl = current.toString();
    if (result.status >= 300 && result.status < 400 && result.location) {
      let target: URL | null = null;
      try {
        target = new URL(result.location, current);
      } catch {
        target = null;
      }
      const wanted = target?.protocol === "https:" || target?.protocol === "http:";
      if (!target || !wanted) {
        snapshot.redirects.push({
          to: plainText(result.location, 200),
          status: result.status,
          followed: false,
        });
        return snapshot;
      }
      const targetHost = target.hostname.replace(/^\[|\]$/g, "");
      const defaultPort = target.port === "" || target.port === (target.protocol === "https:" ? "443" : "80");
      const follow = hop < MAX_REDIRECTS && defaultPort && mayFollow(host, targetHost, verifiedHosts);
      snapshot.redirects.push({
        to: plainText(target.toString(), 200),
        status: result.status,
        followed: follow,
      });
      if (!follow) return snapshot;
      if (targetHost !== host) {
        const resolved = await resolveAssetAddresses(env, targetHost);
        if (resolved.addresses.length === 0) {
          snapshot.error = "refused";
          return snapshot;
        }
        addresses = resolved.addresses;
      }
      current = target;
      continue;
    }
    return snapshot;
  }
  return snapshot;
}

/** GET `http://name/` on port 80 without following: does plain HTTP answer, and does it send people to https? */
export async function fetchPlain(
  env: NetEnv,
  asset: { name: string; isAddress: boolean },
  addresses: readonly string[],
): Promise<PlainHttpSnapshot> {
  let last: HttpGetResult = { ok: false, error: "refused" };
  for (const address of addresses) {
    last = await httpGet({
      scheme: "http",
      address,
      port: env.httpPort ?? 80,
      host: asset.isAddress ? null : asset.name,
      path: "/",
      verify: false,
      maxBody: 0,
    });
    if (last.ok || last.error !== "refused") {
      if (!last.ok) {
        return {
          address,
          status: null,
          location: null,
          redirectsToHttps: null,
          error: last.error === "timeout" ? "timeout" : "protocol",
        };
      }
      const redirect = last.status >= 300 && last.status < 400 && last.location;
      let toHttps = false;
      if (redirect) {
        try {
          toHttps = new URL(last.location as string, `http://${asset.name}/`).protocol === "https:";
        } catch {
          toHttps = false;
        }
      }
      return {
        address,
        status: last.status,
        location: last.location,
        redirectsToHttps: toHttps,
        error: null,
      };
    }
  }
  return { address: null, status: null, location: null, redirectsToHttps: null, error: "refused" };
}

/* -------------------------------------------------------------------------- */
/* Verification file                                                           */
/* -------------------------------------------------------------------------- */

export type ProofFile =
  | { ok: true; body: string }
  | {
      ok: false;
      error:
        | "fileUnreachable"
        | "fileNotFound"
        | "fileRedirected"
        | "fileNoMatch"
        | "fileTooLarge"
        | "tlsFailed"
        | "timeout";
    };

/**
 * Fetches the proof file once, without following a redirect. A name is fetched over HTTPS with the certificate verified; an address
 * is tried over HTTPS (chain verified) and then over plain HTTP, because few certificates name an address and the file holds a token
 * that is public by design.
 */
export async function fetchProofFile(
  env: NetEnv,
  asset: { value: string; isAddress: boolean },
  addresses: readonly string[],
  path: string,
): Promise<ProofFile> {
  const schemes: ("https" | "http")[] = asset.isAddress ? ["https", "http"] : ["https"];
  let sawTls = false;
  for (const scheme of schemes) {
    for (const address of addresses) {
      const result = await httpGet({
        scheme,
        address,
        port: scheme === "https" ? (env.httpsPort ?? 443) : (env.httpPort ?? 80),
        host: asset.isAddress ? null : asset.value,
        path,
        verify: scheme === "https",
        ca: env.ca,
        maxBody: MAX_VERIFY_FILE_BYTES + 1,
        timeoutMs: 10_000,
      });
      if (!result.ok) {
        if (result.error === "tls") sawTls = true;
        if (result.error === "timeout") return { ok: false, error: "timeout" };
        continue;
      }
      if (result.status >= 300 && result.status < 400) return { ok: false, error: "fileRedirected" };
      // Gone is an answer; a server error is not (an outage must not read as "the proof was removed").
      if (result.status !== 200) {
        return {
          ok: false,
          error: result.status === 404 || result.status === 410 ? "fileNotFound" : "fileUnreachable",
        };
      }
      if (result.body.length > MAX_VERIFY_FILE_BYTES) return { ok: false, error: "fileTooLarge" };
      return { ok: true, body: result.body.toString("utf8") };
    }
  }
  return { ok: false, error: sawTls ? "tlsFailed" : "fileUnreachable" };
}

/* -------------------------------------------------------------------------- */
/* Stage 2: ports                                                              */
/* -------------------------------------------------------------------------- */

export interface PortProbe {
  state: "open" | "closed" | "noAnswer";
  banner: string | null;
  tls: TlsSnapshot | null;
}

/**
 * One port. A TLS port gets the handshake and nothing else. A port where the service speaks first is connected to and listened to
 * for up to two seconds and 512 bytes. Every other port is connected to and closed. **Nothing is ever written to the socket.**
 */
export async function probePort(
  env: NetEnv,
  address: string,
  spec: PortSpec,
  servername: string | null,
): Promise<PortProbe> {
  const connectTimeout = env.connectTimeoutMs ?? ACTIVE_LIMITS.connectTimeoutMs;
  if (spec.tls) {
    const tls = await tlsProbe({
      address,
      port: spec.port,
      servername,
      timeoutMs: connectTimeout + 3000,
      ca: env.ca,
    });
    if (tls.ok) return { state: "open", banner: null, tls };
    if (tls.error === "refused") return { state: "closed", banner: null, tls: null };
    if (tls.error === "timeout") return { state: "noAnswer", banner: null, tls: null };
    // The connection was accepted but the service did not answer the handshake: the port is open, the service is not TLS.
    return { state: "open", banner: null, tls: { ...tls, error: "handshake" } };
  }
  return new Promise((resolve) => {
    let done = false;
    const chunks: Buffer[] = [];
    let size = 0;
    const socket = tcpConnect({ host: address, port: spec.port });
    const finish = (probe: PortProbe) => {
      if (done) return;
      done = true;
      clearTimeout(connectTimer);
      clearTimeout(readTimer);
      socket.destroy();
      resolve(probe);
    };
    const connectTimer = setTimeout(
      () => finish({ state: "noAnswer", banner: null, tls: null }),
      connectTimeout,
    );
    let readTimer: ReturnType<typeof setTimeout> | undefined;
    const bannerOf = () => (chunks.length > 0 ? sanitizeBanner(Buffer.concat(chunks)) : null);
    socket.once("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code ?? "";
      finish({ state: code === "ETIMEDOUT" ? "noAnswer" : "closed", banner: null, tls: null });
    });
    socket.once("connect", () => {
      clearTimeout(connectTimer);
      if (!spec.banner) return finish({ state: "open", banner: null, tls: null });
      readTimer = setTimeout(
        () => finish({ state: "open", banner: bannerOf(), tls: null }),
        env.bannerReadMs ?? ACTIVE_LIMITS.bannerReadMs,
      );
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        size += chunk.length;
        // A greeting ends with a line break; whatever else the service sends is not wanted.
        if (size >= ACTIVE_LIMITS.bannerBytes || /\n/.test(chunk.toString("latin1"))) {
          finish({ state: "open", banner: bannerOf(), tls: null });
        }
      });
      socket.once("close", () => finish({ state: "open", banner: bannerOf(), tls: null }));
    });
  });
}

/**
 * Runs `run` for each item with at most `concurrency` in flight and at least `gapMs` between the starts of two. `stop` is asked
 * before every start: a true answer ends the run (the proof of control disappeared, say) without starting anything else.
 */
export async function pacedRun<T>(
  items: readonly T[],
  run: (item: T) => Promise<void>,
  options: { concurrency: number; gapMs: number; stop?: () => Promise<boolean> | boolean },
): Promise<{ stopped: boolean }> {
  const inFlight = new Set<Promise<void>>();
  let lastStart = Number.NEGATIVE_INFINITY;
  let stopped = false;
  for (const item of items) {
    if (options.stop && (await options.stop())) {
      stopped = true;
      break;
    }
    while (inFlight.size >= options.concurrency) await Promise.race(inFlight);
    const wait = lastStart + options.gapMs - Date.now();
    if (wait > 0) await sleep(wait);
    // Stop may have become true while waiting.
    if (options.stop && (await options.stop())) {
      stopped = true;
      break;
    }
    lastStart = Date.now();
    const task: Promise<void> = run(item)
      .catch(() => {})
      .finally(() => {
        inFlight.delete(task);
      });
    inFlight.add(task);
  }
  await Promise.all(inFlight);
  return { stopped };
}

/** One port result in the shape the snapshot stores. */
export const portResult = (address: string, spec: PortSpec, probe: PortProbe): PortResult => ({
  address,
  port: spec.port,
  service: spec.service,
  category: spec.category,
  severity: spec.severity,
  banner: probe.banner,
  tls: probe.tls,
});
