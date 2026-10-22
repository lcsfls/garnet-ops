/**
 * The HTTP side of the UniFi integration (ADR 0022): resolving and checking the address, reading the
 * certificate a console presents, a client for the official local API that can only read, and the session of
 * the optional IPS preview.
 *
 * - The address is resolved here, every answer is checked, and the connection goes to the address that was
 *   checked (SNI and Host header carry the name), so DNS cannot change its answer between check and connect.
 * - The certificate is compared with the pinned fingerprint of the leaf certificate *before the first byte of
 *   the request is written*, so the API key and the password never reach a console that presents another
 *   certificate. A certificate that also chains to a public CA is still compared with the pin.
 * - Official client: GET only, to paths on an allow-list, no redirects, a cap on the size of every answer, a
 *   timeout on every request. IPS session: GET of the events of one site and POST of the console's login and
 *   logout, exactly (`isIpsRequest`); the session cookie and the CSRF token live in this object only.
 */
import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import type { IncomingHttpHeaders } from "node:http";
import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import { UnifiError } from "@garnetops/core";
import { checkHostAddress } from "@garnetops/core/hosts";
import { isForbiddenAddress } from "@garnetops/core/notifications";
import { certificateFingerprint, certificateName } from "@garnetops/core/proxmox";
import {
  API_BASES,
  type ApiBase,
  CONNECT_TIMEOUT_MS,
  isOfficialQuery,
  isOfficialReadPath,
  MAX_RESPONSE_BYTES,
  REQUEST_GAP_MS,
  REQUEST_TIMEOUT_MS,
} from "@garnetops/core/unifi";
import {
  IPS_MAX_BYTES,
  IPS_PATHS,
  type IpsFlavor,
  isIpsRequest,
  parseLoginResponse,
} from "@garnetops/core/unifi-ips";

/** What a console's leaf certificate looks like to an admin deciding whether to trust it. */
export interface CertificateInfo {
  /** SHA-256 of the DER certificate, upper-case hex pairs separated by colons. */
  fingerprint: string;
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  /** The certificate also verifies (chain and host name) against the public CA store. Informational. */
  caTrusted: boolean;
}

/** A certificate that is not the pinned one. Carries what was seen so an admin can decide. */
export class CertificateMismatch extends UnifiError {
  readonly seen: CertificateInfo;
  constructor(seen: CertificateInfo) {
    super("certificateChanged");
    this.seen = seen;
  }
}

/**
 * Turns a stored host name into the IP address to connect to. Every answer is checked, so a name that points at
 * loopback, link-local or metadata addresses is refused (ADR 0022). Private ranges stay allowed: consoles live
 * there. The address that is returned is the address the caller must connect to.
 */
export async function resolveUnifiAddress(host: string): Promise<string> {
  const check = checkHostAddress(host);
  if (!check.ok) throw new UnifiError("addressRefused");
  if (check.kind !== "hostname") return check.address;
  let answers: { address: string }[];
  try {
    answers = await lookup(check.address, { all: true, verbatim: true });
  } catch {
    throw new UnifiError("addressUnresolvable");
  }
  const first = answers[0];
  if (!first) throw new UnifiError("addressUnresolvable");
  if (answers.some((a) => isForbiddenAddress(a.address))) throw new UnifiError("addressRefused");
  return first.address;
}

export interface Endpoint {
  /** The name from the connection settings: SNI and Host header. */
  host: string;
  port: number;
  /** The checked IP address to connect to. */
  address: string;
}

const hostHeader = (e: Endpoint) => `${isIP(e.host) === 6 ? `[${e.host}]` : e.host}:${e.port}`;

/** Maps socket and TLS failures to a code the admin can act on. */
function connectionError(error: unknown): UnifiError {
  if (error instanceof UnifiError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new UnifiError("timeout");
  if (
    /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|ENOTFOUND|EAI_AGAIN|EADDRNOTAVAIL)$/.test(code)
  ) {
    return new UnifiError("unreachable");
  }
  if (
    code.startsWith("ERR_SSL") ||
    code.startsWith("ERR_TLS") ||
    code === "EPROTO" ||
    /CERT|SSL/.test(code)
  ) {
    return new UnifiError("tlsFailed");
  }
  return new UnifiError("unreachable");
}

function describe(socket: TLSSocket): CertificateInfo {
  const peer = socket.getPeerCertificate();
  if (!peer?.raw || peer.raw.length === 0) throw new UnifiError("tlsFailed");
  const x509 = new X509Certificate(peer.raw);
  return {
    fingerprint: certificateFingerprint(peer.raw),
    subject: certificateName(x509.subject),
    issuer: certificateName(x509.issuer),
    validFrom: new Date(x509.validFrom),
    validTo: new Date(x509.validTo),
    caTrusted: socket.authorized,
  };
}

/** Test hooks: certificate authority for a local test server. Never set from configuration. */
export interface TlsTestOptions {
  ca?: string;
}

/**
 * Opens a TLS connection to the checked address. Verification of the chain is switched off here on purpose
 * (consoles usually have a self-signed certificate); trust comes from the pin, which the caller checks before it
 * sends anything. TLS 1.2 or newer, HTTP/1.1 only.
 */
function openTls(
  endpoint: Endpoint,
  test: TlsTestOptions,
): Promise<{ socket: TLSSocket; info: CertificateInfo }> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({
      host: endpoint.address,
      port: endpoint.port,
      // SNI must be a name, not an address (RFC 6066).
      ...(isIP(endpoint.host) === 0 ? { servername: endpoint.host } : {}),
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"],
      ...(test.ca ? { ca: test.ca } : {}),
    });
    const fail = (error: unknown) => {
      socket.destroy();
      reject(connectionError(error));
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => fail(new UnifiError("timeout")));
    socket.once("error", fail);
    socket.once("secureConnect", () => {
      socket.setTimeout(0);
      socket.removeListener("error", fail);
      try {
        resolve({ socket, info: describe(socket) });
      } catch (error) {
        fail(error);
      }
    });
  });
}

/**
 * Reads the leaf certificate the console presents, without sending a request (and so without the key or the
 * password). The result is a proposal for an admin to confirm, never trusted by itself.
 */
export async function fetchLeafCertificate(
  endpoint: Endpoint,
  test: TlsTestOptions = {},
): Promise<CertificateInfo> {
  const { socket, info } = await openTls(endpoint, test);
  socket.destroy();
  return info;
}

/** Agent that opens only verified connections: the pin is checked before any request is written. */
class PinnedAgent extends Agent {
  private readonly endpoint: Endpoint;
  private readonly pinned: string;
  private readonly test: TlsTestOptions;
  private readonly onMismatch: (seen: CertificateInfo) => void;

  constructor(
    endpoint: Endpoint,
    pinned: string,
    test: TlsTestOptions,
    onMismatch: (seen: CertificateInfo) => void,
  ) {
    super({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
    this.endpoint = endpoint;
    this.pinned = pinned;
    this.test = test;
    this.onMismatch = onMismatch;
  }

  override createConnection(
    _options: unknown,
    callback?: (error: Error | null, socket: TLSSocket) => void,
  ): undefined {
    openTls(this.endpoint, this.test).then(
      ({ socket, info }) => {
        if (info.fingerprint !== this.pinned) {
          socket.destroy();
          this.onMismatch(info);
          callback?.(new CertificateMismatch(info), undefined as never);
          return;
        }
        callback?.(null, socket);
      },
      (error: unknown) => callback?.(error as Error, undefined as never),
    );
    return undefined;
  }
}

/* -------------------------------------------------------------------------- */
/* One pinned connection, one request at a time                                 */
/* -------------------------------------------------------------------------- */

/** Everything a client needs to know about the connection. */
export interface ClientOptions {
  endpoint: Endpoint;
  /** Pinned SHA-256 fingerprint of the leaf certificate. Required: there is no unpinned client. */
  pinned: string;
  /** Smaller limits and no pause in tests. */
  maxBytes?: number;
  timeoutMs?: number;
  gapMs?: number;
  test?: TlsTestOptions;
}

interface Reply {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

abstract class PinnedClient {
  /** Requests sent so far (a sync keeps a budget). */
  requests = 0;
  /** Set when the console presented a certificate other than the pin. */
  mismatch: CertificateInfo | null = null;
  protected readonly options: ClientOptions;
  private readonly agent: PinnedAgent;
  private lastStart = 0;

  protected constructor(options: ClientOptions) {
    this.options = options;
    this.agent = new PinnedAgent(options.endpoint, options.pinned, options.test ?? {}, (seen) => {
      this.mismatch = seen;
    });
  }

  close(): void {
    this.agent.destroy();
  }

  /** Sends one request. Callers have checked the allow-list; this paces, bounds and maps transport failures. */
  protected async exchange(
    method: "GET" | "POST",
    path: string,
    headers: Record<string, string>,
    body?: string,
    limits: { maxBytes?: number; timeoutMs?: number } = {},
  ): Promise<Reply> {
    const gap = this.options.gapMs ?? REQUEST_GAP_MS;
    const wait = this.lastStart + gap - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastStart = Date.now();
    this.requests++;
    try {
      return await this.once(method, path, headers, body, limits);
    } catch (error) {
      // A kept-alive connection the console closed meanwhile: one more try on a fresh connection (GET only).
      if (method === "GET" && (error as { retry?: boolean })?.retry) {
        return this.once(method, path, headers, body, limits);
      }
      if ((error as { retry?: boolean })?.retry) throw new UnifiError("unreachable");
      throw error;
    }
  }

  private once(
    method: "GET" | "POST",
    path: string,
    headers: Record<string, string>,
    body: string | undefined,
    limits: { maxBytes?: number; timeoutMs?: number },
  ): Promise<Reply> {
    const { endpoint } = this.options;
    const maxBytes = limits.maxBytes ?? this.options.maxBytes ?? MAX_RESPONSE_BYTES;
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (error: Error | null, value?: Reply) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(value as Reply);
      };
      const req = request({
        agent: this.agent,
        method,
        host: endpoint.address,
        port: endpoint.port,
        path,
        headers: {
          host: hostHeader(endpoint),
          accept: "application/json",
          "accept-encoding": "identity",
          "user-agent": "GarnetOps",
          ...(body !== undefined
            ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }
            : {}),
          ...headers,
        },
      });
      const timer = setTimeout(
        () => req.destroy(new UnifiError("timeout")),
        limits.timeoutMs ?? this.options.timeoutMs ?? REQUEST_TIMEOUT_MS,
      );
      req.on("error", (error: Error) => {
        const reused = (req as { reusedSocket?: boolean }).reusedSocket === true;
        const code = (error as NodeJS.ErrnoException).code;
        if (reused && (code === "ECONNRESET" || code === "EPIPE")) {
          return done(Object.assign(new Error("retry"), { retry: true }));
        }
        done(connectionError(error));
      });
      req.on("response", (res) => {
        const status = res.statusCode ?? 0;
        const limit = Math.round(maxBytes / 1024 / 1024) || 1;
        const declared = Number(res.headers["content-length"] ?? 0);
        if (declared > maxBytes) {
          done(new UnifiError("responseTooLarge", { limit }, status));
          res.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            // Settle first: destroying the response emits "aborted" at once.
            done(new UnifiError("responseTooLarge", { limit }, status));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", (error) => done(connectionError(error)));
        res.on("aborted", () => done(new UnifiError("unreachable", {}, status)));
        res.on("end", () => {
          if (status >= 300 && status < 400) return done(new UnifiError("redirected", {}, status));
          if (status === 429) return done(new UnifiError("rateLimited", {}, status));
          if (status >= 500) return done(new UnifiError("serverError", {}, status));
          done(null, { status, headers: res.headers, body: Buffer.concat(chunks) });
        });
      });
      if (body !== undefined) req.write(body);
      req.end();
    });
  }
}

const queryString = (query: Record<string, string>) => {
  const qs = new URLSearchParams(query).toString();
  return qs ? `?${qs}` : "";
};

function json(reply: Reply): unknown {
  try {
    return JSON.parse(reply.body.toString("utf8"));
  } catch {
    throw new UnifiError("invalidResponse", {}, reply.status);
  }
}

/* -------------------------------------------------------------------------- */
/* The official local API                                                      */
/* -------------------------------------------------------------------------- */

export interface UnifiClientOptions extends ClientOptions {
  /** Only ever put into the `X-API-KEY` header. */
  apiKey: string;
  /** Where the official API lives on this console. */
  base: ApiBase;
}

/**
 * A read-only client for the official UniFi Network API. `request` refuses every method but GET and every path
 * that is not on the allow-list of packages/core/src/unifi.ts, before a socket is opened; one request at a time,
 * with a short pause between requests, so a sync never loads the console heavily.
 */
export class UnifiClient extends PinnedClient {
  base: ApiBase;
  private readonly apiKey: string;

  constructor(options: UnifiClientOptions) {
    super(options);
    this.apiKey = options.apiKey;
    this.base = options.base;
  }

  /** The only way to ask: `request("GET", "/v1/info")`. */
  async request(
    method: string,
    path: string,
    query: Record<string, string> = {},
    limits: { timeoutMs?: number } = {},
  ): Promise<unknown> {
    if (method !== "GET")
      throw new Error(`Method ${method} is not allowed: the UniFi integration is read-only`);
    if (!isOfficialReadPath(path)) throw new Error("Path is not on the read-only allow-list");
    if (!isOfficialQuery(query)) throw new Error("Query is not on the read-only allow-list");
    const reply = await this.exchange(
      "GET",
      `${API_BASES[this.base]}${path}${queryString(query)}`,
      { "x-api-key": this.apiKey },
      undefined,
      limits,
    );
    if (reply.status === 401) throw new UnifiError("keyRejected", {}, reply.status);
    if (reply.status === 403) throw new UnifiError("forbidden", {}, reply.status);
    if (reply.status < 200 || reply.status >= 300) throw new UnifiError("notUnifi", {}, reply.status);
    return json(reply);
  }

  get(path: string, query?: Record<string, string>, limits?: { timeoutMs?: number }): Promise<unknown> {
    return this.request("GET", path, query, limits);
  }
}

/* -------------------------------------------------------------------------- */
/* The IPS preview session                                                     */
/* -------------------------------------------------------------------------- */

export interface IpsSessionOptions extends ClientOptions {
  flavor: IpsFlavor;
}

/** The cookies a console sets at login that carry the session. Anything else it sets is ignored. */
const SESSION_COOKIES = new Set(["TOKEN", "unifises", "csrf_token"]);

/**
 * The session of the optional IPS preview (ADR 0022). Cookie and CSRF token are fields of this object, never
 * written anywhere; `logout` (always called by the poll) forgets them. `request` enforces `isIpsRequest`: the
 * login and logout paths are the only POSTs that can ever be sent.
 */
export class IpsSession extends PinnedClient {
  private readonly flavor: IpsFlavor;
  private cookies = new Map<string, string>();
  private csrf: string | null = null;

  constructor(options: IpsSessionOptions) {
    super({ maxBytes: IPS_MAX_BYTES, ...options });
    this.flavor = options.flavor;
  }

  /** Whether a login succeeded and not yet ended. */
  get loggedIn(): boolean {
    return this.cookies.size > 0;
  }

  private async send(
    method: string,
    path: string,
    query: Record<string, string> = {},
    body?: unknown,
  ): Promise<Reply> {
    if (method !== "GET" && method !== "POST") throw new Error(`Method ${method} is not allowed`);
    if (!isIpsRequest(this.flavor, method, path, query))
      throw new Error("Request is not on the IPS allow-list");
    const headers: Record<string, string> = {};
    if (this.cookies.size > 0) {
      headers.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    }
    if (this.csrf) headers["x-csrf-token"] = this.csrf;
    const reply = await this.exchange(
      method,
      `${path}${queryString(query)}`,
      headers,
      body === undefined ? undefined : JSON.stringify(body),
    );
    this.remember(reply.headers);
    return reply;
  }

  /** Keeps the session cookie and the CSRF token of an answer, in memory only. */
  private remember(headers: IncomingHttpHeaders): void {
    for (const line of headers["set-cookie"] ?? []) {
      const pair = line.split(";", 1)[0] ?? "";
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (eq <= 0 || !SESSION_COOKIES.has(name)) continue;
      if (value === "" || /expires=Thu, 01 Jan 1970/i.test(line)) this.cookies.delete(name);
      else if (/^[\x21-\x7e]{1,4096}$/.test(value) && !/[;,"\\]/.test(value)) this.cookies.set(name, value);
      if (name === "csrf_token" && value) this.csrf = value;
    }
    const token = headers["x-updated-csrf-token"] ?? headers["x-csrf-token"];
    const text = Array.isArray(token) ? token[0] : token;
    if (text && /^[\x21-\x7e]{1,2048}$/.test(text)) this.csrf = text;
  }

  /** Logs in with the view-only user. The password is only ever put into the request body. */
  async login(username: string, password: string): Promise<{ rights: string[] }> {
    const reply = await this.send(
      "POST",
      IPS_PATHS[this.flavor].login,
      {},
      { username, password, remember: false },
    );
    if (reply.status === 404) throw new UnifiError("notUnifi", {}, reply.status);
    if (reply.status < 200 || reply.status >= 300 || this.cookies.size === 0) {
      this.forget();
      throw new UnifiError("ipsLoginRejected", {}, reply.status);
    }
    let body: unknown = null;
    try {
      body = JSON.parse(reply.body.toString("utf8"));
    } catch {
      // An answer without a body is fine: the cookie is what matters. No rights are then reported.
    }
    return parseLoginResponse(body);
  }

  /** One page of events of one site, from `startMs` to `endMs`. */
  async events(siteRef: string, startMs: number, endMs: number, limit: number): Promise<unknown> {
    const path = `${IPS_PATHS[this.flavor].prefix}/api/s/${siteRef}/stat/ips/event`;
    const reply = await this.send("GET", path, {
      start: String(Math.trunc(startMs)),
      end: String(Math.trunc(endMs)),
      _limit: String(limit),
    });
    if (reply.status === 401 || reply.status === 403)
      throw new UnifiError("ipsSessionRejected", {}, reply.status);
    if (reply.status === 404) throw new UnifiError("ipsEndpointMissing", {}, reply.status);
    if (reply.status < 200 || reply.status >= 300) throw new UnifiError("notUnifi", {}, reply.status);
    return json(reply);
  }

  /** Logs out (best effort) and forgets cookie and token. Never throws. */
  async logout(): Promise<void> {
    try {
      if (this.loggedIn) await this.send("POST", IPS_PATHS[this.flavor].logout);
    } catch {
      // The session ends with the cookie being forgotten; the console expires it by itself.
    } finally {
      this.forget();
    }
  }

  private forget(): void {
    this.cookies.clear();
    this.csrf = null;
  }
}
