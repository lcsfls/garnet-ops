/**
 * The HTTP side of the Proxmox VE integration (ADR 0012): resolving and checking the address,
 * reading the certificate a server presents, and a client that can only read.
 *
 * - The address is resolved here, every answer is checked, and the connection goes to the
 *   address that was checked (SNI and Host header carry the name), so DNS cannot change its
 *   answer between the check and the connection.
 * - The certificate is verified against the pinned fingerprint of the leaf certificate
 *   *before the first byte of the request is written*, so the token never reaches a server
 *   that presents another certificate. A certificate that also verifies against a public CA
 *   is still compared with the pin.
 * - The client sends GET only, to paths on an allow-list, follows no redirects, caps the size
 *   of every answer, bounds every request by a timeout and parses defensively.
 */
import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import { ProxmoxError } from "@garnetops/core";
import { checkHostAddress } from "@garnetops/core/hosts";
import { isForbiddenAddress } from "@garnetops/core/notifications";
import {
  CONNECT_TIMEOUT_MS,
  certificateFingerprint,
  certificateName,
  isReadPath,
  MAX_RESPONSE_BYTES,
  READ_QUERIES,
  REQUEST_GAP_MS,
  REQUEST_TIMEOUT_MS,
  unwrap,
} from "@garnetops/core/proxmox";

/** What a server's leaf certificate looks like to an admin deciding whether to trust it. */
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
export class CertificateMismatch extends ProxmoxError {
  readonly seen: CertificateInfo;
  constructor(seen: CertificateInfo) {
    super("certificateChanged");
    this.seen = seen;
  }
}

/**
 * Turns a stored host name into the IP address to connect to. Every answer is checked, so a
 * name that points at loopback, link-local or metadata addresses is refused (ADR 0012). The
 * address that is returned is the address the caller must connect to.
 */
export async function resolveProxmoxAddress(host: string): Promise<string> {
  const check = checkHostAddress(host);
  if (!check.ok) throw new ProxmoxError("addressRefused");
  if (check.kind !== "hostname") return check.address;
  let answers: { address: string }[];
  try {
    answers = await lookup(check.address, { all: true, verbatim: true });
  } catch {
    throw new ProxmoxError("addressUnresolvable");
  }
  const first = answers[0];
  if (!first) throw new ProxmoxError("addressUnresolvable");
  if (answers.some((a) => isForbiddenAddress(a.address))) throw new ProxmoxError("addressRefused");
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
function connectionError(error: unknown): ProxmoxError {
  if (error instanceof ProxmoxError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new ProxmoxError("timeout");
  if (
    /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|ENOTFOUND|EAI_AGAIN|EADDRNOTAVAIL)$/.test(code)
  ) {
    return new ProxmoxError("unreachable");
  }
  if (
    code.startsWith("ERR_SSL") ||
    code.startsWith("ERR_TLS") ||
    code === "EPROTO" ||
    /CERT|SSL/.test(code)
  ) {
    return new ProxmoxError("tlsFailed");
  }
  return new ProxmoxError("unreachable");
}

function describe(socket: TLSSocket): CertificateInfo {
  const peer = socket.getPeerCertificate();
  if (!peer?.raw || peer.raw.length === 0) throw new ProxmoxError("tlsFailed");
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
 * Opens a TLS connection to the checked address. Verification of the chain is switched off
 * here on purpose (Proxmox usually has a self-signed certificate); trust comes from the pin,
 * which the caller checks before it sends anything. TLS 1.2 or newer, HTTP/1.1 only.
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
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => fail(new ProxmoxError("timeout")));
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
 * Reads the leaf certificate the server presents, without sending a request (and so without
 * the token). The result is a proposal for an admin to confirm, never trusted by itself.
 */
export async function fetchLeafCertificate(
  endpoint: Endpoint,
  test: TlsTestOptions = {},
): Promise<CertificateInfo> {
  const { socket, info } = await openTls(endpoint, test);
  socket.destroy();
  return info;
}

/** Everything a client needs to know about the connection. */
export interface ClientOptions {
  endpoint: Endpoint;
  /** Pinned SHA-256 fingerprint of the leaf certificate. Required: there is no unpinned client. */
  pinned: string;
  /** `user@realm!tokenid` and the secret; only ever put into the Authorization header. */
  tokenId: string;
  tokenSecret: string;
  /** Smaller limits and no pause in tests. */
  maxBytes?: number;
  timeoutMs?: number;
  gapMs?: number;
  test?: TlsTestOptions;
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

/**
 * A read-only Proxmox VE API client. `request` refuses every method but GET and every path
 * that is not on the allow-list of packages/core/src/proxmox.ts; one request at a time, with
 * a short pause between requests, so a sync never loads the Proxmox API heavily.
 */
export class ProxmoxClient {
  /** Requests sent so far (a sync keeps a budget). */
  requests = 0;
  /** Set when the server presented a certificate other than the pin. */
  mismatch: CertificateInfo | null = null;
  private readonly agent: PinnedAgent;
  private readonly authorization: string;
  private lastStart = 0;
  private readonly options: ClientOptions;

  constructor(options: ClientOptions) {
    this.options = options;
    this.authorization = `PVEAPIToken=${options.tokenId}=${options.tokenSecret}`;
    this.agent = new PinnedAgent(options.endpoint, options.pinned, options.test ?? {}, (seen) => {
      this.mismatch = seen;
    });
  }

  close(): void {
    this.agent.destroy();
  }

  /** The only way to ask: `request("GET", "/version")`. Anything but GET is refused before a socket is opened. */
  async request(
    method: string,
    path: string,
    query: Record<string, string> = {},
    limits: { timeoutMs?: number } = {},
  ): Promise<unknown> {
    if (method !== "GET")
      throw new Error(`Method ${method} is not allowed: the Proxmox integration is read-only`);
    if (!isReadPath(path)) throw new Error("Path is not on the read-only allow-list");
    for (const [key, value] of Object.entries(query)) {
      if (READ_QUERIES[key] !== value) throw new Error("Query is not on the read-only allow-list");
    }
    const gap = this.options.gapMs ?? REQUEST_GAP_MS;
    const wait = this.lastStart + gap - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastStart = Date.now();
    this.requests++;
    try {
      return await this.once(path, query, limits.timeoutMs);
    } catch (error) {
      // A kept-alive connection the server closed meanwhile: one more try on a fresh connection.
      if ((error as { retry?: boolean })?.retry) return this.once(path, query, limits.timeoutMs);
      throw error;
    }
  }

  get(path: string, query?: Record<string, string>, limits?: { timeoutMs?: number }): Promise<unknown> {
    return this.request("GET", path, query, limits);
  }

  private once(path: string, query: Record<string, string>, timeoutMs?: number): Promise<unknown> {
    const { endpoint } = this.options;
    const maxBytes = this.options.maxBytes ?? MAX_RESPONSE_BYTES;
    const qs = new URLSearchParams(query).toString();
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (error: Error | null, value?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(value);
      };
      const req = request({
        agent: this.agent,
        method: "GET",
        host: endpoint.address,
        port: endpoint.port,
        path: `/api2/json${path}${qs ? `?${qs}` : ""}`,
        headers: {
          host: hostHeader(endpoint),
          authorization: this.authorization,
          accept: "application/json",
          "accept-encoding": "identity",
          "user-agent": "GarnetOps",
        },
      });
      const timer = setTimeout(
        () => req.destroy(new ProxmoxError("timeout")),
        timeoutMs ?? this.options.timeoutMs ?? REQUEST_TIMEOUT_MS,
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
        const declared = Number(res.headers["content-length"] ?? 0);
        if (declared > maxBytes) {
          done(new ProxmoxError("responseTooLarge", { limit: Math.round(maxBytes / 1024 / 1024) }, status));
          res.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            // Settle first: destroying the response emits "aborted" at once.
            done(new ProxmoxError("responseTooLarge", { limit: Math.round(maxBytes / 1024 / 1024) }, status));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", (error) => done(connectionError(error)));
        res.on("aborted", () => done(new ProxmoxError("unreachable", {}, status)));
        res.on("end", () => {
          if (status >= 300 && status < 400) return done(new ProxmoxError("redirected", {}, status));
          if (status === 401) return done(new ProxmoxError("tokenRejected", {}, status));
          if (status === 403) return done(new ProxmoxError("forbidden", {}, status));
          if (status >= 500) return done(new ProxmoxError("serverError", {}, status));
          if (status < 200 || status >= 300) return done(new ProxmoxError("notProxmox", {}, status));
          try {
            done(null, unwrap(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
          } catch {
            done(new ProxmoxError("invalidResponse", {}, status));
          }
        });
      });
      req.end();
    });
  }
}
