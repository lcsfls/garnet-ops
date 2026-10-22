/**
 * The HTTP side of the Wazuh integration (ADR 0015): resolving and checking the address, reading
 * the certificate an endpoint presents, and two clients that can only read.
 *
 * - The address is resolved here, every answer is checked, and the connection goes to the address
 *   that was checked (SNI and Host header carry the name), so DNS cannot change its answer
 *   between the check and the connection.
 * - Trust is either a pinned SHA-256 fingerprint of the leaf certificate, compared *before the
 *   first byte of the request is written* so the password never reaches a server that presents
 *   another certificate, or a certificate authority the admin uploaded (chain and host name
 *   verified by TLS).
 * - The manager client sends GET only, except the login `POST /security/user/authenticate`; the
 *   JWT it returns lives in memory for the length of a sync and is never stored or logged. The
 *   indexer client sends GET to three paths and POST `_search`/`_count` with bodies built by the
 *   fixed templates of packages/core/src/wazuh.ts, never by input.
 * - No redirects, a size cap and a timeout on every answer, and every answer is parsed
 *   defensively by the caller.
 */
import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import { type WazuhEndpointKind, WazuhError } from "@garnetops/core";
import { checkHostAddress } from "@garnetops/core/hosts";
import { isForbiddenAddress } from "@garnetops/core/notifications";
import { certificateFingerprint, certificateName } from "@garnetops/core/proxmox";
import {
  buildIndexerRequest,
  CONNECT_TIMEOUT_MS,
  type IndexerQuery,
  isIndexerRequestAllowed,
  isManagerRequestAllowed,
  MANAGER_LOGIN_PATH,
  MAX_RESPONSE_BYTES,
  parseLoginToken,
  REQUEST_GAP_MS,
  REQUEST_TIMEOUT_MS,
  type WazuhAdapter,
} from "@garnetops/core/wazuh";

/** What an endpoint's leaf certificate looks like to an admin deciding whether to trust it. */
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
export class CertificateMismatch extends WazuhError {
  readonly seen: CertificateInfo;
  constructor(seen: CertificateInfo, endpoint?: WazuhEndpointKind) {
    super("certificateChanged", endpoint ? { endpoint } : {});
    this.seen = seen;
  }
}

/** How the connection is trusted: the pinned leaf certificate, or the admin's certificate authority. */
export type Trust = { mode: "pin"; fingerprint: string } | { mode: "ca"; ca: string };

/**
 * Turns a stored host name into the IP address to connect to. Every answer is checked, so a name
 * that points at loopback, link-local or metadata addresses is refused (ADR 0015). The address
 * that is returned is the address the caller must connect to.
 */
export async function resolveWazuhAddress(host: string): Promise<string> {
  const check = checkHostAddress(host);
  if (!check.ok) throw new WazuhError("addressRefused");
  if (check.kind !== "hostname") return check.address;
  let answers: { address: string }[];
  try {
    answers = await lookup(check.address, { all: true, verbatim: true });
  } catch {
    throw new WazuhError("addressUnresolvable");
  }
  const first = answers[0];
  if (!first) throw new WazuhError("addressUnresolvable");
  if (answers.some((a) => isForbiddenAddress(a.address))) throw new WazuhError("addressRefused");
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
function connectionError(error: unknown, caMode: boolean): WazuhError {
  if (error instanceof WazuhError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new WazuhError("timeout");
  if (
    /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|ENOTFOUND|EAI_AGAIN|EADDRNOTAVAIL)$/.test(code)
  ) {
    return new WazuhError("unreachable");
  }
  if (caMode && /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|HOSTNAME|ALTNAME|ISSUER/i.test(code)) {
    return new WazuhError("caRejected");
  }
  if (
    code.startsWith("ERR_SSL") ||
    code.startsWith("ERR_TLS") ||
    code === "EPROTO" ||
    /CERT|SSL/.test(code)
  ) {
    return new WazuhError("tlsFailed");
  }
  return new WazuhError("unreachable");
}

function describe(socket: TLSSocket): CertificateInfo {
  const peer = socket.getPeerCertificate();
  if (!peer?.raw || peer.raw.length === 0) throw new WazuhError("tlsFailed");
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
 * Opens a TLS connection to the checked address. With a pin, verification of the chain is
 * switched off here on purpose (Wazuh uses self-signed certificates); trust comes from the pin,
 * which the caller checks before it sends anything. With a custom authority TLS verifies chain
 * and host name itself. TLS 1.2 or newer, HTTP/1.1 only.
 */
function openTls(
  endpoint: Endpoint,
  trust: Trust | null,
  test: TlsTestOptions,
): Promise<{ socket: TLSSocket; info: CertificateInfo }> {
  const caMode = trust?.mode === "ca";
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({
      host: endpoint.address,
      port: endpoint.port,
      // SNI must be a name, not an address (RFC 6066).
      ...(isIP(endpoint.host) === 0 ? { servername: endpoint.host } : {}),
      rejectUnauthorized: caMode,
      minVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"],
      ...(trust?.mode === "ca" ? { ca: trust.ca } : test.ca ? { ca: test.ca } : {}),
    });
    const fail = (error: unknown) => {
      socket.destroy();
      reject(connectionError(error, caMode));
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => fail(new WazuhError("timeout")));
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
 * Reads the leaf certificate the endpoint presents, without sending a request (and so without
 * the password). With a pin the result is a proposal for an admin to confirm, never trusted by
 * itself. With a certificate authority the handshake itself verifies the certificate: an
 * endpoint that does not chain to the authority fails with `caRejected`.
 */
export async function fetchLeafCertificate(
  endpoint: Endpoint,
  trust: Trust | null = null,
  test: TlsTestOptions = {},
): Promise<CertificateInfo> {
  const { socket, info } = await openTls(endpoint, trust, test);
  socket.destroy();
  return info;
}

/** Agent that opens only verified connections: the pin is checked before any request is written. */
class TrustedAgent extends Agent {
  private readonly kind: WazuhEndpointKind;
  private readonly endpoint: Endpoint;
  private readonly trust: Trust;
  private readonly test: TlsTestOptions;
  private readonly onMismatch: (seen: CertificateInfo) => void;

  constructor(
    kind: WazuhEndpointKind,
    endpoint: Endpoint,
    trust: Trust,
    test: TlsTestOptions,
    onMismatch: (seen: CertificateInfo) => void,
  ) {
    super({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
    this.kind = kind;
    this.endpoint = endpoint;
    this.trust = trust;
    this.test = test;
    this.onMismatch = onMismatch;
  }

  override createConnection(
    _options: unknown,
    callback?: (error: Error | null, socket: TLSSocket) => void,
  ): undefined {
    openTls(this.endpoint, this.trust, this.test).then(
      ({ socket, info }) => {
        if (this.trust.mode === "pin" && info.fingerprint !== this.trust.fingerprint) {
          socket.destroy();
          this.onMismatch(info);
          callback?.(new CertificateMismatch(info, this.kind), undefined as never);
          return;
        }
        callback?.(null, socket);
      },
      (error: unknown) => callback?.(error as Error, undefined as never),
    );
    return undefined;
  }
}

/** Everything a client needs to know about one endpoint. */
export interface ClientOptions {
  kind: WazuhEndpointKind;
  endpoint: Endpoint;
  /** Required: there is no untrusted client. */
  trust: Trust;
  /** Smaller limits and no pause in tests. */
  maxBytes?: number;
  timeoutMs?: number;
  gapMs?: number;
  test?: TlsTestOptions;
}

export interface RequestInput {
  query?: Record<string, string>;
  /** Built by the templates in packages/core/src/wazuh.ts; never from input. */
  body?: Record<string, unknown>;
  authorization: string;
}

/**
 * The shared machinery of both clients. `allow` is the method and path allow-list of the
 * endpoint; a request that is not on it throws before a socket is opened. One request at a
 * time, with a short pause between requests, so a sync never loads Wazuh heavily.
 */
class WazuhHttp {
  /** Requests sent so far (a sync keeps a budget). */
  requests = 0;
  /** Set when the endpoint presented a certificate other than the pin. */
  mismatch: CertificateInfo | null = null;
  private readonly agent: TrustedAgent;
  private lastStart = 0;
  protected readonly options: ClientOptions;
  private readonly allow: (method: string, path: string, query: Record<string, string>) => boolean;

  constructor(
    options: ClientOptions,
    allow: (method: string, path: string, query: Record<string, string>) => boolean,
  ) {
    this.options = options;
    this.allow = allow;
    this.agent = new TrustedAgent(
      options.kind,
      options.endpoint,
      options.trust,
      options.test ?? {},
      (seen) => {
        this.mismatch = seen;
      },
    );
  }

  close(): void {
    this.agent.destroy();
  }

  /** Every request goes through here, and so through the allow-list. */
  protected async send(method: string, path: string, input: RequestInput): Promise<unknown> {
    const query = input.query ?? {};
    if (!this.allow(method, path, query)) {
      throw new Error(
        `${method} ${path} is not on the read-only allow-list of the Wazuh ${this.options.kind}`,
      );
    }
    const gap = this.options.gapMs ?? REQUEST_GAP_MS;
    const wait = this.lastStart + gap - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastStart = Date.now();
    this.requests++;
    try {
      return await this.once(method, path, input);
    } catch (error) {
      // A kept-alive connection the server closed meanwhile: one more try on a fresh connection.
      if ((error as { retry?: boolean })?.retry) return this.once(method, path, input);
      throw error;
    }
  }

  private once(method: string, path: string, input: RequestInput): Promise<unknown> {
    const { endpoint, kind } = this.options;
    const maxBytes = this.options.maxBytes ?? MAX_RESPONSE_BYTES;
    const limitMb = Math.max(1, Math.round(maxBytes / 1024 / 1024));
    const qs = new URLSearchParams(input.query ?? {}).toString();
    const payload = input.body === undefined ? null : Buffer.from(JSON.stringify(input.body), "utf8");
    const caMode = this.options.trust.mode === "ca";
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (error: Error | null, value?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) {
          // A changed certificate keeps what was seen; any other error is attributed to this endpoint.
          reject(
            error instanceof WazuhError && !(error instanceof CertificateMismatch)
              ? error.forEndpoint(kind)
              : error,
          );
        } else resolve(value);
      };
      const req = request({
        agent: this.agent,
        method,
        host: endpoint.address,
        port: endpoint.port,
        path: `${path}${qs ? `?${qs}` : ""}`,
        headers: {
          host: hostHeader(endpoint),
          authorization: input.authorization,
          accept: "application/json",
          "accept-encoding": "identity",
          "user-agent": "GarnetOps",
          ...(method === "POST"
            ? { "content-type": "application/json", "content-length": payload ? payload.length : 0 }
            : {}),
        },
      });
      const timer = setTimeout(
        () => req.destroy(new WazuhError("timeout")),
        this.options.timeoutMs ?? REQUEST_TIMEOUT_MS,
      );
      req.on("error", (error: Error) => {
        const reused = (req as { reusedSocket?: boolean }).reusedSocket === true;
        const code = (error as NodeJS.ErrnoException).code;
        if (reused && (code === "ECONNRESET" || code === "EPIPE")) {
          return done(Object.assign(new Error("retry"), { retry: true }));
        }
        done(connectionError(error, caMode));
      });
      req.on("response", (res) => {
        const status = res.statusCode ?? 0;
        const declared = Number(res.headers["content-length"] ?? 0);
        if (declared > maxBytes) {
          done(new WazuhError("responseTooLarge", { limit: limitMb }, status));
          res.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            // Settle first: destroying the response emits "aborted" at once.
            done(new WazuhError("responseTooLarge", { limit: limitMb }, status));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", (error) => done(connectionError(error, caMode)));
        res.on("aborted", () => done(new WazuhError("unreachable", {}, status)));
        res.on("end", () => {
          if (status >= 300 && status < 400) return done(new WazuhError("redirected", {}, status));
          if (status === 401) return done(new WazuhError("loginRejected", {}, status));
          if (status === 403) return done(new WazuhError("forbidden", {}, status));
          if (status === 429) return done(new WazuhError("rateLimited", {}, status));
          if (status >= 500) return done(new WazuhError("serverError", {}, status));
          if (status < 200 || status >= 300) return done(new WazuhError("notWazuh", {}, status));
          try {
            done(null, JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            done(new WazuhError("invalidResponse", {}, status));
          }
        });
      });
      req.end(payload ?? undefined);
    });
  }
}

const basic = (user: string, password: string) =>
  `Basic ${Buffer.from(`${user}:${password}`, "utf8").toString("base64")}`;

/**
 * The read-only client of the Wazuh manager API. It logs in once per sync with the dedicated
 * user (HTTP basic over the trusted connection), keeps the JWT in this object only and asks for
 * a new one once if the manager says it expired. The token is never written anywhere.
 */
export class ManagerClient extends WazuhHttp {
  private token: string | null = null;
  private readonly user: string;
  private readonly password: string;

  constructor(options: Omit<ClientOptions, "kind"> & { username: string; password: string }) {
    const { username, password, ...rest } = options;
    super({ ...rest, kind: "manager" }, isManagerRequestAllowed);
    this.user = username;
    this.password = password;
  }

  /** `POST /security/user/authenticate`: the only POST this client can send. */
  async login(): Promise<void> {
    const body = await this.send("POST", MANAGER_LOGIN_PATH, {
      authorization: basic(this.user, this.password),
    });
    const token = parseLoginToken(body);
    if (!token) throw new WazuhError("notWazuh", { endpoint: "manager" });
    this.token = token;
  }

  /** The only way to ask for data: GET of a path on the allow-list. */
  async get(path: string, query: Record<string, string> = {}): Promise<unknown> {
    if (!this.token) await this.login();
    try {
      return await this.send("GET", path, { query, authorization: `Bearer ${this.token}` });
    } catch (error) {
      // An expired token (a long sync) is the one case for a second login; a rejected password is not.
      if (error instanceof WazuhError && error.status === 401 && path !== MANAGER_LOGIN_PATH) {
        await this.login();
        return this.send("GET", path, { query, authorization: `Bearer ${this.token}` });
      }
      throw error;
    }
  }

  override close(): void {
    this.token = null;
    super.close();
  }
}

/**
 * The read-only client of the Wazuh indexer. It reads the root, the roles of its own user, and
 * runs the fixed query templates; it has no method that takes a query from outside.
 */
export class IndexerClient extends WazuhHttp {
  private readonly authorization: string;

  constructor(options: Omit<ClientOptions, "kind"> & { username: string; password: string }) {
    const { username, password, ...rest } = options;
    super({ ...rest, kind: "indexer" }, isIndexerRequestAllowed);
    this.authorization = basic(username, password);
  }

  get(path: string): Promise<unknown> {
    return this.send("GET", path, { authorization: this.authorization });
  }

  /** Runs one of the fixed questions of packages/core/src/wazuh.ts. */
  run(adapter: WazuhAdapter, question: IndexerQuery): Promise<unknown> {
    const built = buildIndexerRequest(adapter, question);
    return this.send(built.method, built.path, { body: built.body, authorization: this.authorization });
  }
}
