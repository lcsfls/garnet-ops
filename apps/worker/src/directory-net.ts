/**
 * The network side of the directory sign-in (ADR 0020): resolving and checking the address,
 * StartTLS, the TLS handshake with its trust decision, and an LDAP client that only ever speaks
 * over a connection that has been verified.
 *
 * - The address is resolved here, every answer is checked against the address policy, and the
 *   connection goes to the address that was checked (the name is only used for TLS server name
 *   and host name verification), so DNS cannot change its answer between check and connect.
 * - Plain LDAP is never used for anything: `ldap://` servers are upgraded with StartTLS first and
 *   the connection is dropped if the server refuses or the handshake fails. No bind, no search
 *   and no password goes over an unencrypted connection.
 * - Trust is one of: the system's certificate store, only the configured CA certificate(s), or
 *   the pinned leaf certificate (SHA-256) like Proxmox (ADR 0012). The decision is made before
 *   the first LDAP byte is written; ldapts is handed a socket that is already trusted.
 * - Connect and handshake are bounded by a timeout.
 */
import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP, connect as tcpConnect } from "node:net";
import { type TLSSocket, connect as tlsConnect } from "node:tls";
import type { CertificateFacts, DirectoryProblem } from "@garnetops/core/directory";
import { checkHostAddress } from "@garnetops/core/hosts";
import { isForbiddenAddress } from "@garnetops/core/notifications";
import { certificateFingerprint, certificateName } from "@garnetops/core/proxmox";
import { Client, ExtendedRequest, MessageParser } from "ldapts";

/** A failure with a reason an admin can act on. The message never contains a password or directory content. */
export class DirectoryError extends Error {
  readonly problem: DirectoryProblem;
  /** The certificate that was presented, when the failure is about the certificate. */
  readonly seen: CertificateFacts | undefined;
  /** A Node error code of the TLS or socket failure (`CERT_HAS_EXPIRED`, `ECONNREFUSED`); safe to show an admin. */
  readonly detail: string | undefined;
  constructor(problem: DirectoryProblem, options: { seen?: CertificateFacts; detail?: string } = {}) {
    super(problem);
    this.name = "DirectoryError";
    this.problem = problem;
    this.seen = options.seen;
    this.detail = options.detail;
  }
}

/** Test hooks. Never set from configuration. */
export interface DirectoryNetHooks {
  /** Replaces name resolution (the address policy still judges the configured host). */
  resolve?: (host: string) => Promise<string>;
}

export interface ServerTarget {
  scheme: "ldaps" | "ldap";
  host: string;
  port: number;
}

/** Parses a stored, already validated server URL. */
export function targetOf(url: string): ServerTarget {
  const match = /^(ldaps|ldap):\/\/(\[[^\]]+\]|[^:/]+)(?::(\d+))?$/.exec(url);
  if (!match) throw new DirectoryError("internal");
  const scheme = match[1] as "ldaps" | "ldap";
  const host = (match[2] as string).replace(/^\[|\]$/g, "");
  return { scheme, host, port: match[3] ? Number(match[3]) : scheme === "ldaps" ? 636 : 389 };
}

export type TrustPolicy =
  | { kind: "system" }
  | { kind: "ca"; ca: string }
  /** `pin` is the confirmed fingerprint of this server, or null on first contact (then only inspecting is allowed). */
  | { kind: "pin"; pin: string | null };

/** Turns a stored host name into the IP address to connect to, refusing reserved addresses (ADR 0020). */
export async function resolveAddress(host: string, hooks: DirectoryNetHooks = {}): Promise<string> {
  const check = checkHostAddress(host);
  if (!check.ok) throw new DirectoryError("address-refused");
  if (check.kind !== "hostname") return check.address;
  if (hooks.resolve) return hooks.resolve(check.address);
  let answers: { address: string }[];
  try {
    answers = await lookup(check.address, { all: true, verbatim: true });
  } catch {
    throw new DirectoryError("unresolvable");
  }
  const first = answers[0];
  if (!first) throw new DirectoryError("unresolvable");
  if (answers.some((a) => isForbiddenAddress(a.address))) throw new DirectoryError("address-refused");
  return first.address;
}

function socketProblem(error: unknown): DirectoryError {
  if (error instanceof DirectoryError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT")
    return new DirectoryError("timeout", { detail: code });
  if (
    code.startsWith("ERR_SSL") ||
    code.startsWith("ERR_TLS") ||
    code === "EPROTO" ||
    /CERT|SSL|SELF_SIGNED|ISSUER|SIGNATURE|HOSTNAME/.test(code)
  ) {
    return new DirectoryError("tls-failed", { detail: code || undefined });
  }
  return new DirectoryError("unreachable", { detail: code || undefined });
}

function describeCertificate(socket: TLSSocket): CertificateFacts {
  const peer = socket.getPeerCertificate();
  if (!peer?.raw || peer.raw.length === 0) throw new DirectoryError("tls-failed");
  const x509 = new X509Certificate(peer.raw);
  return {
    fingerprint: certificateFingerprint(peer.raw),
    subject: certificateName(x509.subject),
    issuer: certificateName(x509.issuer),
    validFrom: new Date(x509.validFrom).toISOString(),
    validTo: new Date(x509.validTo).toISOString(),
    trusted: socket.authorized,
  };
}

/** Reads a complete LDAP message from a plain socket: used for the StartTLS answer only. */
function readStartTlsAnswer(
  socket: import("node:net").Socket,
  messageId: number,
  timeoutMs: number,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const parser = new MessageParser();
    const timer = setTimeout(() => done(new DirectoryError("timeout")), timeoutMs);
    function done(error: Error | null, status?: number) {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      if (error) reject(error);
      else resolve(status as number);
    }
    parser.on("message", (message) => done(null, message.status));
    parser.on("error", () => done(new DirectoryError("starttls-refused")));
    const onData = (data: Buffer) => {
      // The only message that may come is the answer to our request, with its id.
      parser.read(data, new Map([[`${messageId}`, { message: new ExtendedRequest({ messageId }) }]]));
    };
    const onError = (error: Error) => done(socketProblem(error));
    const onClose = () => done(new DirectoryError("unreachable"));
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

const START_TLS_OID = "1.3.6.1.4.1.1466.20037";

/**
 * Opens a verified TLS connection to one server: TLS from the start for `ldaps://`, StartTLS for
 * `ldap://`. The returned socket is already trusted according to `trust`. With a pin that does
 * not match (or no pin yet and `inspect` false) the socket is destroyed before anything is sent
 * and a {@link DirectoryError} carries the certificate that was seen.
 *
 * `inspect` is for reading a certificate an admin will confirm: no trust decision is made, and
 * the caller must not send anything over the socket.
 */
export async function openSecureSocket(
  target: ServerTarget,
  trust: TrustPolicy,
  options: { connectTimeoutMs: number; inspect?: boolean; hooks?: DirectoryNetHooks },
): Promise<{ socket: TLSSocket; certificate: CertificateFacts }> {
  const address = await resolveAddress(target.host, options.hooks);
  const inspect = options.inspect === true;
  const servername = isIP(target.host) ? undefined : target.host;
  const verify = !inspect && trust.kind !== "pin";
  const tlsOptions = {
    // SNI must be a name, not an address (RFC 6066). Host name verification uses the name from the configuration.
    ...(servername ? { servername } : {}),
    rejectUnauthorized: verify,
    minVersion: "TLSv1.2" as const,
    ...(trust.kind === "ca" ? { ca: trust.ca } : {}),
  };

  let plain: import("node:net").Socket | undefined;
  let secure: TLSSocket | undefined;
  try {
    if (target.scheme === "ldap") {
      plain = await new Promise<import("node:net").Socket>((resolve, reject) => {
        const s = tcpConnect({ host: address, port: target.port });
        const timer = setTimeout(() => {
          s.destroy();
          reject(new DirectoryError("timeout"));
        }, options.connectTimeoutMs);
        s.once("connect", () => {
          clearTimeout(timer);
          resolve(s);
        });
        s.once("error", (error) => {
          clearTimeout(timer);
          reject(socketProblem(error));
        });
      });
      plain.write(new ExtendedRequest({ messageId: 1, oid: START_TLS_OID }).write());
      const status = await readStartTlsAnswer(plain, 1, options.connectTimeoutMs);
      if (status !== 0) throw new DirectoryError("starttls-refused");
    }
    secure = await new Promise<TLSSocket>((resolve, reject) => {
      const s = plain
        ? // `host` is only used to verify the certificate: the name from the configuration, or the IP address.
          tlsConnect({ socket: plain, host: target.host, ...tlsOptions })
        : tlsConnect({ host: address, port: target.port, ...tlsOptions });
      const timer = setTimeout(() => {
        s.destroy();
        reject(new DirectoryError("timeout"));
      }, options.connectTimeoutMs);
      s.once("secureConnect", () => {
        clearTimeout(timer);
        resolve(s);
      });
      s.once("error", (error) => {
        clearTimeout(timer);
        reject(socketProblem(error));
      });
    });
    const certificate = describeCertificate(secure);
    if (!inspect && trust.kind === "pin") {
      if (trust.pin === null) throw new DirectoryError("certificate-not-confirmed", { seen: certificate });
      if (trust.pin !== certificate.fingerprint)
        throw new DirectoryError("certificate-changed", { seen: certificate });
    }
    return { socket: secure, certificate };
  } catch (error) {
    secure?.destroy();
    plain?.destroy();
    throw socketProblem(error);
  }
}

/** An LDAP client over a trusted socket, plus a way to close everything. */
export interface DirectoryConnection {
  client: Client;
  certificate: CertificateFacts;
  close(): Promise<void>;
}

/**
 * Connects, trusts and wraps the connection in an LDAP client. Nothing has been bound yet.
 * `operationTimeoutMs` bounds every LDAP operation.
 */
export async function connectDirectory(
  url: string,
  trust: TrustPolicy,
  options: { connectTimeoutMs: number; operationTimeoutMs: number; hooks?: DirectoryNetHooks },
): Promise<DirectoryConnection> {
  const target = targetOf(url);
  const { socket, certificate } = await openSecureSocket(target, trust, options);
  const client = new Client({
    // Only host and port are read from the URL; the socket below is the connection.
    url: `ldaps://${isIP(target.host) === 6 ? `[${target.host}]` : target.host}:${target.port}`,
    timeout: options.operationTimeoutMs,
    connectTimeout: options.connectTimeoutMs,
    // Names that come from the server are passed on as they are; the configured ones were checked when saved.
    strictDN: false,
    createSecureConnection: (() => socket) as unknown as typeof tlsConnect,
  });
  return {
    client,
    certificate,
    async close() {
      await client.unbind().catch(() => {});
      socket.destroy();
    },
  };
}
