/**
 * Outbound HTTPS to a fixed public host named in code (first written for ADR 0016; today only the opt-in
 * Certificate Transparency lookups of website monitoring, ADR 0023 and 0033), never to an address from the
 * database or from a form.
 *
 * - The name is resolved by the connection's own lookup and *every* answer must be a public
 *   address: private, loopback, link-local, metadata and reserved addresses are refused, so a
 *   poisoned DNS answer cannot aim the worker at the internal network, and the address that was
 *   checked is the address that is connected to (no second lookup in between).
 * - TLS 1.2 or newer, the certificate chain and host name always verified against the system's
 *   certificate store. No redirects: a redirect is an error, not something to follow.
 * - Connection timeout, an overall deadline that also covers a slowly dripping body, and (for the
 *   callers) a cap on the bytes they read.
 * - Only GET, only the headers the caller names, no cookies, no proxy.
 */
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import type { IncomingHttpHeaders } from "node:http";
import { request } from "node:https";
import { isIP } from "node:net";
import { classifyAddress } from "@garnetops/core/ai-endpoint";

export type OutboundErrorCode =
  | "refusedAddress"
  | "unreachable"
  | "timeout"
  | "redirected"
  | "httpStatus"
  | "tooLarge"
  | "tls";

export class OutboundError extends Error {
  readonly code: OutboundErrorCode;
  readonly status: number | null;
  /** The answer's headers for `httpStatus` (a registry's 401 names its token service in them). */
  readonly headers: IncomingHttpHeaders | null;
  constructor(
    code: OutboundErrorCode,
    status: number | null = null,
    headers: IncomingHttpHeaders | null = null,
  ) {
    super(code === "httpStatus" ? `HTTP ${status}` : code);
    this.name = "OutboundError";
    this.code = code;
    this.status = status;
    this.headers = headers;
  }
}

type LookupCallback = (
  error: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;
export type Lookup = (hostname: string, options: object, callback: LookupCallback) => void;

/** Every address the system resolver has for a name (`getaddrinfo`, as a connection would resolve it). */
export function systemAddresses(hostname: string, options: object = {}): Promise<LookupAddress[]> {
  return new Promise((resolve, reject) =>
    dnsLookup(hostname, { ...options, all: true }, (error, addresses) =>
      error ? reject(error) : resolve(addresses as LookupAddress[]),
    ),
  );
}

/** A lookup that resolves with `resolveAll` and refuses the name unless every answer is a public address. */
export function lookupVia(
  resolveAll: (hostname: string, options: object) => Promise<LookupAddress[]>,
): Lookup {
  return (hostname, options, callback) => {
    resolveAll(hostname, options).then(
      (list) => {
        if (list.length === 0 || list.some((a) => classifyAddress(a.address) !== "public")) {
          return callback(Object.assign(new Error("refused address"), { code: "EREFUSED_ADDRESS" }), []);
        }
        if ((options as { all?: boolean }).all) return callback(null, list);
        const first = list[0] as LookupAddress;
        callback(null, first.address, first.family);
      },
      (error: NodeJS.ErrnoException) => callback(error, []),
    );
  };
}

/** Resolves a name through the system resolver and refuses it unless every answer is a public address. */
export const publicLookup: Lookup = lookupVia(systemAddresses);

export interface OutboundOptions {
  host: string;
  /** GET by default; HEAD for a registry manifest, which does not count as a pull. */
  method?: "GET" | "HEAD";
  /** Path and query. */
  path: string;
  headers?: Record<string, string>;
  /** Overall deadline for headers and body. */
  timeoutMs: number;
  connectTimeoutMs?: number;
  /** A lookup in place of `publicLookup` (one that also asks the organisation's public DNS); it must keep the address policy. */
  lookup?: Lookup;
  /** Tests only: another lookup (to reach a local server), its certificate, and its port. */
  test?: { lookup?: Lookup; ca?: string; port?: number };
}

export interface OutboundResponse {
  status: number;
  headers: IncomingHttpHeaders;
  /** The body as it arrives; ends with an `OutboundError` on a timeout or a broken connection. */
  body: AsyncGenerator<Buffer>;
  /** Stops the transfer. */
  close(): void;
}

function mapError(error: unknown): OutboundError {
  if (error instanceof OutboundError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "EREFUSED_ADDRESS") return new OutboundError("refusedAddress");
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new OutboundError("timeout");
  if (
    code.startsWith("ERR_TLS") ||
    code.startsWith("ERR_SSL") ||
    code === "CERT_HAS_EXPIRED" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
  ) {
    return new OutboundError("tls");
  }
  return new OutboundError("unreachable");
}

/**
 * GET (or HEAD) over HTTPS. Resolves with the status and a body stream once the headers are in. A 3xx is
 * `redirected` and any other status outside 2xx is `httpStatus`; in both cases the body is not read.
 */
export function httpsGet(options: OutboundOptions): Promise<OutboundResponse> {
  // A name goes through `publicLookup`; an address literal never would, so it is checked here.
  const literal = options.host.replace(/^\[|\]$/g, "");
  if (isIP(literal) !== 0 && !options.test && classifyAddress(literal) !== "public") {
    return Promise.reject(new OutboundError("refusedAddress"));
  }
  return new Promise((resolve, reject) => {
    let finished = false;
    const fail = (error: unknown) => {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      reject(mapError(error));
    };
    const req = request({
      host: options.host,
      port: options.test?.port ?? 443,
      path: options.path,
      method: options.method ?? "GET",
      servername: options.host,
      lookup: options.test?.lookup ?? options.lookup ?? publicLookup,
      ...(options.test?.ca ? { ca: options.test.ca } : {}),
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
      agent: false,
      timeout: options.connectTimeoutMs ?? 10_000,
      headers: { "user-agent": "GarnetOps", accept: "*/*", ...options.headers },
    });
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      req.destroy(new OutboundError("timeout"));
    }, options.timeoutMs);
    req.on("timeout", () => req.destroy(new OutboundError("timeout")));
    req.on("error", fail);
    req.on("response", (res) => {
      const status = res.statusCode ?? 0;
      if (status < 200 || status >= 300) {
        res.destroy();
        req.destroy();
        clearTimeout(deadline);
        finished = true;
        return reject(
          new OutboundError(status >= 300 && status < 400 ? "redirected" : "httpStatus", status, res.headers),
        );
      }
      finished = true;
      async function* body(): AsyncGenerator<Buffer> {
        try {
          for await (const chunk of res) yield chunk as Buffer;
        } catch (error) {
          throw timedOut ? new OutboundError("timeout") : mapError(error);
        } finally {
          clearTimeout(deadline);
          res.destroy();
        }
      }
      resolve({
        status,
        headers: res.headers,
        body: body(),
        close: () => {
          clearTimeout(deadline);
          res.destroy();
          req.destroy();
        },
      });
    });
    req.end();
  });
}

/** Reads a small body completely; `tooLarge` if it exceeds `maxBytes`. */
export async function readCapped(response: OutboundResponse, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBytes) throw new OutboundError("tooLarge");
      chunks.push(chunk);
    }
  } catch (error) {
    response.close();
    throw error;
  }
  return Buffer.concat(chunks);
}
