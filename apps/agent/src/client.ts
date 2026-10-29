/**
 * The agent's way to GarnetOps (ADR 0034): HTTPS only, the certificate checked against the system store (or a CA file), no redirects,
 * every request after enrolment signed with the host's Ed25519 key, answers capped.
 */
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { signRequest } from "@garnetops/core/agent";

const MAX_ANSWER = 1024 * 1024;

export class ServerError extends Error {
  readonly status: number;
  readonly code: string | null;
  constructor(status: number, code: string | null) {
    super(`GarnetOps answered ${status}${code ? ` (${code})` : ""}`);
    this.name = "ServerError";
    this.status = status;
    this.code = code;
  }
}

export interface ServerOptions {
  /** The address of the GarnetOps installation, https:// (http:// only in tests). */
  baseUrl: string;
  /** A CA bundle for an internal certificate authority. */
  ca?: string;
  timeoutMs?: number;
}

export interface Identity {
  hostId: string;
  privateKeyPem: string;
}

export class Server {
  readonly base: URL;
  private readonly ca: string | undefined;
  private readonly timeoutMs: number;

  constructor(options: ServerOptions) {
    this.base = new URL(options.baseUrl);
    this.ca = options.ca;
    this.timeoutMs = options.timeoutMs ?? 60_000;
  }

  /** POSTs JSON to a path under /api/v1/agent; signed when an identity is given. */
  async post<T>(path: string, body: unknown, identity?: Identity): Promise<T> {
    const prefix = this.base.pathname.replace(/\/+$/, "");
    const fullPath = `${prefix}/api/v1/agent${path}`;
    const text = JSON.stringify(body);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(text)),
      "user-agent": "GarnetOps-Agent",
    };
    if (identity) {
      headers.authorization = signRequest({ ...identity, method: "POST", path: fullPath, body: text });
    }
    const send = this.base.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise<T>((resolve, reject) => {
      const req = send(
        {
          host: this.base.hostname,
          port: this.base.port || (this.base.protocol === "https:" ? 443 : 80),
          path: fullPath,
          method: "POST",
          headers,
          timeout: this.timeoutMs,
          ...(this.base.protocol === "https:"
            ? { minVersion: "TLSv1.2" as const, rejectUnauthorized: true }
            : {}),
          ...(this.ca ? { ca: this.ca } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_ANSWER) res.destroy(new Error("answer too large"));
            else chunks.push(chunk);
          });
          res.on("error", reject);
          res.on("end", () => {
            const status = res.statusCode ?? 0;
            const raw = Buffer.concat(chunks).toString("utf8");
            let json: unknown = null;
            try {
              json = raw ? JSON.parse(raw) : null;
            } catch {
              // not JSON
            }
            // A redirect is never followed: it is an error like any other status outside 2xx.
            if (status < 200 || status >= 300) {
              const type = (json as { type?: unknown } | null)?.type;
              return reject(
                new ServerError(status, typeof type === "string" ? (type.split("/").pop() ?? null) : null),
              );
            }
            resolve(json as T);
          });
        },
      );
      req.on("timeout", () => req.destroy(new Error("GarnetOps did not answer in time")));
      req.on("error", reject);
      req.end(text);
    });
  }
}
