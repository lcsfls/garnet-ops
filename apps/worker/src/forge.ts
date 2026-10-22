/**
 * The forge REST client behind fix pull requests (ADR 0014): GitHub (github.com and GitHub
 * Enterprise Server, `/api/v3`) and Gitea or Forgejo (`/api/v1`). It can do exactly what a
 * version-bump pull request needs and nothing else: read the repository, read one branch and
 * one file, create one branch, update one file, open and read one pull request, delete the
 * branch it made. It never merges, approves, comments or touches the default branch.
 *
 * The token is only sent to the API address stored with the write access, which an admin
 * chose. The address is resolved here and every answer is checked with the same rules as
 * everywhere else (loopback, link-local, metadata, unspecified and multicast are refused;
 * private networks are fine, because a self-hosted forge is the normal case). The connection
 * goes to the address that was checked, the name only travels as SNI and Host header. No
 * redirects are followed (a redirect would carry the token to another host), TLS
 * verification is always on, every phase has a time limit and every answer a size limit.
 * Error bodies are discarded: an error is a short code.
 */
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { classifyAddress } from "@garnetops/core/ai-endpoint";
import type { ForgeKind } from "@garnetops/core/fix-prs";
import { z } from "zod";

export const FORGE_ERROR_CODES = [
  "token-rejected",
  "forbidden",
  "not-found",
  "conflict",
  "rejected",
  "rate-limited",
  "redirect",
  "too-large",
  "timeout",
  "tls",
  "connection-failed",
  "address-refused",
  "unresolvable",
  "bad-response",
  "http-error",
] as const;
export type ForgeErrorCode = (typeof FORGE_ERROR_CODES)[number];

/** A failure with a short code that is safe to store and show. */
export class ForgeError extends Error {
  readonly code: ForgeErrorCode;
  readonly status: number | null;
  constructor(code: ForgeErrorCode, status: number | null = null) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

/** Tests only: reach a server on loopback, map a host name, trust a throw-away CA. Never set by production code. */
export interface ForgeTestHooks {
  allowLoopback?: boolean;
  connectTo?: (address: string) => string;
  resolve?: (hostname: string) => Promise<string[]>;
  ca?: string;
}
let testHooks: ForgeTestHooks | null = null;
export function setForgeTestHooks(hooks: ForgeTestHooks | null): void {
  testHooks = hooks;
}

export interface ForgeTarget {
  kind: ForgeKind;
  /** https://api.github.com, https://ghe.example.com/api/v3 or https://git.example.com/api/v1 */
  apiBaseUrl: string;
  token: string;
  owner: string;
  repo: string;
}

/** Writable only so that tests can shorten the time limits. */
export const LIMITS = {
  /** Time to connect and receive the headers. */
  firstByteMs: 15_000,
  /** The whole request, body included. */
  totalMs: 30_000,
  /** Largest answer we read. A 1 MB file is about 1.4 MB as base64 inside JSON. */
  responseBytes: 2 * 1024 * 1024,
  requestBytes: 3 * 1024 * 1024,
  /** Largest manifest we edit. */
  fileBytes: 1_000_000,
};

const CONNECT_ATTEMPTS = 4;
/** Printable ASCII only, so a token can never smuggle a line break into a header. */
const TOKEN_PATTERN = /^[\x21-\x7e]{8,500}$/;
const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;

function mapNetworkError(error: unknown): ForgeError {
  if (error instanceof ForgeError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new ForgeError("timeout");
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new ForgeError("unresolvable");
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH|ERR_OSSL/.test(code)) {
    return new ForgeError("tls");
  }
  return new ForgeError("connection-failed");
}

/** Resolves the API host and refuses it if any answer is an address we never talk to. */
export async function resolveForgeHost(url: URL): Promise<string[]> {
  if (url.protocol !== "https:") throw new ForgeError("address-refused");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) throw new ForgeError("address-refused");
  let addresses: string[];
  if (isIP(host)) addresses = [host];
  else if (testHooks?.resolve) addresses = await testHooks.resolve(host);
  else {
    try {
      addresses = (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);
    } catch {
      throw new ForgeError("unresolvable");
    }
  }
  if (addresses.length === 0) throw new ForgeError("unresolvable");
  // Mixed answers count as the strictest address.
  if (addresses.some((a) => classifyAddress(a, testHooks?.allowLoopback === true) === "forbidden")) {
    throw new ForgeError("address-refused");
  }
  return addresses;
}

interface Response {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  json: unknown;
}

interface Call {
  method: "GET" | "POST" | "PUT" | "DELETE";
  /** Path below the API base, already encoded, starting with "/". */
  path: string;
  body?: unknown;
}

function authHeaders(target: ForgeTarget): Record<string, string> {
  return target.kind === "github"
    ? {
        authorization: `Bearer ${target.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
      }
    : { authorization: `token ${target.token}`, accept: "application/json" };
}

/** One request. 2xx returns the parsed JSON; every other status becomes a {@link ForgeError}. */
async function call(target: ForgeTarget, options: Call): Promise<Response> {
  if (!TOKEN_PATTERN.test(target.token)) throw new ForgeError("token-rejected");
  if (!NAME_PATTERN.test(target.owner) || !NAME_PATTERN.test(target.repo)) throw new ForgeError("not-found");
  const base = new URL(target.apiBaseUrl);
  if (base.username || base.password || base.search || base.hash) throw new ForgeError("address-refused");
  const addresses = await resolveForgeHost(base);
  const data = options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body));
  if (data && data.length > LIMITS.requestBytes) throw new ForgeError("too-large");
  const hostname = base.hostname.replace(/^\[|\]$/g, "");
  const path = `${base.pathname.replace(/\/+$/, "")}${options.path}`;
  let last = new ForgeError("connection-failed");

  for (const address of addresses.slice(0, CONNECT_ATTEMPTS)) {
    try {
      return await new Promise<Response>((resolve, reject) => {
        const req = httpsRequest({
          host: testHooks?.connectTo ? testHooks.connectTo(address) : address,
          port: base.port ? Number(base.port) : 443,
          method: options.method,
          path,
          agent: false,
          servername: isIP(hostname) ? undefined : hostname,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          ...(testHooks?.ca ? { ca: testHooks.ca } : {}),
          headers: {
            host: base.host,
            "user-agent": "GarnetOps",
            connection: "close",
            ...authHeaders(target),
            ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
          },
        });
        const total = setTimeout(() => req.destroy(new ForgeError("timeout")), LIMITS.totalMs);
        const first = setTimeout(() => req.destroy(new ForgeError("timeout")), LIMITS.firstByteMs);
        const done = () => {
          clearTimeout(total);
          clearTimeout(first);
        };
        req.on("error", (error) => {
          done();
          reject(mapNetworkError(error));
        });
        req.once("response", (res) => {
          clearTimeout(first);
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            res.resume(); // the body is never read: it can be anything
            done();
            const rateLimited =
              status === 429 ||
              (status === 403 &&
                (res.headers["x-ratelimit-remaining"] === "0" || res.headers["retry-after"]));
            reject(
              new ForgeError(
                status >= 300 && status < 400
                  ? "redirect"
                  : status === 401
                    ? "token-rejected"
                    : rateLimited
                      ? "rate-limited"
                      : status === 403
                        ? "forbidden"
                        : status === 404
                          ? "not-found"
                          : status === 409
                            ? "conflict"
                            : status === 422
                              ? "rejected"
                              : "http-error",
                status,
              ),
            );
            return;
          }
          const length = Number(res.headers["content-length"] ?? 0);
          if (length > LIMITS.responseBytes) {
            res.destroy();
            done();
            return reject(new ForgeError("too-large", status));
          }
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > LIMITS.responseBytes) {
              res.destroy();
              done();
              reject(new ForgeError("too-large", status));
              return;
            }
            chunks.push(chunk);
          });
          res.on("error", (error) => {
            done();
            reject(mapNetworkError(error));
          });
          res.on("end", () => {
            done();
            if (size === 0) return resolve({ status, headers: res.headers, json: null });
            try {
              resolve({
                status,
                headers: res.headers,
                json: JSON.parse(Buffer.concat(chunks).toString("utf8")),
              });
            } catch {
              reject(new ForgeError("bad-response", status));
            }
          });
        });
        req.end(data);
      });
    } catch (error) {
      last = mapNetworkError(error);
      // Only an unreachable address is worth trying the next one for.
      if (last.code !== "connection-failed") throw last;
    }
  }
  throw last;
}

const parse = <T extends z.ZodTypeAny>(schema: T, value: unknown): z.infer<T> => {
  const result = schema.safeParse(value);
  if (!result.success) throw new ForgeError("bad-response");
  return result.data;
};

const seg = (value: string) => encodeURIComponent(value);
const repoPath = (t: ForgeTarget) => `/repos/${seg(t.owner)}/${seg(t.repo)}`;
/** A path or branch name with its slashes kept and every part encoded. */
const slashPath = (value: string) => value.split("/").map(seg).join("/");

/* -------------------------------------------------------------------------- */
/* Operations                                                                  */
/* -------------------------------------------------------------------------- */

const repoSchema = z.object({
  default_branch: z.string().min(1).max(250),
  archived: z.boolean().optional(),
  permissions: z.object({ push: z.boolean().optional() }).partial().nullish(),
});

export interface RepoInfo {
  defaultBranch: string;
  archived: boolean;
  /** Whether the token may push; null if the forge did not say. */
  canPush: boolean | null;
  /** The forge says the token has scopes beyond one repository (a classic GitHub token with `repo`). */
  broadToken: boolean;
}

export async function repoInfo(target: ForgeTarget): Promise<RepoInfo> {
  const response = await call(target, { method: "GET", path: repoPath(target) });
  const data = parse(repoSchema, response.json);
  const scopes = response.headers["x-oauth-scopes"];
  // Fine-grained tokens send no scopes header; a classic token lists them, and `repo` covers every repository.
  const broadToken =
    target.kind === "github" &&
    typeof scopes === "string" &&
    /(^|[\s,])(repo|admin:org|write:org)([\s,]|$)/.test(scopes);
  return {
    defaultBranch: data.default_branch,
    archived: data.archived === true,
    canPush: typeof data.permissions?.push === "boolean" ? data.permissions.push : null,
    broadToken,
  };
}

const branchSchema = z.object({
  commit: z.object({ sha: z.string().optional(), id: z.string().optional() }),
});

export async function branchHead(target: ForgeTarget, branch: string): Promise<string> {
  const response = await call(target, {
    method: "GET",
    path: `${repoPath(target)}/branches/${slashPath(branch)}`,
  });
  const commit = parse(branchSchema, response.json).commit;
  const sha = commit.sha ?? commit.id ?? "";
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(sha)) throw new ForgeError("bad-response");
  return sha;
}

const fileSchema = z.object({
  type: z.literal("file"),
  sha: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i),
  size: z.number().int().nonnegative().optional(),
  encoding: z.literal("base64"),
  content: z.string(),
});

/** A file at a branch: its git blob id and its bytes. Larger than the manifest limit is refused. */
export async function readFile(
  target: ForgeTarget,
  path: string,
  ref: string,
): Promise<{ sha: string; bytes: Buffer }> {
  const response = await call(target, {
    method: "GET",
    path: `${repoPath(target)}/contents/${slashPath(path)}?ref=${seg(ref)}`,
  });
  // A directory is an array, a file larger than 1 MB has encoding "none": neither is a manifest we edit.
  const file = parse(fileSchema, response.json);
  if (
    (file.size ?? 0) > LIMITS.fileBytes ||
    file.content.length > Math.ceil((LIMITS.fileBytes * 4) / 3) + 1024
  ) {
    throw new ForgeError("too-large");
  }
  const bytes = Buffer.from(file.content.replace(/\s+/g, ""), "base64");
  if (bytes.length > LIMITS.fileBytes) throw new ForgeError("too-large");
  return { sha: file.sha.toLowerCase(), bytes };
}

/** Creates `branch` at `fromSha` (GitHub: a ref; Gitea and Forgejo: a branch from the base branch). */
export async function createBranch(
  target: ForgeTarget,
  branch: string,
  from: { branch: string; sha: string },
): Promise<void> {
  if (target.kind === "github") {
    await call(target, {
      method: "POST",
      path: `${repoPath(target)}/git/refs`,
      body: { ref: `refs/heads/${branch}`, sha: from.sha },
    });
  } else {
    await call(target, {
      method: "POST",
      path: `${repoPath(target)}/branches`,
      body: { new_branch_name: branch, old_branch_name: from.branch },
    });
  }
}

export async function deleteBranch(target: ForgeTarget, branch: string): Promise<void> {
  await call(target, {
    method: "DELETE",
    path:
      target.kind === "github"
        ? `${repoPath(target)}/git/refs/heads/${slashPath(branch)}`
        : `${repoPath(target)}/branches/${slashPath(branch)}`,
  });
}

/** Replaces one file on `branch`. `sha` is the blob id being replaced: the forge refuses the write if the file moved on. */
export async function writeFile(
  target: ForgeTarget,
  input: { path: string; branch: string; sha: string; bytes: Buffer; message: string },
): Promise<void> {
  await call(target, {
    method: "PUT",
    path: `${repoPath(target)}/contents/${slashPath(input.path)}`,
    body: {
      message: input.message,
      content: input.bytes.toString("base64"),
      sha: input.sha,
      branch: input.branch,
    },
  });
}

const pullSchema = z.object({ number: z.number().int().positive() });

export async function openPullRequest(
  target: ForgeTarget,
  input: { title: string; body: string; head: string; base: string },
): Promise<number> {
  const response = await call(target, {
    method: "POST",
    path: `${repoPath(target)}/pulls`,
    body: { title: input.title, body: input.body, head: input.head, base: input.base },
  });
  return parse(pullSchema, response.json).number;
}

const pullStateSchema = z.object({
  state: z.string(),
  merged: z.boolean().optional(),
  merged_at: z.string().nullish(),
});

export type PullState = "open" | "merged" | "closed";

export async function pullRequestState(target: ForgeTarget, number: number): Promise<PullState> {
  const response = await call(target, {
    method: "GET",
    path: `${repoPath(target)}/pulls/${seg(String(number))}`,
  });
  const data = parse(pullStateSchema, response.json);
  if (data.merged === true || data.merged_at) return "merged";
  return data.state === "open" ? "open" : "closed";
}
