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
import { type ForgeKind, stripControl } from "@garnetops/core/fix-prs";
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

/** An account on a forge: where its API is and the token to send there. */
export interface ForgeAccount {
  kind: ForgeKind;
  /** https://api.github.com, https://ghe.example.com/api/v3 or https://git.example.com/api/v1 */
  apiBaseUrl: string;
  token: string;
}

/** One repository of an account. */
export interface ForgeTarget extends ForgeAccount {
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

/** The headers of a forge API request; without a token (public repositories, ADR 0032) no authorization is sent. */
function authHeaders(target: ForgeAccount): Record<string, string> {
  const headers: Record<string, string> =
    target.kind === "github"
      ? { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" }
      : { accept: "application/json" };
  if (target.token)
    headers.authorization = target.kind === "github" ? `Bearer ${target.token}` : `token ${target.token}`;
  return headers;
}

/** One request. 2xx returns the parsed JSON; every other status becomes a {@link ForgeError}. */
async function call(target: ForgeAccount, options: Call): Promise<Response> {
  if (target.token !== "" && !TOKEN_PATTERN.test(target.token)) throw new ForgeError("token-rejected");
  const data = options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body));
  return send(
    target.apiBaseUrl,
    options.method,
    options.path,
    { ...authHeaders(target), ...(data ? { "content-type": "application/json" } : {}) },
    data,
  );
}

/** One HTTPS request to `baseUrl` + `pathAndQuery`, with every rule of this file (addresses, TLS, limits, no redirects). */
async function send(
  baseUrl: string,
  method: Call["method"],
  pathAndQuery: string,
  extraHeaders: Record<string, string>,
  data?: Buffer,
): Promise<Response> {
  const base = new URL(baseUrl);
  if (base.username || base.password || base.search || base.hash) throw new ForgeError("address-refused");
  const addresses = await resolveForgeHost(base);
  if (data && data.length > LIMITS.requestBytes) throw new ForgeError("too-large");
  const hostname = base.hostname.replace(/^\[|\]$/g, "");
  const path = `${base.pathname.replace(/\/+$/, "")}${pathAndQuery}`;
  let last = new ForgeError("connection-failed");

  for (const address of addresses.slice(0, CONNECT_ATTEMPTS)) {
    try {
      return await new Promise<Response>((resolve, reject) => {
        const req = httpsRequest({
          host: testHooks?.connectTo ? testHooks.connectTo(address) : address,
          port: base.port ? Number(base.port) : 443,
          method,
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
            ...extraHeaders,
            ...(data ? { "content-length": data.length } : {}),
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
const repoPath = (t: ForgeTarget) => {
  if (!NAME_PATTERN.test(t.owner) || !NAME_PATTERN.test(t.repo)) throw new ForgeError("not-found");
  return `/repos/${seg(t.owner)}/${seg(t.repo)}`;
};
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

/* -------------------------------------------------------------------------- */
/* Personal connections (ADR 0030): read only                                  */
/* -------------------------------------------------------------------------- */

/** A classic GitHub token whose scopes reach every repository or can write. */
const broadScopes = (kind: ForgeKind, scopes: unknown) =>
  kind === "github" &&
  typeof scopes === "string" &&
  /(^|[\s,])(repo|admin:org|write:org|workflow|delete_repo)([\s,]|$)/.test(scopes);

const userSchema = z.object({ login: z.string().min(1).max(100) });

export interface AccountInfo {
  login: string;
  broadToken: boolean;
}

/** Who the token belongs to; the first thing a connection checks. */
export async function accountInfo(account: ForgeAccount): Promise<AccountInfo> {
  const response = await call(account, { method: "GET", path: "/user" });
  return {
    login: parse(userSchema, response.json).login,
    broadToken: broadScopes(account.kind, response.headers["x-oauth-scopes"]),
  };
}

const listedSchema = z.array(
  z.object({
    id: z.union([z.number().int(), z.string().regex(/^[0-9A-Za-z_=-]{1,100}$/)]),
    full_name: z.string().max(201),
    clone_url: z.string().max(500),
    default_branch: z.string().max(250).nullish(),
    private: z.boolean(),
    archived: z.boolean().nullish(),
    description: z.string().nullish(),
  }),
);

export interface ListedRepository {
  forgeId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string | null;
  private: boolean;
  archived: boolean;
  description: string | null;
}

/** Most repositories a connection lists; more are cut and the list says so. */
export const MAX_LISTED_REPOSITORIES = 2000;

/**
 * The repositories the account can see, page by page, sorted by name. Entries whose name or clone address does not
 * look like a repository on `webHost` over https are left out: they are not something GarnetOps could clone with
 * this token.
 */
export async function listRepositories(
  account: ForgeAccount,
  webHost: string,
): Promise<{ items: ListedRepository[]; truncated: boolean }> {
  const perPage = account.kind === "github" ? 100 : 50;
  const items: ListedRepository[] = [];
  for (let page = 1; ; page++) {
    const path =
      account.kind === "github"
        ? `/user/repos?per_page=${perPage}&page=${page}&sort=full_name&affiliation=owner,collaborator,organization_member`
        : `/user/repos?limit=${perPage}&page=${page}`;
    const batch = parse(listedSchema, (await call(account, { method: "GET", path })).json);
    for (const r of batch) {
      const [owner, name, ...rest] = r.full_name.split("/");
      if (rest.length || !owner || !name || !NAME_PATTERN.test(owner) || !NAME_PATTERN.test(name)) continue;
      let clone: URL;
      try {
        clone = new URL(r.clone_url);
      } catch {
        continue;
      }
      if (clone.protocol !== "https:" || clone.hostname !== webHost || clone.username || clone.password)
        continue;
      if (clone.search || clone.hash) continue;
      if (items.length >= MAX_LISTED_REPOSITORIES) return { items, truncated: true };
      items.push({
        forgeId: String(r.id),
        fullName: `${owner}/${name}`,
        cloneUrl: clone.toString(),
        defaultBranch: r.default_branch || null,
        private: r.private,
        archived: r.archived === true,
        // Shown as text only; control characters and length are cut here.
        description: r.description ? stripControl(r.description).slice(0, 300) : null,
      });
    }
    if (batch.length < perPage) break;
    if (page * perPage >= MAX_LISTED_REPOSITORIES + perPage) return { items, truncated: true };
  }
  items.sort((a, b) => a.fullName.localeCompare(b.fullName));
  return { items, truncated: false };
}

/* -------------------------------------------------------------------------- */
/* Signing in (ADR 0031): the forge's OAuth endpoints, no token sent           */
/* -------------------------------------------------------------------------- */

/** A form post to the forge's web address (`/login/...`), answered with JSON. */
async function oauthPost(webBaseUrl: string, path: string, form: Record<string, string>): Promise<unknown> {
  const body = Buffer.from(new URLSearchParams(form).toString());
  const response = await send(
    webBaseUrl,
    "POST",
    path,
    { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body,
  );
  return response.json;
}

const deviceCodeSchema = z.object({
  device_code: z.string().min(1).max(500),
  user_code: z.string().regex(/^[A-Z0-9-]{4,20}$/),
  verification_uri: z.string().max(500),
  expires_in: z.number().int().positive().max(3600),
  interval: z.number().int().positive().max(60).optional(),
});

export interface DeviceCode {
  deviceCode: string;
  userCode: string;
  /** Only an https address on the forge's own host; anything else is refused. */
  verificationUri: string;
  expiresInSeconds: number;
  intervalSeconds: number;
}

/** Starts the device flow (GitHub Apps): a code for the person to confirm on the forge. */
export async function requestDeviceCode(webBaseUrl: string, clientId: string): Promise<DeviceCode> {
  const data = parse(
    deviceCodeSchema,
    await oauthPost(webBaseUrl, "/login/device/code", { client_id: clientId }),
  );
  const page = new URL(data.verification_uri);
  if (page.protocol !== "https:" || page.hostname !== new URL(webBaseUrl).hostname)
    throw new ForgeError("bad-response");
  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri: page.toString(),
    expiresInSeconds: data.expires_in,
    intervalSeconds: data.interval ?? 5,
  };
}

const tokenSchema = z.object({
  access_token: z
    .string()
    .regex(/^[\x21-\x7e]{8,500}$/)
    .optional(),
  refresh_token: z
    .string()
    .regex(/^[\x21-\x7e]{8,1000}$/)
    .optional(),
  expires_in: z.number().int().positive().optional(),
  error: z.string().max(100).optional(),
});

export type TokenAnswer =
  | { kind: "token"; accessToken: string; refreshToken: string | null; expiresInSeconds: number | null }
  | { kind: "pending" }
  | { kind: "slow-down" }
  | { kind: "denied" }
  | { kind: "expired" };

/**
 * The token endpoint (`/login/oauth/access_token`): for a device code, an authorization code with its PKCE verifier,
 * or a refresh token. GitHub answers errors of the device flow with status 200 and an `error` field; those become
 * answers, everything else that is not a token is a {@link ForgeError}.
 */
export async function requestToken(webBaseUrl: string, form: Record<string, string>): Promise<TokenAnswer> {
  let json: unknown;
  try {
    json = await oauthPost(webBaseUrl, "/login/oauth/access_token", form);
  } catch (error) {
    // Gitea and Forgejo refuse a used or wrong code or refresh token with 400 or 401.
    if (error instanceof ForgeError && (error.status === 400 || error.status === 401))
      return { kind: "denied" };
    throw error;
  }
  const data = parse(tokenSchema, json);
  if (data.access_token) {
    return {
      kind: "token",
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? null,
      expiresInSeconds: data.expires_in ?? null,
    };
  }
  if (data.error === "authorization_pending") return { kind: "pending" };
  if (data.error === "slow_down") return { kind: "slow-down" };
  if (data.error === "expired_token") return { kind: "expired" };
  if (data.error) return { kind: "denied" };
  throw new ForgeError("bad-response");
}

/* -------------------------------------------------------------------------- */
/* Open pull requests (ADR 0032): read only                                    */
/* -------------------------------------------------------------------------- */

const openPullsSchema = z.array(
  z.object({
    number: z.number().int().positive(),
    title: z.string().max(10_000),
    draft: z.boolean().nullish(),
    user: z.object({ login: z.string().max(200) }).nullish(),
    head: z.object({ ref: z.string().max(500).nullish(), sha: z.string() }),
    base: z.object({ ref: z.string().max(500).nullish() }).nullish(),
    created_at: z.string().max(50).nullish(),
    updated_at: z.string().max(50).nullish(),
  }),
);

export interface OpenPullRequest {
  number: number;
  /** Control characters removed, at most 300 characters: it is shown as text, never as markup. */
  title: string;
  author: string | null;
  headRef: string | null;
  headSha: string;
  baseRef: string | null;
  draft: boolean;
  openedAt: Date | null;
  updatedAt: Date | null;
}

/** Most open pull requests read per repository. */
export const MAX_PULL_REQUESTS = 300;

const clean = (text: string | null | undefined, max: number) =>
  text ? stripControl(text).slice(0, max) || null : null;
const when = (value: string | null | undefined) => {
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
};

/** The open pull requests of one repository, newest first, at most {@link MAX_PULL_REQUESTS}. */
export async function listOpenPullRequests(target: ForgeTarget): Promise<OpenPullRequest[]> {
  const perPage = target.kind === "github" ? 100 : 50;
  const out: OpenPullRequest[] = [];
  for (let page = 1; out.length < MAX_PULL_REQUESTS; page++) {
    const query =
      target.kind === "github"
        ? `?state=open&per_page=${perPage}&page=${page}&sort=updated&direction=desc`
        : `?state=open&limit=${perPage}&page=${page}&sort=recentupdate`;
    const batch = parse(
      openPullsSchema,
      (await call(target, { method: "GET", path: `${repoPath(target)}/pulls${query}` })).json,
    );
    for (const p of batch) {
      if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(p.head.sha)) continue;
      out.push({
        number: p.number,
        title: clean(p.title, 300) ?? `#${p.number}`,
        author: clean(p.user?.login, 100),
        headRef: clean(p.head.ref, 250),
        headSha: p.head.sha.toLowerCase(),
        baseRef: clean(p.base?.ref, 250),
        draft: p.draft === true,
        openedAt: when(p.created_at),
        updatedAt: when(p.updated_at),
      });
      if (out.length >= MAX_PULL_REQUESTS) break;
    }
    if (batch.length < perPage) break;
  }
  return out;
}
