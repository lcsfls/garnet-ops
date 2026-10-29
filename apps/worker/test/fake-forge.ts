/**
 * A fake forge for tests (never used by production code): the parts of the GitHub and the
 * Gitea/Forgejo REST API that fix pull requests use, over HTTPS with a throw-away self-signed
 * certificate made with openssl (certificate name forge.example.test). State is in memory:
 * branches with their files, pull requests, and a log of every request. Faults can be injected
 * per request (status codes, redirects, endless or oversized bodies, a hang).
 *
 * Used by apps/worker/src/fix-pr.test.ts and the end-to-end worker in test/e2e-forge-worker.ts.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type Flavour = "github" | "gitea";

export const FORGE_HOST = "forge.example.test";

export interface RecordedRequest {
  method: string;
  /** Path including the API prefix, without the query. */
  path: string;
  query: string;
  authorization: string | undefined;
  body: unknown;
}

export interface Fault {
  /** Matches "METHOD path", for example /^PUT .*contents/. */
  match: RegExp;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  /** Instead of an answer: never answer, send endless data, or send a body bigger than allowed. */
  action?: "hang" | "endless" | "huge";
  /** Fire once, then behave normally. */
  once?: boolean;
}

interface Commit {
  sha: string;
  files: Map<string, Buffer>;
}

export interface Pull {
  number: number;
  title: string;
  body: string;
  head: string;
  base: string;
  state: "open" | "closed";
  merged: boolean;
}

export const blobSha = (content: Buffer | string) => {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
};

export class FakeForge {
  readonly requests: RecordedRequest[] = [];
  readonly faults: Fault[] = [];
  readonly pulls: Pull[] = [];
  readonly branches = new Map<string, Commit>();
  readonly commits: Commit[] = [];
  readonly scopes: string | undefined;
  /** Sign-in (ADR 0031): the registered client, the device flow's progress and the codes handed out. */
  oauth = {
    clientId: "garnetops-test-client",
    clientSecret: null as string | null,
    redirectUri: "",
    /** The device flow answers "pending" this many times, then hands out the token. */
    pendingPolls: 1,
    polls: 0,
    denyDevice: false,
    /** code → S256 challenge, from {@link authorize}. */
    codes: new Map<string, string>(),
    /** The refresh token that is valid now; every renewal replaces it. */
    refreshToken: "refresh-1",
    renewals: 0,
    expiresIn: 28_800,
  };
  /** More open pull requests for `GET /repos/{owner}/{repo}/pulls`, as the forge would spell them. */
  extraPulls: Record<string, unknown>[] = [];
  /** The account name `GET /user` answers with. */
  login = "alex";
  /** What `GET /user/repos` lists, page by page, as the forge would spell it. */
  listed: Record<string, unknown>[] = [];
  port = 0;
  ca = "";
  private server: Server | null = null;
  private dir = "";
  private counter = 0;
  /** Connections held open by a "hang" or "endless" fault, closed with the server. */
  private open = new Set<ServerResponse>();

  readonly flavour: Flavour;
  readonly token: string;
  readonly owner: string;
  readonly repo: string;

  constructor(
    flavour: Flavour,
    token: string,
    owner = "team",
    repo = "app",
    options: {
      defaultBranch?: string;
      files?: Record<string, string>;
      scopes?: string;
      prefix?: string;
    } = {},
  ) {
    this.flavour = flavour;
    this.token = token;
    this.owner = owner;
    this.repo = repo;
    this.defaultBranch = options.defaultBranch ?? "main";
    this.prefix = options.prefix ?? (flavour === "github" ? "" : "/api/v1");
    this.scopes = options.scopes;
    const files = new Map(Object.entries(options.files ?? {}).map(([p, c]) => [p, Buffer.from(c)]));
    this.branches.set(this.defaultBranch, this.commit(files));
  }

  readonly defaultBranch: string;
  readonly prefix: string;

  get apiBase() {
    return `https://${FORGE_HOST}:${this.port}${this.prefix}`;
  }

  /** What the app stores as the repository address. */
  get repositoryUrl() {
    return `https://${FORGE_HOST}:${this.port}/${this.owner}/${this.repo}.git`;
  }

  get authorization() {
    return this.flavour === "github" ? `Bearer ${this.token}` : `token ${this.token}`;
  }

  private commit(files: Map<string, Buffer>): Commit {
    const c = {
      sha: createHash("sha1")
        .update(`commit ${++this.counter}`)
        .digest("hex"),
      files,
    };
    this.commits.push(c);
    return c;
  }

  /** Puts a file on a branch as a new commit (a push by somebody else). */
  setFile(branch: string, path: string, content: string) {
    const current = this.branches.get(branch);
    if (!current) throw new Error(`no branch ${branch}`);
    const files = new Map(current.files);
    files.set(path, Buffer.from(content));
    this.branches.set(branch, this.commit(files));
  }

  fileOn(branch: string, path: string): string | null {
    return this.branches.get(branch)?.files.get(path)?.toString("utf8") ?? null;
  }

  setPull(number: number, patch: Partial<Pull>) {
    const pull = this.pulls.find((p) => p.number === number);
    if (!pull) throw new Error(`no pull request ${number}`);
    Object.assign(pull, patch);
  }

  async start(port = 0): Promise<this> {
    this.dir = mkdtempSync(join(tmpdir(), "garnetops-forge-"));
    const key = join(this.dir, "key.pem");
    const cert = join(this.dir, "cert.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        `/CN=${FORGE_HOST}`,
        "-addext",
        `subjectAltName=DNS:${FORGE_HOST}`,
        "-keyout",
        key,
        "-out",
        cert,
      ],
      { stdio: "ignore" },
    );
    this.ca = readFileSync(cert, "utf8");
    this.server = createServer({ key: readFileSync(key), cert: this.ca }, (req, res) =>
      this.handle(req, res),
    );
    await new Promise<void>((resolve) => this.server?.listen(port, "127.0.0.1", resolve));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }

  async stop() {
    for (const res of this.open) res.destroy();
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
    if (this.dir) rmSync(this.dir, { recursive: true, force: true });
  }

  private handle(req: IncomingMessage, res: ServerResponse) {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "https://x");
      let body: unknown = null;
      const text = Buffer.concat(chunks).toString("utf8");
      if ((req.headers["content-type"] ?? "").startsWith("application/x-www-form-urlencoded")) {
        body = Object.fromEntries(new URLSearchParams(text));
      } else {
        try {
          body = text ? JSON.parse(text) : null;
        } catch {
          body = "unparseable";
        }
      }
      const method = req.method ?? "GET";
      this.requests.push({
        method,
        path: url.pathname,
        query: url.search,
        authorization: req.headers.authorization,
        body,
      });
      const fault = this.faults.find((f) => f.match.test(`${method} ${url.pathname}`));
      if (fault) {
        if (fault.once) this.faults.splice(this.faults.indexOf(fault), 1);
        return this.fault(fault, res);
      }
      // The sign-in endpoints live on the web address and take no bearer token (ADR 0031).
      if (url.pathname.startsWith("/login/"))
        return this.signIn(method, url.pathname, body as Record<string, string>, res);
      if (req.headers.authorization !== this.authorization)
        return json(res, 401, { message: "Bad credentials" });
      const path = url.pathname.startsWith(this.prefix) ? url.pathname.slice(this.prefix.length) : null;
      if (path === null) return json(res, 404, { message: "Not Found" });
      try {
        this.route(method, path, url.searchParams, body, res);
      } catch (error) {
        json(res, 500, { message: String(error) });
      }
    });
  }

  private fault(fault: Fault, res: ServerResponse) {
    if (fault.action === "hang") {
      this.open.add(res);
      return;
    }
    if (fault.action === "endless" || fault.action === "huge") {
      res.writeHead(200, { "content-type": "application/json" });
      this.open.add(res);
      const piece = Buffer.alloc(64 * 1024, 0x20);
      const limit = fault.action === "huge" ? 8 * 1024 * 1024 : Number.POSITIVE_INFINITY;
      let sent = 0;
      const write = () => {
        while (!res.destroyed && sent < limit) {
          sent += piece.length;
          if (!res.write(piece)) return void res.once("drain", write);
        }
        if (!res.destroyed && fault.action === "huge") res.end('"x"');
      };
      write();
      return;
    }
    res.writeHead(fault.status ?? 500, { "content-type": "application/json", ...fault.headers });
    res.end(fault.body ?? JSON.stringify({ message: "secret details of the failure" }));
  }

  /** What a person's browser gets from the authorize page: a code bound to the PKCE challenge. */
  authorize(challenge: string): string {
    const code = `code-${this.oauth.codes.size + 1}`;
    this.oauth.codes.set(code, challenge);
    return code;
  }

  private signIn(method: string, path: string, form: Record<string, string>, res: ServerResponse) {
    const o = this.oauth;
    if (method !== "POST" || form.client_id !== o.clientId)
      return json(res, 401, { error: "invalid_client" });
    if (path === "/login/device/code") {
      return json(res, 200, {
        device_code: "device-code-0123456789",
        user_code: "WDJB-MJHT",
        verification_uri: `https://${FORGE_HOST}/login/device`,
        expires_in: 900,
        interval: 1,
      });
    }
    if (path !== "/login/oauth/access_token") return json(res, 404, { message: "Not Found" });
    const tokens = () => {
      o.refreshToken = `refresh-${++o.renewals + 1}`;
      return {
        access_token: this.token,
        token_type: "bearer",
        expires_in: o.expiresIn,
        refresh_token: o.refreshToken,
      };
    };
    if (form.grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
      if (o.denyDevice) return json(res, 200, { error: "access_denied" });
      if (o.polls++ < o.pendingPolls) return json(res, 200, { error: "authorization_pending" });
      return json(res, 200, tokens());
    }
    if (o.clientSecret && form.client_secret !== o.clientSecret)
      return json(res, 401, { error: "invalid_client" });
    if (form.grant_type === "authorization_code") {
      const challenge = o.codes.get(form.code ?? "");
      const verifier = createHash("sha256")
        .update(form.code_verifier ?? "")
        .digest("base64url");
      if (!challenge || challenge !== verifier || form.redirect_uri !== o.redirectUri) {
        return json(res, 400, { error: "invalid_grant" });
      }
      o.codes.delete(form.code as string);
      return json(res, 200, tokens());
    }
    if (form.grant_type === "refresh_token") {
      if (form.refresh_token !== o.refreshToken) return json(res, 400, { error: "invalid_grant" });
      return json(res, 200, tokens());
    }
    return json(res, 400, { error: "unsupported_grant_type" });
  }

  private route(method: string, path: string, query: URLSearchParams, body: unknown, res: ServerResponse) {
    // The account behind the token, and the repositories it can see (personal connections, ADR 0030).
    if (method === "GET" && path === "/user") {
      return json(res, 200, { login: this.login }, this.scopes ? { "x-oauth-scopes": this.scopes } : {});
    }
    if (method === "GET" && path === "/user/repos") {
      const size = Number(query.get(this.flavour === "github" ? "per_page" : "limit") ?? 30);
      const page = Number(query.get("page") ?? 1);
      return json(res, 200, this.listed.slice((page - 1) * size, page * size));
    }
    // The repository is "app"; "app1", "app2" … are the same repository under other names, so that
    // tests can register several repositories of one organisation (the address is unique per organisation).
    const named = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(path);
    if (!named || named[1] !== this.owner || !new RegExp(`^${this.repo}\\d*$`).test(named[2] as string)) {
      return json(res, 404, { message: "Not Found" });
    }
    const rest = named[3] ?? "";
    const b = (body ?? {}) as Record<string, unknown>;
    const github = this.flavour === "github";
    const headers: Record<string, string> = this.scopes ? { "x-oauth-scopes": this.scopes } : {};

    // Open pull requests (ADR 0032): the ones opened here, then any a test adds as the forge would spell them.
    if (method === "GET" && rest === "/pulls") {
      const opened = this.pulls
        .filter((p) => p.state === "open")
        .map((p) => ({
          number: p.number,
          title: p.title,
          user: { login: "alex" },
          head: { ref: p.head, sha: this.branches.get(p.head)?.sha ?? "0".repeat(40) },
          base: { ref: p.base },
          draft: false,
          created_at: "2026-10-28T10:00:00Z",
          updated_at: "2026-10-29T10:00:00Z",
        }));
      const size = Number(query.get(github ? "per_page" : "limit") ?? 30);
      const page = Number(query.get("page") ?? 1);
      return json(res, 200, [...opened, ...this.extraPulls].slice((page - 1) * size, page * size));
    }
    if (method === "GET" && rest === "") {
      return json(
        res,
        200,
        { default_branch: this.defaultBranch, archived: false, permissions: { push: true, pull: true } },
        headers,
      );
    }
    let m = /^\/branches\/(.+)$/.exec(rest);
    if (m && method === "GET") {
      const name = decodeURIComponent(m[1] as string);
      const head = this.branches.get(name);
      if (!head) return json(res, 404, { message: "Branch not found" });
      return json(res, 200, { name, commit: github ? { sha: head.sha } : { id: head.sha } });
    }
    if (m && method === "DELETE" && !github) {
      const name = decodeURIComponent(m[1] as string);
      if (!this.branches.delete(name)) return json(res, 404, { message: "Branch not found" });
      return void res.writeHead(204).end();
    }
    m = /^\/contents\/(.+)$/.exec(rest);
    if (m) {
      const file = m[1]?.split("/").map(decodeURIComponent).join("/") as string;
      if (method === "GET") {
        const content = this.branches.get(query.get("ref") ?? this.defaultBranch)?.files.get(file);
        if (!content) return json(res, 404, { message: "Not Found" });
        return json(res, 200, {
          type: "file",
          path: file,
          sha: blobSha(content),
          size: content.length,
          encoding: "base64",
          content: content.toString("base64").replace(/(.{60})/g, "$1\n"),
        });
      }
      if (method === "PUT") {
        const branch = String(b.branch ?? "");
        const head = this.branches.get(branch);
        if (!head) return json(res, github ? 404 : 404, { message: "Branch not found" });
        const current = head.files.get(file);
        if (!current || blobSha(current) !== b.sha) {
          return json(res, github ? 409 : 422, { message: `${file} does not match ${String(b.sha)}` });
        }
        const files = new Map(head.files);
        files.set(file, Buffer.from(String(b.content), "base64"));
        const commit = this.commit(files);
        this.branches.set(branch, commit);
        return json(res, 200, { content: { path: file }, commit: { sha: commit.sha, message: b.message } });
      }
    }
    if (github && method === "POST" && rest === "/git/refs") {
      const name = String(b.ref ?? "").replace(/^refs\/heads\//, "");
      if (this.branches.has(name)) return json(res, 422, { message: "Reference already exists" });
      const from = this.commits.find((c) => c.sha === b.sha);
      if (!from) return json(res, 422, { message: "Object does not exist" });
      this.branches.set(name, from);
      return json(res, 201, { ref: b.ref, object: { sha: from.sha } });
    }
    const ref = /^\/git\/refs\/heads\/(.+)$/.exec(rest);
    if (github && method === "DELETE" && ref) {
      m = ref;
      if (!this.branches.delete(decodeURIComponent(m[1] as string)))
        return json(res, 422, { message: "Reference does not exist" });
      return void res.writeHead(204).end();
    }
    if (!github && method === "POST" && rest === "/branches") {
      const name = String(b.new_branch_name ?? "");
      if (this.branches.has(name)) return json(res, 409, { message: "branch already exists" });
      const from = this.branches.get(String(b.old_branch_name ?? ""));
      if (!from) return json(res, 404, { message: "old branch not found" });
      this.branches.set(name, from);
      return json(res, 201, { name, commit: { id: from.sha } });
    }
    if (method === "POST" && rest === "/pulls") {
      const head = String(b.head ?? "");
      const base2 = String(b.base ?? "");
      const headCommit = this.branches.get(head);
      const baseCommit = this.branches.get(base2);
      if (!headCommit || !baseCommit) return json(res, 422, { message: "Validation Failed" });
      if (headCommit.sha === baseCommit.sha) return json(res, 422, { message: "No commits between" });
      const pull: Pull = {
        number: this.pulls.length + 1,
        title: String(b.title ?? ""),
        body: String(b.body ?? ""),
        head,
        base: base2,
        state: "open",
        merged: false,
      };
      this.pulls.push(pull);
      // A hostile forge answer: the page address is never taken from here.
      return json(res, 201, { number: pull.number, html_url: "https://evil.example/phish" });
    }
    m = /^\/pulls\/(\d+)$/.exec(rest);
    if (m && method === "GET") {
      const pull = this.pulls.find((p) => p.number === Number(m?.[1]));
      if (!pull) return json(res, 404, { message: "Not Found" });
      return json(res, 200, {
        number: pull.number,
        state: pull.state,
        merged: pull.merged,
        merged_at: pull.merged ? "2026-10-21T10:00:00Z" : null,
      });
    }
    return json(res, 404, { message: "Not Found" });
  }
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}
