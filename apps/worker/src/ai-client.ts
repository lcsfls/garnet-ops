/**
 * The HTTP side of AI triage (ADR 0013): a small client for an OpenAI-compatible server
 * (vLLM, Ollama, LiteLLM, LM Studio) that cannot be turned against the network around it.
 *
 *  - The host name is resolved here, every answer is checked (never loopback, link-local,
 *    metadata, multicast; public addresses only over https and only when an admin
 *    acknowledged the host; other private addresses over https, plain http only on the same
 *    host or network as this worker or inside a VPN overlay), and the connection goes to the address that was checked. The
 *    name travels as SNI and Host header only, so DNS cannot change its answer in between.
 *  - Redirects are not followed. TLS verification is always on.
 *  - Every phase has a time limit, every answer a size limit, and the stream is parsed
 *    defensively (broken events are skipped; a stream that is all noise is an error).
 *  - Error bodies are never read into messages or stored: an error is a short code.
 *
 * Nothing in here touches the database or the vault; callers hand in the API key.
 */
import { lookup } from "node:dns/promises";
import { type ClientRequest, request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { AI_LIMITS, type AiError, looksLikeSse, parseChatChunk, SseParser } from "@garnetops/core/ai";
import { decideEndpoint, endpointHost } from "@garnetops/core/ai-endpoint";

/** A failure with a short code that is safe to store and show. */
export class ModelError extends Error {
  readonly code: AiError;
  readonly status: number | null;
  /** The system or TLS error code behind it (e.g. ECONNREFUSED), for the log only; never a message. */
  readonly systemCode: string | null;
  constructor(code: AiError, status: number | null = null, systemCode: string | null = null) {
    super(code);
    this.code = code;
    this.status = status;
    this.systemCode = systemCode;
  }
}

/**
 * Tests only: reach a server on loopback, map a test host name, trust a throw-away CA. Never
 * set by production code and never read from the environment.
 */
export interface ModelTestHooks {
  allowLoopback?: boolean;
  /**
   * Opens the socket to another address than the one the policy judged: the end-to-end tests
   * configure a private address and let the fake model server answer on loopback.
   */
  connectTo?: (address: string) => string;
  resolve?: (hostname: string) => Promise<string[]>;
  ca?: string;
  /** Replaces the subnets of the worker's own network interfaces (CIDR). */
  localNetworks?: string[];
}
let testHooks: ModelTestHooks | null = null;
export function setModelTestHooks(hooks: ModelTestHooks | null): void {
  testHooks = hooks;
}

/**
 * The subnets of this container's own network interfaces, loopback excluded (CIDR). A model
 * server inside one of them is on the same host or the same Docker network as the worker, so
 * plain http to it does not cross a network anyone else can listen on. Read from the
 * operating system on every call (interfaces change when a container joins a network), never
 * from the environment; a /0 entry would match everything and is ignored.
 */
export function localNetworks(): string[] {
  if (testHooks?.localNetworks) return testHooks.localNetworks;
  const cidrs: string[] = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.internal || !entry.cidr || entry.cidr.endsWith("/0")) continue;
      cidrs.push(entry.cidr);
    }
  }
  return cidrs;
}

export interface ModelTarget {
  /** Normalised base URL, e.g. http://llm.example.lan:8000/v1 */
  baseUrl: string;
  apiKey: string | null;
  /** The host (with port) an admin acknowledged as an endpoint outside the network, or null. */
  acknowledgedHost: string | null;
}

export interface Connection {
  req: ClientRequest;
  res: IncomingMessage;
  scope: "private" | "external";
}

export interface RequestOptions {
  method: "GET" | "POST";
  /** Path below the base URL, e.g. "/chat/completions". */
  path: string;
  body?: unknown;
  /** Time to the first byte of the answer (a large model can take a while to load). */
  firstByteMs: number;
  signal?: AbortSignal;
}

const CONNECT_ATTEMPTS = 4;

function mapNetworkError(error: unknown): ModelError {
  if (error instanceof ModelError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code ?? "";
  // Only the code, which is an identifier like ECONNRESET, is kept; error messages can carry addresses.
  const cause = /^[A-Z0-9_]{1,64}$/.test(code) ? code : null;
  if (code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT") return new ModelError("timeout", null, cause);
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new ModelError("unresolvable", null, cause);
  if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH|ERR_OSSL/.test(code)) {
    return new ModelError("tls", null, cause);
  }
  return new ModelError("connection-failed", null, cause);
}

/** Resolves the host of the base URL and decides whether this endpoint may be used. */
export async function resolveTarget(
  target: ModelTarget,
): Promise<{ url: URL; addresses: string[]; scope: "private" | "external" }> {
  const url = new URL(target.baseUrl);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new ModelError("address-refused");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  let addresses: string[];
  if (isIP(host)) addresses = [host];
  else if (testHooks?.resolve) addresses = await testHooks.resolve(host);
  else {
    try {
      addresses = (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);
    } catch {
      throw new ModelError("unresolvable");
    }
  }
  const decision = decideEndpoint(
    url.protocol,
    addresses,
    target.acknowledgedHost !== null && target.acknowledgedHost === endpointHost(target.baseUrl),
    { allowLoopback: testHooks?.allowLoopback === true, localNetworks: localNetworks() },
  );
  if (!decision.ok || !decision.scope) throw new ModelError(decision.error ?? "address-refused");
  return { url, addresses, scope: decision.scope };
}

/**
 * Sends one request and returns the response with its headers read. The body is left
 * unread so the caller can stream it. Several addresses are tried in turn on connection errors.
 */
export async function connect(target: ModelTarget, options: RequestOptions): Promise<Connection> {
  const { url, addresses, scope } = await resolveTarget(target);
  const secure = url.protocol === "https:";
  const basePath = url.pathname.replace(/\/+$/, "");
  const data = options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body));
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  let last: ModelError = new ModelError("connection-failed");

  for (const address of addresses.slice(0, CONNECT_ATTEMPTS)) {
    try {
      return await new Promise<Connection>((resolve, reject) => {
        if (options.signal?.aborted) return reject(new ModelError("interrupted"));
        const send = secure ? httpsRequest : httpRequest;
        const req = send({
          host: testHooks?.connectTo ? testHooks.connectTo(address) : address,
          port: url.port ? Number(url.port) : secure ? 443 : 80,
          method: options.method,
          path: `${basePath}${options.path}`,
          agent: false,
          headers: {
            host: url.host,
            accept: options.method === "POST" ? "text/event-stream, application/json" : "application/json",
            "user-agent": "GarnetOps",
            connection: "close",
            ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
            ...(target.apiKey ? { authorization: `Bearer ${target.apiKey}` } : {}),
          },
          ...(secure
            ? {
                servername: isIP(hostname) ? undefined : hostname,
                rejectUnauthorized: true,
                minVersion: "TLSv1.2" as const,
                ...(testHooks?.ca ? { ca: testHooks.ca } : {}),
              }
            : {}),
        });
        const timer = setTimeout(() => req.destroy(new ModelError("timeout")), options.firstByteMs);
        const onAbort = () => req.destroy(new ModelError("interrupted"));
        options.signal?.addEventListener("abort", onAbort, { once: true });
        const done = () => {
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onAbort);
        };
        req.once("response", (res) => {
          done();
          resolve({ req, res, scope });
        });
        // Stays attached after the response: a later socket error must never go unhandled.
        req.on("error", (error) => {
          done();
          reject(mapNetworkError(error));
        });
        req.end(data);
      });
    } catch (error) {
      last = error instanceof ModelError ? error : mapNetworkError(error);
      // Only a refused or unreachable address is worth trying the next one for.
      if (last.code !== "connection-failed") throw last;
    }
  }
  throw last;
}

/** A status that is not 2xx becomes a short code; the body is discarded unread. */
export function statusError(status: number, res: IncomingMessage): ModelError | null {
  if (status >= 200 && status < 300) return null;
  res.resume();
  if (status === 401 || status === 403) return new ModelError("auth", status);
  if (status === 404) return new ModelError("model-not-found", status);
  if (status === 429) return new ModelError("rate-limited", status);
  return new ModelError("http-error", status);
}

/** Reads at most `max` bytes of a response as text; more is an error, not a truncation. */
export async function readLimited(res: IncomingMessage, max: number, idleMs: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  let timer: NodeJS.Timeout | undefined;
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => res.destroy(new ModelError("timeout")), idleMs);
  };
  arm();
  try {
    for await (const chunk of res) {
      size += (chunk as Buffer).length;
      if (size > max) {
        res.destroy();
        throw new ModelError("too-large");
      }
      chunks.push(chunk as Buffer);
      arm();
    }
  } catch (error) {
    throw error instanceof ModelError ? error : mapNetworkError(error);
  } finally {
    clearTimeout(timer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export interface ChatRequest {
  model: string;
  messages: { role: string; content: string }[];
  maxTokens: number;
  temperature: number;
}

export interface StreamLimits {
  /** Wall-clock limit of the whole generation. */
  totalMs: number;
  /** Longest silence once the answer has started. */
  idleMs: number;
}

export interface StreamResult {
  usage: { prompt: number | null; completion: number | null } | null;
  finish: string | null;
  /** Characters handed to `onText`. */
  chars: number;
}

/**
 * Streams a chat completion. `onText` gets the text pieces as they arrive and returns false to
 * stop (the output budget is used up); the abort signal stops the request too. The result
 * says how the stream ended; an unclean end throws after the text so far was delivered.
 */
export async function streamChat(
  target: ModelTarget,
  request: ChatRequest,
  limits: StreamLimits,
  onText: (text: string) => boolean | undefined | Promise<boolean | undefined>,
  signal: AbortSignal,
  onConnected?: (scope: "private" | "external") => void,
): Promise<StreamResult> {
  const started = Date.now();
  const connection = await connect(target, {
    method: "POST",
    path: "/chat/completions",
    body: {
      model: request.model,
      messages: request.messages,
      stream: true,
      max_tokens: request.maxTokens,
      temperature: request.temperature,
    },
    firstByteMs: limits.totalMs,
    signal,
  });
  onConnected?.(connection.scope);
  const { req, res } = connection;
  const failed = statusError(res.statusCode ?? 0, res);
  if (failed) {
    req.destroy();
    throw failed;
  }

  let failure: ModelError | null = null;
  const stop = (error: ModelError) => {
    failure ??= error;
    res.destroy();
    req.destroy();
  };
  const onAbort = () => stop(new ModelError("interrupted"));
  signal.addEventListener("abort", onAbort, { once: true });
  let idle: NodeJS.Timeout | undefined;
  const armIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(() => stop(new ModelError("timeout")), limits.idleMs);
  };
  const total = setTimeout(
    () => stop(new ModelError("timeout")),
    Math.max(1, limits.totalMs - (Date.now() - started)),
  );
  armIdle();

  const result: StreamResult = { usage: null, finish: null, chars: 0 };
  let sawDone = false;
  let good = 0;
  let bad = 0;
  let consecutiveBad = 0;
  const emit = async (text: string | undefined): Promise<boolean> => {
    if (!text) return true;
    result.chars += text.length;
    return (await onText(text)) !== false;
  };

  try {
    const contentType = String(res.headers["content-type"] ?? "").toLowerCase();
    if (!contentType.includes("event-stream")) {
      const body = await readLimited(res, 1024 * 1024, limits.idleMs);
      if (looksLikeSse(body)) {
        // A stream sent with another content type (text/plain, or none at all).
        const parser = new SseParser();
        for (const event of [...parser.push(body), ...parser.end()]) {
          const chunk = parseChatChunk(event.data);
          if (!chunk) continue;
          good++;
          if (chunk.error) throw new ModelError("http-error");
          if (chunk.usage) result.usage = chunk.usage;
          if (chunk.finish) result.finish = chunk.finish;
          if (chunk.done) break;
          if (!(await emit(chunk.delta))) break;
        }
        if (good === 0) throw new ModelError("invalid-response");
        result.finish ??= "stop";
        return result;
      }
      // A server that ignores `stream: true` and answers with one JSON document.
      const chunk = parseChatChunk(body);
      if (chunk?.error) throw new ModelError("http-error");
      if (!chunk || (!chunk.delta && !chunk.usage && !chunk.message && !chunk.finish))
        throw new ModelError("invalid-response");
      await emit(chunk.delta);
      result.usage = chunk.usage ?? null;
      result.finish = chunk.finish ?? "stop";
      return result;
    }

    const decoder = new TextDecoder("utf-8", { fatal: false });
    const parser = new SseParser();
    let bytes = 0;
    const handle = async (events: { data: string }[]): Promise<boolean> => {
      for (const event of events) {
        const chunk = parseChatChunk(event.data);
        if (!chunk) {
          bad++;
          consecutiveBad++;
          // A stream that is mostly noise is not a stream we can read.
          if (consecutiveBad > 50 || (bad > 200 && good === 0)) throw new ModelError("invalid-response");
          continue;
        }
        good++;
        consecutiveBad = 0;
        if (chunk.error) throw new ModelError("http-error");
        if (chunk.usage) result.usage = chunk.usage;
        if (chunk.finish) result.finish = chunk.finish;
        if (chunk.done) {
          sawDone = true;
          return false;
        }
        if (!(await emit(chunk.delta))) return false;
      }
      return true;
    };

    for await (const piece of res) {
      armIdle();
      bytes += (piece as Buffer).length;
      if (bytes > AI_LIMITS.maxStreamBytes) throw new ModelError("too-large");
      if (!(await handle(parser.push(decoder.decode(piece as Buffer, { stream: true }))))) {
        res.destroy();
        req.destroy();
        return result;
      }
    }
    await handle(parser.end());
    if (failure) throw failure;
    // Ended without "[DONE]" and without a finish reason: the connection was cut.
    if (!sawDone && !result.finish && good > 0) throw new ModelError("connection-failed");
    if (good === 0) throw new ModelError("invalid-response");
    return result;
  } catch (error) {
    if (failure) throw failure;
    throw error instanceof ModelError ? error : mapNetworkError(error);
  } finally {
    clearTimeout(idle);
    clearTimeout(total);
    signal.removeEventListener("abort", onAbort);
    res.destroy();
    req.destroy();
  }
}

/** GET /models: the model ids the server offers (at most 200, plain names only). */
export async function listModels(
  target: ModelTarget,
  totalMs: number,
): Promise<{ models: string[]; scope: "private" | "external" }> {
  const { req, res, scope } = await connect(target, { method: "GET", path: "/models", firstByteMs: totalMs });
  try {
    const failed = statusError(res.statusCode ?? 0, res);
    if (failed) throw failed;
    const body = await readLimited(res, 1024 * 1024, totalMs);
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      throw new ModelError("invalid-response");
    }
    const list =
      (json as { data?: unknown; models?: unknown } | null)?.data ??
      (json as { models?: unknown } | null)?.models;
    if (!Array.isArray(list)) throw new ModelError("invalid-response");
    const names = new Set<string>();
    for (const item of list) {
      const id =
        typeof item === "string"
          ? item
          : ((item as { id?: unknown; name?: unknown })?.id ?? (item as { name?: unknown })?.name);
      if (typeof id === "string" && /^[\w.:/@+ -]{1,200}$/.test(id)) names.add(id);
      if (names.size >= AI_LIMITS.maxModels) break;
    }
    return { models: [...names].sort(), scope };
  } finally {
    res.destroy();
    req.destroy();
  }
}

/** A tiny, fixed request to check that the endpoint, the key and the model work. */
export async function testCompletion(
  target: ModelTarget,
  model: string,
  totalMs: number,
): Promise<{ latencyMs: number; replyChars: number; scope: "private" | "external" }> {
  const started = performance.now();
  const connection = await connect(target, {
    method: "POST",
    path: "/chat/completions",
    body: {
      model,
      messages: [{ role: "user", content: "Reply with the single word: ok" }],
      stream: false,
      max_tokens: 16,
      temperature: 0,
    },
    firstByteMs: totalMs,
  });
  const { req, res } = connection;
  try {
    const failed = statusError(res.statusCode ?? 0, res);
    if (failed) throw failed;
    const body = await readLimited(res, 256 * 1024, totalMs);
    // Any well-formed answer proves the model is there. A reasoning model may spend the few tokens
    // of the test on thinking and return no text (content null), and some servers stream although
    // `stream: false` was asked for, or send the content as a list of parts.
    let reply: string | undefined;
    const chunks = looksLikeSse(body)
      ? (() => {
          const parser = new SseParser();
          return [...parser.push(body), ...parser.end()].map((e) => parseChatChunk(e.data));
        })()
      : [parseChatChunk(body)];
    for (const chunk of chunks) {
      if (!chunk || chunk.done) continue;
      if (chunk.error) throw new ModelError("http-error");
      if (chunk.delta !== undefined || chunk.message || chunk.finish)
        reply = (reply ?? "") + (chunk.delta ?? "");
    }
    if (reply === undefined) throw new ModelError("invalid-response");
    return {
      latencyMs: Math.round(performance.now() - started),
      replyChars: reply.length,
      scope: connection.scope,
    };
  } finally {
    res.destroy();
    req.destroy();
  }
}
