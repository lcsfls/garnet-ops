import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { newId } from "@garnetops/core";
import {
  AI_LIMITS,
  type StreamNotice,
  SYSTEM_PROMPT,
  type TriageResult,
  threadChannel,
  triageNote,
} from "@garnetops/core/ai";
import {
  aiBaseUrlProblem,
  decideEndpoint,
  endpointHost,
  normalizeBaseUrl,
} from "@garnetops/core/ai-endpoint";
import { seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { boss, db, pool, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { aiBus } from "../lib/ai-bus.ts";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const s = schema;
const msg = s.chatMessage;

/** Requests per minute for one person and for the whole organisation (ADR 0013). */
const USER_PER_MINUTE = 12;
const ORG_PER_MINUTE = 40;
const PROBES_PER_MINUTE = 10;
/** Open event streams of one person in this process. */
const MAX_STREAMS_PER_USER = 6;
const HEARTBEAT_MS = 15_000;
const MAX_STREAM_MS = 20 * 60_000;
/** A message that is still pending after this long no longer counts against the concurrency limit. */
const SLOT_GRACE_SECONDS = 120;

const language = z.enum(["en", "de"]).default("en");

/* -------------------------------------------------------------------------- */
/* Endpoint checks                                                             */
/* -------------------------------------------------------------------------- */

interface EndpointCheck {
  baseUrl: string;
  host: string;
  /** "unknown": the API could not resolve the name (in the Compose stack only the worker has a route out); the worker decides. */
  scope: "private" | "external" | "unknown";
}

function invalid(path: string, message: string, code = "validation"): ProblemError {
  return new ProblemError(422, code, message, undefined, { errors: [{ path, message }] });
}

/**
 * Judges a base URL before it is stored or probed: static rules, then the addresses the host
 * resolves to from here. The worker repeats the address check on every connection and is
 * authoritative (DNS can change, and only the worker is guaranteed to have a route and the
 * right resolver); this one gives the admin an answer at once. Nothing is connected to. A name
 * that cannot be resolved here is not refused, it stays "unknown" until the worker has seen it.
 */
async function checkEndpoint(value: string, acknowledged: (host: string) => boolean): Promise<EndpointCheck> {
  const problem = aiBaseUrlProblem(value);
  if (problem) throw invalid("baseUrl", problem);
  const baseUrl = normalizeBaseUrl(value);
  const url = new URL(baseUrl);
  const host = endpointHost(baseUrl);
  const name = url.hostname.replace(/^\[|\]$/g, "");
  let addresses: string[] = [];
  if (isIP(name)) addresses = [name];
  else {
    try {
      addresses = (await lookup(name, { all: true, verbatim: true })).map((a) => a.address);
    } catch {
      return { baseUrl, host, scope: "unknown" };
    }
  }
  const decision = decideEndpoint(url.protocol as "http:" | "https:", addresses, acknowledged(host));
  // The API sits on the internal Compose network and cannot know which networks the worker is
  // on (the model may be a service next to the worker), so plain http to a private address it
  // cannot place is left to the worker, which decides on every connection.
  if (!decision.ok && decision.error === "insecure-private") return { baseUrl, host, scope: "unknown" };
  if (!decision.ok) {
    if (decision.error === "external-not-acknowledged") {
      throw new ProblemError(
        422,
        "external-not-acknowledged",
        "This address is outside your network. Confirm that finding data may be sent there",
        undefined,
        {
          host,
          errors: [{ path: "acknowledgeExternal", message: "Confirm that finding data may be sent there" }],
        },
      );
    }
    if (decision.error === "insecure-external")
      throw invalid("baseUrl", "An address outside your network needs https://");
    throw invalid("baseUrl", "This address is not allowed (loopback, link-local, metadata or reserved)");
  }
  return { baseUrl, host, scope: decision.scope as "private" | "external" };
}

async function loadSettings(organizationId: string) {
  const [row] = await db
    .select()
    .from(s.aiSettings)
    .where(eq(s.aiSettings.organizationId, organizationId))
    .limit(1);
  return row ?? null;
}

type Settings = NonNullable<Awaited<ReturnType<typeof loadSettings>>>;

function settingsView(row: Settings | null) {
  if (!row) return { configured: false as const };
  return {
    configured: true as const,
    enabled: row.enabled,
    baseUrl: row.baseUrl,
    model: row.model,
    hasApiKey: row.apiKeySecretId !== null,
    maxTokens: row.maxTokens,
    temperature: row.temperature,
    timeoutSeconds: row.timeoutSeconds,
    maxConcurrent: row.maxConcurrent,
    scope: row.endpointScope,
    insecureTransport: row.baseUrl.startsWith("http:"),
    externalAcknowledged: row.externalAckHost !== null && row.externalAckHost === endpointHost(row.baseUrl),
    externalAckAt: row.externalAckAt,
    updatedAt: row.updatedAt,
  };
}

/** Whether the model can be used right now, for everyone who may see findings. */
function availability(row: Settings | null) {
  if (!row) return { state: "not-configured" as const };
  if (!row.enabled) return { state: "disabled" as const };
  return {
    state: "ready" as const,
    model: row.model,
    scope: row.endpointScope,
    insecureTransport: row.baseUrl.startsWith("http:"),
  };
}

/* -------------------------------------------------------------------------- */
/* Messages                                                                    */
/* -------------------------------------------------------------------------- */

type MessageRow = typeof msg.$inferSelect;

function messageView(row: MessageRow, author: string | null, noted: boolean) {
  return {
    id: row.id,
    role: row.role,
    kind: row.kind,
    status: row.status,
    content: row.content,
    structured: row.structured as TriageResult | null,
    error: row.error,
    model: row.model,
    promptTokens: row.promptTokens,
    completionTokens: row.completionTokens,
    latencyMs: row.latencyMs,
    createdAt: row.createdAt,
    author,
    noted,
  };
}

async function loadMessages(threadId: string) {
  const rows = await db
    .select({ message: msg, author: s.user.name, noteId: s.findingNote.id })
    .from(msg)
    .leftJoin(s.user, eq(s.user.id, msg.createdBy))
    .leftJoin(s.findingNote, eq(s.findingNote.messageId, msg.id))
    .where(eq(msg.threadId, threadId))
    .orderBy(msg.seq);
  return rows.map((r) =>
    messageView(r.message, r.message.role === "user" ? r.author : null, r.noteId !== null),
  );
}

const ACTIVE = ["pending", "streaming"] as const;

async function ownFinding(organizationId: string, id: string) {
  const [row] = await db
    .select({ id: s.finding.id })
    .from(s.finding)
    .where(and(eq(s.finding.id, id), eq(s.finding.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Finding");
  return row;
}

async function ownThread(organizationId: string, id: string) {
  const [row] = await db
    .select()
    .from(s.chatThread)
    .where(and(eq(s.chatThread.id, id), eq(s.chatThread.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Thread");
  return row;
}

/** A message with its thread, only if it belongs to the actor's organisation. */
async function ownMessage(organizationId: string, id: string) {
  const [row] = await db
    .select({ message: msg, thread: s.chatThread })
    .from(msg)
    .innerJoin(s.chatThread, eq(s.chatThread.id, msg.threadId))
    .where(and(eq(msg.id, id), eq(s.chatThread.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Message");
  return row;
}

/** Something to ask must exist, be switched on, and not exceed the limits (ADR 0013). */
async function requireReady(actor: Actor): Promise<Settings> {
  requireRole(actor, "member");
  const settings = await loadSettings(actor.organizationId);
  const state = availability(settings).state;
  if (!settings || state !== "ready") {
    throw new ProblemError(409, "ai-not-ready", "AI triage is not available", undefined, { state });
  }
  await rateLimit(`ai:user:${actor.userId}`, USER_PER_MINUTE);
  await rateLimit(`ai:org:${actor.organizationId}`, ORG_PER_MINUTE);
  return settings;
}

async function requireFreeSlot(organizationId: string, settings: Settings): Promise<void> {
  const [row] = await db
    .select({ n: count() })
    .from(msg)
    .innerJoin(s.chatThread, eq(s.chatThread.id, msg.threadId))
    .where(
      and(
        eq(s.chatThread.organizationId, organizationId),
        inArray(msg.status, [...ACTIVE]),
        sql`${msg.createdAt} > now() - make_interval(secs => ${settings.timeoutSeconds + SLOT_GRACE_SECONDS})`,
      ),
    );
  if ((row?.n ?? 0) >= settings.maxConcurrent) {
    throw new ProblemError(429, "ai-busy", "The model is busy with other requests, try again in a moment");
  }
}

async function enqueue(actor: Actor, messageId: string, findingId: string, model: string, kind: string) {
  try {
    await boss.send(QUEUES.aiGenerate, { messageId }, { retryLimit: 0, expireInSeconds: 15 * 60 });
  } catch (error) {
    await db.update(msg).set({ status: "failed", error: "internal" }).where(eq(msg.id, messageId));
    throw error;
  }
  // The prompt is never part of the log, only what was asked about and which model answers.
  await audit(actor, "ai.request", { type: "finding", id: findingId }, { findingId, model, kind, messageId });
}

async function notifyState(threadId: string, messageId: string): Promise<void> {
  await pool.query("select pg_notify($1, json_build_object('e', 'state', 'm', $2::text)::text)", [
    threadChannel(threadId),
    messageId,
  ]);
}

/** Serialises changes of one thread, so two clicks cannot start two answers. */
async function withThreadLock<T>(
  threadId: string,
  fn: (tx: Parameters<Parameters<typeof db.transaction>[0]>[0]) => Promise<T>,
) {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${threadId}))`);
    return fn(tx);
  });
}

/* -------------------------------------------------------------------------- */
/* Bodies                                                                      */
/* -------------------------------------------------------------------------- */

const modelName = z
  .string()
  .trim()
  .max(200)
  .regex(/^[\w.:/@+ -]*$/, "Use the model name as the server lists it");

const settingsBody = z.object({
  enabled: z.boolean(),
  baseUrl: z.string().trim().min(1).max(300),
  model: modelName,
  apiKey: z.string().min(1).max(500).optional(),
  clearApiKey: z.boolean().optional(),
  maxTokens: z.number().int().min(64).max(8192),
  temperature: z.number().min(0).max(2),
  timeoutSeconds: z.number().int().min(10).max(600),
  maxConcurrent: z.number().int().min(1).max(8),
  acknowledgeExternal: z.boolean().optional(),
});

const probeBody = z.object({
  kind: z.enum(["models", "test"]),
  baseUrl: z.string().trim().min(1).max(300),
  model: modelName.optional(),
  apiKey: z.string().min(1).max(500).optional(),
  useStoredKey: z.boolean().optional(),
  acknowledgeExternal: z.boolean().optional(),
});

const askBody = z.object({ content: z.string().trim().min(1).max(AI_LIMITS.maxQuestionChars), language });
const languageBody = z.object({ language }).default({ language: "en" });

async function sealKey(organizationId: string, userId: string, plain: string): Promise<string> {
  const id = newId("sec");
  await db.insert(s.secret).values({
    id,
    organizationId,
    purpose: "ai-api-key",
    sealed: seal(plain, { organizationId, recordId: id, purpose: "ai-api-key" }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
    createdBy: userId,
  });
  return id;
}

const openStreams = new Map<string, number>();

/**
 * AI triage (ADR 0013). The API never calls the model and never sees the API key again after
 * sealing it: it stores messages, queues jobs for the worker and relays the worker's progress.
 */
export const aiRoutes = new Hono<AppEnv>()
  /* ---------------------------- settings (admins) ---------------------------- */
  .get("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    return c.json(settingsView(await loadSettings(actor.organizationId)));
  })
  .put("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = settingsBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    if (input.enabled && input.model === "") throw invalid("model", "Choose a model first");
    const before = await loadSettings(actor.organizationId);
    const endpoint = await checkEndpoint(
      input.baseUrl,
      (host) => input.acknowledgeExternal === true || before?.externalAckHost === host,
    );

    // The acknowledgement belongs to the host it was given for: a new host asks again. For a name
    // this server could not resolve, an explicit confirmation is kept too, in case it is outside.
    const kept = before?.externalAckHost === endpoint.host;
    const ackHost =
      endpoint.scope === "external"
        ? endpoint.host
        : endpoint.scope === "unknown" && (input.acknowledgeExternal === true || kept)
          ? endpoint.host
          : kept
            ? endpoint.host
            : null;
    const acknowledgedNow = ackHost !== null && !kept && endpoint.scope !== "private";

    let apiKeySecretId = before?.apiKeySecretId ?? null;
    let key: "unchanged" | "set" | "removed" = "unchanged";
    const oldSecretId = apiKeySecretId;
    if (input.apiKey) {
      apiKeySecretId = await sealKey(actor.organizationId, actor.userId, input.apiKey);
      key = "set";
    } else if (input.clearApiKey) {
      apiKeySecretId = null;
      key = oldSecretId ? "removed" : "unchanged";
    }
    const values = {
      baseUrl: endpoint.baseUrl,
      model: input.model,
      apiKeySecretId,
      contextPolicy: "metadata" as const,
      enabled: input.enabled,
      maxTokens: input.maxTokens,
      temperature: input.temperature,
      timeoutSeconds: input.timeoutSeconds,
      maxConcurrent: input.maxConcurrent,
      endpointScope: endpoint.scope,
      externalAckHost: ackHost,
      ...(acknowledgedNow
        ? { externalAckBy: actor.userId, externalAckAt: new Date() }
        : ackHost === null
          ? { externalAckBy: null, externalAckAt: null }
          : {}),
      updatedBy: actor.userId,
      updatedAt: new Date(),
    };
    await db
      .insert(s.aiSettings)
      .values({ organizationId: actor.organizationId, ...values })
      .onConflictDoUpdate({ target: s.aiSettings.organizationId, set: values });
    if (oldSecretId && oldSecretId !== apiKeySecretId) {
      await db
        .delete(s.secret)
        .where(and(eq(s.secret.id, oldSecretId), eq(s.secret.organizationId, actor.organizationId)));
    }
    await audit(
      actor,
      "ai.settings_changed",
      { type: "organization", id: actor.organizationId },
      {
        enabled: input.enabled,
        host: endpoint.host,
        scheme: new URL(endpoint.baseUrl).protocol.replace(":", ""),
        scope: endpoint.scope,
        model: input.model,
        apiKey: key,
        maxTokens: input.maxTokens,
        timeoutSeconds: input.timeoutSeconds,
        maxConcurrent: input.maxConcurrent,
        wasEnabled: before?.enabled ?? false,
      },
    );
    if (acknowledgedNow) {
      await audit(
        actor,
        "ai.external_acknowledged",
        { type: "organization", id: actor.organizationId },
        { host: endpoint.host },
      );
    }
    return c.json(settingsView(await loadSettings(actor.organizationId)));
  })
  .delete("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const before = await loadSettings(actor.organizationId);
    if (!before) return c.body(null, 204);
    await db.delete(s.aiSettings).where(eq(s.aiSettings.organizationId, actor.organizationId));
    if (before.apiKeySecretId) await db.delete(s.secret).where(eq(s.secret.id, before.apiKeySecretId));
    await audit(
      actor,
      "ai.settings_deleted",
      { type: "organization", id: actor.organizationId },
      { host: endpointHost(before.baseUrl) },
    );
    return c.body(null, 204);
  })
  /** Queues "load models" or "test connection". The worker holds the key, so it makes the call. */
  .post("/probe", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = probeBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    await rateLimit(`ai:probe:${actor.organizationId}`, PROBES_PER_MINUTE);
    if (input.kind === "test" && !input.model) throw invalid("model", "Choose a model first");
    const stored = await loadSettings(actor.organizationId);
    const endpoint = await checkEndpoint(
      input.baseUrl,
      (host) => input.acknowledgeExternal === true || stored?.externalAckHost === host,
    );
    let secretId: string | null = null;
    let temp = false;
    if (input.apiKey) {
      secretId = await sealKey(actor.organizationId, actor.userId, input.apiKey);
      temp = true;
    } else if (input.useStoredKey && stored?.apiKeySecretId) secretId = stored.apiKeySecretId;
    const id = newId("prb");
    await db.insert(s.aiProbe).values({
      id,
      organizationId: actor.organizationId,
      kind: input.kind,
      baseUrl: endpoint.baseUrl,
      model: input.model ?? null,
      secretId,
      tempSecret: temp,
      ackHost:
        endpoint.scope === "external" ||
        (endpoint.scope === "unknown" &&
          (input.acknowledgeExternal === true || stored?.externalAckHost === endpoint.host))
          ? endpoint.host
          : null,
      requestedBy: actor.userId,
    });
    try {
      await boss.send(QUEUES.aiProbe, { probeId: id }, { retryLimit: 0, expireInSeconds: 120 });
    } catch (error) {
      await db.delete(s.aiProbe).where(eq(s.aiProbe.id, id));
      if (temp && secretId) await db.delete(s.secret).where(eq(s.secret.id, secretId));
      throw error;
    }
    await audit(
      actor,
      "ai.endpoint_tested",
      { type: "organization", id: actor.organizationId },
      { kind: input.kind, host: endpoint.host, scope: endpoint.scope },
    );
    return c.json({ id }, 202);
  })
  .get("/probe/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const [row] = await db
      .select({ status: s.aiProbe.status, kind: s.aiProbe.kind, result: s.aiProbe.result })
      .from(s.aiProbe)
      .where(and(eq(s.aiProbe.id, c.req.param("id")), eq(s.aiProbe.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw notFound("Probe");
    return c.json(row);
  })

  /* ------------------------------ conversations ------------------------------ */
  .get("/findings/:id/thread", async (c) => {
    const actor = c.get("actor");
    await ownFinding(actor.organizationId, c.req.param("id"));
    const settings = await loadSettings(actor.organizationId);
    const [thread] = await db
      .select({ id: s.chatThread.id })
      .from(s.chatThread)
      .where(
        and(
          eq(s.chatThread.findingId, c.req.param("id")),
          eq(s.chatThread.organizationId, actor.organizationId),
        ),
      )
      .limit(1);
    const available = availability(settings);
    return c.json({
      ...available,
      canAsk: available.state === "ready" && actor.role !== "viewer",
      threadId: thread?.id ?? null,
      messages: thread ? await loadMessages(thread.id) : [],
    });
  })
  /** Starts the structured triage of a finding (once; later changes go through "regenerate"). */
  .post("/findings/:id/triage", async (c) => {
    const actor = c.get("actor");
    const findingId = c.req.param("id");
    const input = languageBody.parse(await c.req.json().catch(() => ({})));
    await ownFinding(actor.organizationId, findingId);
    const settings = await requireReady(actor);

    const threadId = await db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${findingId}))`);
      const [existing] = await tx
        .select({ id: s.chatThread.id })
        .from(s.chatThread)
        .where(eq(s.chatThread.findingId, findingId))
        .limit(1);
      if (existing) return existing.id;
      const id = newId("thr");
      await tx
        .insert(s.chatThread)
        .values({ id, organizationId: actor.organizationId, findingId, createdBy: actor.userId });
      return id;
    });
    const existing = await db
      .select({ id: msg.id, status: msg.status })
      .from(msg)
      .where(and(eq(msg.threadId, threadId), eq(msg.kind, "triage")))
      .limit(1);
    if (existing[0]) return c.json({ threadId, messageId: existing[0].id, queued: false });

    await requireFreeSlot(actor.organizationId, settings);
    const messageId = await withThreadLock(threadId, async (tx) => {
      const [again] = await tx
        .select({ id: msg.id })
        .from(msg)
        .where(and(eq(msg.threadId, threadId), eq(msg.kind, "triage")))
        .limit(1);
      if (again) return null;
      const id = newId("msg");
      await tx.insert(msg).values({
        id,
        threadId,
        role: "assistant",
        kind: "triage",
        content: "",
        status: "pending",
        context: { language: input.language },
        createdBy: actor.userId,
      });
      return id;
    });
    if (!messageId) return c.json({ threadId, queued: false });
    await enqueue(actor, messageId, findingId, settings.model, "triage");
    return c.json({ threadId, messageId, queued: true }, 202);
  })
  /** A follow-up question; the answer is a new message that the worker streams. */
  .post("/threads/:id/messages", async (c) => {
    const actor = c.get("actor");
    const input = askBody.parse(await c.req.json());
    const thread = await ownThread(actor.organizationId, c.req.param("id"));
    const settings = await requireReady(actor);
    await requireFreeSlot(actor.organizationId, settings);
    const created = await withThreadLock(thread.id, async (tx) => {
      const [busy] = await tx
        .select({ id: msg.id })
        .from(msg)
        .where(and(eq(msg.threadId, thread.id), inArray(msg.status, [...ACTIVE])))
        .limit(1);
      if (busy) throw new ProblemError(409, "ai-thread-busy", "An answer is still being written");
      await tx.insert(msg).values({
        id: newId("msg"),
        threadId: thread.id,
        role: "user",
        kind: "chat",
        content: input.content,
        status: "complete",
        createdBy: actor.userId,
      });
      const id = newId("msg");
      await tx.insert(msg).values({
        id,
        threadId: thread.id,
        role: "assistant",
        kind: "chat",
        content: "",
        status: "pending",
        context: { language: input.language },
        createdBy: actor.userId,
      });
      return id;
    });
    await enqueue(actor, created, thread.findingId, settings.model, "followup");
    return c.json({ messageId: created }, 202);
  })
  .post("/messages/:id/stop", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const { message, thread } = await ownMessage(actor.organizationId, c.req.param("id"));
    const [row] = await db
      .update(msg)
      .set({ status: "stopped" })
      .where(and(eq(msg.id, message.id), inArray(msg.status, [...ACTIVE])))
      .returning({ id: msg.id });
    if (row) {
      await notifyState(thread.id, message.id);
      await audit(
        actor,
        "ai.stopped",
        { type: "finding", id: thread.findingId },
        { findingId: thread.findingId, messageId: message.id },
      );
    }
    return c.body(null, 204);
  })
  /** Replaces the last answer with a new one. */
  .post("/messages/:id/regenerate", async (c) => {
    const actor = c.get("actor");
    const input = languageBody.parse(await c.req.json().catch(() => ({})));
    const { message, thread } = await ownMessage(actor.organizationId, c.req.param("id"));
    const settings = await requireReady(actor);
    if (message.role !== "assistant")
      throw new ProblemError(409, "not-regenerable", "Only an answer can be regenerated");
    await requireFreeSlot(actor.organizationId, settings);
    const created = await withThreadLock(thread.id, async (tx) => {
      const [last] = await tx
        .select({ id: msg.id })
        .from(msg)
        .where(eq(msg.threadId, thread.id))
        .orderBy(desc(msg.seq))
        .limit(1);
      if (last?.id !== message.id)
        throw new ProblemError(409, "not-regenerable", "Only the last answer can be regenerated");
      const [current] = await tx
        .select({ status: msg.status })
        .from(msg)
        .where(eq(msg.id, message.id))
        .limit(1);
      if (!current || (ACTIVE as readonly string[]).includes(current.status)) {
        throw new ProblemError(409, "ai-thread-busy", "An answer is still being written");
      }
      await tx.delete(msg).where(eq(msg.id, message.id));
      const id = newId("msg");
      await tx.insert(msg).values({
        id,
        threadId: thread.id,
        role: "assistant",
        kind: message.kind,
        content: "",
        status: "pending",
        context: { language: input.language },
        createdBy: actor.userId,
      });
      return id;
    });
    await enqueue(actor, created, thread.findingId, settings.model, "regenerate");
    return c.json({ messageId: created }, 202);
  })
  /** What the model was told: the fixed system prompt and the first message with the finding's data. */
  .get("/messages/:id/context", async (c) => {
    const actor = c.get("actor");
    const { message, thread } = await ownMessage(actor.organizationId, c.req.param("id"));
    let prompt = (message.context as { prompt?: unknown } | null)?.prompt;
    if (typeof prompt !== "string") {
      const [triage] = await db
        .select({ context: msg.context })
        .from(msg)
        .where(and(eq(msg.threadId, thread.id), eq(msg.kind, "triage")))
        .limit(1);
      prompt = (triage?.context as { prompt?: unknown } | null)?.prompt;
    }
    return c.json({ system: SYSTEM_PROMPT, prompt: typeof prompt === "string" ? prompt : null });
  })
  /** A human takes an AI suggestion over as a note on the finding. Nothing else changes. */
  .post("/messages/:id/accept-note", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const { message, thread } = await ownMessage(actor.organizationId, c.req.param("id"));
    if (message.role !== "assistant" || message.status !== "complete") {
      throw new ProblemError(409, "not-acceptable", "Only a finished answer can be taken over");
    }
    const structured = message.structured as TriageResult | null;
    const body = (structured ? triageNote(structured) : message.content).trim().slice(0, 4000);
    if (!body) throw new ProblemError(409, "not-acceptable", "There is nothing to take over");
    const id = newId("nte");
    const inserted = await db
      .insert(s.findingNote)
      .values({
        id,
        organizationId: actor.organizationId,
        findingId: thread.findingId,
        authorUserId: actor.userId,
        body,
        source: "ai",
        messageId: message.id,
        meta: structured
          ? {
              exploitability: structured.exploitability,
              reachable: structured.reachable,
              confidence: structured.confidence,
              ...(structured.upgradeTo ? { upgradeTo: structured.upgradeTo } : {}),
            }
          : null,
      })
      .onConflictDoNothing({ target: s.findingNote.messageId })
      .returning({ id: s.findingNote.id });
    if (inserted.length === 0) throw new ProblemError(409, "already-noted", "This answer is already a note");
    await audit(
      actor,
      "ai.note_accepted",
      { type: "finding", id: thread.findingId },
      { findingId: thread.findingId, noteId: id, messageId: message.id },
    );
    return c.json({ id }, 201);
  })

  /* --------------------------------- stream --------------------------------- */
  /**
   * Server-sent events for one thread. Always starts with a `snapshot` of the stored messages
   * (which is also how a reconnect resumes), then `delta` events with the text as the worker
   * writes it, and a `message` event with the final state of each answer. When nothing is
   * pending any more it says `done` and ends, so the browser does not reconnect needlessly.
   */
  .get("/threads/:id/stream", async (c) => {
    const actor = c.get("actor");
    const thread = await ownThread(actor.organizationId, c.req.param("id"));
    if ((openStreams.get(actor.userId) ?? 0) >= MAX_STREAMS_PER_USER) {
      throw new ProblemError(429, "too-many-streams", "Too many open streams");
    }
    openStreams.set(actor.userId, (openStreams.get(actor.userId) ?? 0) + 1);

    const response = streamSSE(
      c,
      async (stream) => {
        const sent = new Map<string, number>();
        const active = new Set<string>();
        let finished = false;
        let finish!: () => void;
        const ended = new Promise<void>((resolve) => {
          finish = resolve;
        });
        let chain: Promise<void> = Promise.resolve();
        const later = (fn: () => Promise<void>) => {
          chain = chain.then(fn).catch(() => {});
        };
        const send = (event: string, data: unknown, id?: string) =>
          stream.writeSSE({ event, data: JSON.stringify(data), ...(id ? { id } : {}) });
        const track = (m: { id: string; status: string; content: string }) => {
          sent.set(m.id, Buffer.byteLength(m.content));
          if ((ACTIVE as readonly string[]).includes(m.status)) active.add(m.id);
          else active.delete(m.id);
        };
        const stop = async () => {
          if (finished) return;
          finished = true;
          await send("done", {}).catch(() => {});
          finish();
        };
        const snapshot = async () => {
          const messages = await loadMessages(thread.id);
          sent.clear();
          active.clear();
          for (const m of messages) track(m);
          await send("snapshot", { messages });
          if (active.size === 0) await stop();
        };
        const onNotice = (payload: string) =>
          later(async () => {
            if (finished) return;
            let notice: StreamNotice;
            try {
              notice = JSON.parse(payload) as StreamNotice;
            } catch {
              return;
            }
            if (typeof notice?.m !== "string") return;
            if (notice.e === "delta") {
              const have = sent.get(notice.m);
              if (have === undefined || typeof notice.d !== "string" || typeof notice.from !== "number") {
                return snapshot();
              }
              const bytes = Buffer.byteLength(notice.d);
              if (notice.from + bytes <= have) return; // already included in a snapshot
              if (notice.from !== have) return snapshot(); // a gap: start over from the stored text
              sent.set(notice.m, have + bytes);
              await send(
                "delta",
                { id: notice.m, from: have, text: notice.d },
                `${notice.m}:${have + bytes}`,
              );
            } else if (notice.e === "state") {
              const [row] = await db
                .select({ message: msg, author: s.user.name, noteId: s.findingNote.id })
                .from(msg)
                .leftJoin(s.user, eq(s.user.id, msg.createdBy))
                .leftJoin(s.findingNote, eq(s.findingNote.messageId, msg.id))
                .where(and(eq(msg.id, notice.m), eq(msg.threadId, thread.id)))
                .limit(1);
              if (!row) return snapshot(); // e.g. a regenerated answer replaced it
              track(row.message);
              await send(
                "message",
                messageView(
                  row.message,
                  row.message.role === "user" ? row.author : null,
                  row.noteId !== null,
                ),
              );
              if (active.size === 0) await stop();
            }
          });

        let unsubscribe: (() => void) | null = null;
        const heartbeat = setInterval(() => {
          stream.write(": keep-alive\n\n").catch(() => {});
        }, HEARTBEAT_MS);
        const lifetime = setTimeout(() => later(stop), MAX_STREAM_MS);
        stream.onAbort(() => {
          finished = true;
          finish();
        });
        try {
          // Listen first, then read the stored state: whatever is written in between is not lost.
          unsubscribe = await aiBus.subscribe(thread.id, onNotice, () => later(snapshot));
          later(snapshot);
          await ended;
          await chain;
        } finally {
          clearInterval(heartbeat);
          clearTimeout(lifetime);
          unsubscribe?.();
          const left = (openStreams.get(actor.userId) ?? 1) - 1;
          if (left <= 0) openStreams.delete(actor.userId);
          else openStreams.set(actor.userId, left);
        }
      },
      async (error) => {
        // Not the message: it may quote data.
        console.error("ai stream:", (error as Error)?.name ?? "error");
      },
    );
    // streamSSE sets no-cache; a proxy must also neither store nor compress (and so buffer) the stream.
    response.headers.set("cache-control", "no-store, no-transform");
    response.headers.set("x-accel-buffering", "no");
    return response;
  });
