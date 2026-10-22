/**
 * AI triage in the worker (ADR 0013). Only the worker opens the API key, so only the worker
 * talks to the model: the API queues a job for a message that is already stored as pending,
 * the worker streams the answer from the model and appends it to the message in small steps.
 * Every step is also announced on the thread's PostgreSQL channel, where the API's event
 * stream picks it up and relays it to the browser. The database always holds at least as much
 * as has been announced, so a client that connects late starts from the stored text.
 *
 * What this module never does: change a finding, a gate run or a setting. Its only writes are
 * the AI message it was asked to produce, the probe result, and the endpoint scope it observed.
 */
import {
  AI_LIMITS,
  type AiError,
  type AiLanguage,
  buildContext,
  buildMessages,
  type ChatTurn,
  parseTriageResult,
  sanitizeModelText,
  splitUtf8,
  ThinkFilter,
  type TriageFacts,
  threadChannel,
} from "@garnetops/core/ai";
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, asc, eq, lt, sql } from "drizzle-orm";
import { listModels, ModelError, type ModelTarget, streamChat, testCompletion } from "./ai-client.ts";
import { db, pool } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";

export const AI_QUEUE = "ai.generate";
export const AI_PROBE_QUEUE = "ai.probe";

/** Pending or streaming longer than this means the worker that had the job is gone. */
const STALE_MINUTES = 15;
/** How often buffered text is written and announced. */
const FLUSH_MS = 120;
const FLUSH_BYTES = 800;
const STATUS_POLL_MS = 1500;
const PROBE_MS = 25_000;

const msg = schema.chatMessage;

/** Announces on the thread's channel that a message changed state; the API then reads the row. */
async function announceState(threadId: string, messageId: string): Promise<void> {
  await pool.query("select pg_notify($1, json_build_object('e', 'state', 'm', $2::text)::text)", [
    threadChannel(threadId),
    messageId,
  ]);
}

export async function openKey(secretId: string | null, organizationId: string): Promise<string | null> {
  if (!secretId) return null;
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, secretId),
        eq(schema.secret.organizationId, organizationId),
        eq(schema.secret.purpose, "ai-api-key"),
      ),
    )
    .limit(1);
  if (!secret) return null;
  const plain = open(
    secret.sealed,
    { organizationId, recordId: secret.id, purpose: "ai-api-key" },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

/* -------------------------------------------------------------------------- */
/* Writing the answer                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Collects text and writes it in small steps: appended to the message and announced in one
 * statement, so the stored text never falls behind what clients were told. Notices stay far
 * below the 8000 bytes PostgreSQL allows (pieces of at most AI_LIMITS.maxDeltaBytes).
 */
class StreamWriter {
  private pending = "";
  private timer: NodeJS.Timeout | null = null;
  private chain: Promise<void> = Promise.resolve();
  /** True once the message is no longer ours to write (the user stopped it). */
  stopped = false;

  private readonly threadId: string;
  private readonly messageId: string;
  private readonly onStopped: () => void;

  constructor(threadId: string, messageId: string, onStopped: () => void) {
    this.threadId = threadId;
    this.messageId = messageId;
    this.onStopped = onStopped;
  }

  append(text: string): void {
    this.pending += text;
    if (Buffer.byteLength(this.pending) >= FLUSH_BYTES) this.flush();
    else if (!this.timer) this.timer = setTimeout(() => this.flush(), FLUSH_MS);
  }

  private flush(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const text = this.pending;
    this.pending = "";
    if (!text) return;
    this.chain = this.chain.then(async () => {
      if (this.stopped) return;
      for (const piece of splitUtf8(text, AI_LIMITS.maxDeltaBytes)) {
        const result = await pool.query(
          `with u as (
             update chat_message set content = content || $2::text
             where id = $1 and status = 'streaming'
             returning id, octet_length(content) as len)
           select pg_notify($3, json_build_object('e', 'delta', 'm', id, 'from', len - $4::int, 'd', $2::text)::text) from u`,
          [this.messageId, piece, threadChannel(this.threadId), Buffer.byteLength(piece)],
        );
        if (result.rowCount === 0) {
          this.stopped = true;
          this.onStopped();
          return;
        }
      }
    });
  }

  /** Writes what is left and waits for every earlier write. */
  async close(): Promise<void> {
    this.flush();
    await this.chain;
  }
}

/* -------------------------------------------------------------------------- */
/* Facts for the context builder                                               */
/* -------------------------------------------------------------------------- */

async function loadFacts(
  organizationId: string,
  findingId: string,
): Promise<{ facts: TriageFacts; urls: string[] } | null> {
  const f = schema.finding;
  const v = schema.vulnerability;
  const [row] = await db
    .select({ finding: f, vulnerability: v, repository: schema.repository })
    .from(f)
    .innerJoin(v, eq(v.id, f.vulnerabilityId))
    .innerJoin(schema.repository, eq(schema.repository.id, f.repositoryId))
    .where(and(eq(f.id, findingId), eq(f.organizationId, organizationId)))
    .limit(1);
  if (!row) return null;
  const [others] = await db
    .select({ n: sql<number>`count(distinct ${f.repositoryId})::int` })
    .from(f)
    .where(
      and(
        eq(f.organizationId, organizationId),
        eq(f.vulnerabilityId, row.finding.vulnerabilityId),
        eq(f.state, "open"),
        sql`${f.repositoryId} <> ${row.finding.repositoryId}`,
      ),
    );
  const [servers] = await db
    .select({ n: sql<number>`count(distinct ${schema.hostFinding.hostId})::int` })
    .from(schema.hostFinding)
    .where(
      and(
        eq(schema.hostFinding.organizationId, organizationId),
        eq(schema.hostFinding.vulnerabilityId, row.finding.vulnerabilityId),
        eq(schema.hostFinding.state, "open"),
      ),
    );
  const urls = row.vulnerability.urls ?? [];
  return {
    urls,
    facts: {
      vulnerabilityId: row.finding.vulnerabilityId,
      aliases: row.vulnerability.aliases ?? [],
      severity: row.finding.severity,
      cvssScore: row.vulnerability.cvssScore,
      cvssVector: row.vulnerability.cvssVector,
      epss: row.vulnerability.epss,
      knownExploited: row.vulnerability.knownExploited,
      publishedAt: row.vulnerability.publishedAt?.toISOString() ?? null,
      description: row.vulnerability.description,
      referenceUrls: urls,
      packageName: row.finding.packageName,
      packageVersion: row.finding.packageVersion,
      packageType: row.finding.packageType,
      fixedIn: row.finding.fixedIn ?? [],
      fixState: row.finding.fixState,
      locations: row.finding.locations ?? [],
      repositoryName: row.repository.name,
      branch: row.repository.branch,
      otherRepositories: others?.n ?? 0,
      affectedServers: servers?.n ?? 0,
    },
  };
}

const languageOf = (context: unknown): AiLanguage =>
  (context as { language?: unknown } | null)?.language === "de" ? "de" : "en";

/* -------------------------------------------------------------------------- */
/* One generation                                                              */
/* -------------------------------------------------------------------------- */

async function finish(row: typeof msg.$inferSelect, update: Partial<typeof msg.$inferInsert>): Promise<void> {
  // Only a message that is still ours: a user who pressed Stop has already set its final state.
  const done = await db
    .update(msg)
    .set(update)
    .where(and(eq(msg.id, row.id), eq(msg.status, "streaming")))
    .returning({ id: msg.id });
  if (done.length > 0) await announceState(row.threadId, row.id);
}

/** Produces the answer for one pending message. Idempotent: a message that is not pending is left alone. */
export async function runGeneration(messageId: string): Promise<void> {
  const [row] = await db
    .update(msg)
    .set({ status: "streaming" })
    .where(and(eq(msg.id, messageId), eq(msg.status, "pending"), eq(msg.role, "assistant")))
    .returning();
  if (!row) return;
  const started = performance.now();
  const [thread] = await db
    .select()
    .from(schema.chatThread)
    .where(eq(schema.chatThread.id, row.threadId))
    .limit(1);
  if (!thread) return;
  await announceState(thread.id, row.id);

  const fail = (code: AiError) => finish(row, { status: "failed", error: code });

  const [settings] = await db
    .select()
    .from(schema.aiSettings)
    .where(eq(schema.aiSettings.organizationId, thread.organizationId))
    .limit(1);
  if (!settings) return fail("not-configured");
  if (!settings.enabled) return fail("disabled");

  const loaded = await loadFacts(thread.organizationId, thread.findingId);
  if (!loaded) return fail("internal");

  // Context: a triage builds it fresh; a follow-up reuses what the model saw the first time.
  const language = languageOf(row.context);
  const earlier = await db
    .select()
    .from(msg)
    .where(and(eq(msg.threadId, thread.id), lt(msg.seq, row.seq)))
    .orderBy(asc(msg.seq));
  const triageTurn = earlier.find((m) => m.kind === "triage" && m.status === "complete");
  const storedPrompt = (triageTurn?.context as { prompt?: unknown } | null)?.prompt;
  const isTriage = row.kind === "triage";
  const context =
    !isTriage && typeof storedPrompt === "string"
      ? storedPrompt
      : buildContext(loaded.facts, { triage: isTriage, language }).prompt;
  if (isTriage || typeof storedPrompt !== "string") {
    await db
      .update(msg)
      .set({ context: { prompt: context, language, version: 1 } })
      .where(eq(msg.id, row.id));
  }

  // Earlier turns that are complete; the last user turn is the question being answered.
  const turns: ChatTurn[] = earlier
    .filter((m) => m.status === "complete" && m.content.trim() !== "")
    .map((m) => ({ role: m.role, content: m.content }));
  let question: string | undefined;
  if (!isTriage && turns.at(-1)?.role === "user") question = turns.pop()?.content;
  const messages = buildMessages({ context, history: turns, question });

  let apiKey: string | null;
  try {
    apiKey = await openKey(settings.apiKeySecretId, thread.organizationId);
  } catch {
    return fail("internal");
  }
  const target: ModelTarget = {
    baseUrl: settings.baseUrl,
    apiKey,
    acknowledgedHost: settings.externalAckHost,
  };

  const controller = new AbortController();
  const writer = new StreamWriter(thread.id, row.id, () => controller.abort());
  // A user's Stop is noticed at the next write; this also covers a model that goes quiet.
  const poll = setInterval(() => {
    db.select({ status: msg.status })
      .from(msg)
      .where(eq(msg.id, row.id))
      .limit(1)
      .then(([r]) => {
        if (r && r.status !== "streaming") {
          writer.stopped = true;
          controller.abort();
        }
      })
      .catch(() => {});
  }, STATUS_POLL_MS);

  const filter = new ThinkFilter();
  let text = "";
  let truncated = false;
  const take = (visible: string): boolean => {
    if (!visible) return true;
    const room = AI_LIMITS.maxOutputChars - text.length;
    const part = visible.length > room ? visible.slice(0, Math.max(0, room)) : visible;
    text += part;
    writer.append(part);
    if (part.length < visible.length) {
      truncated = true;
      return false;
    }
    return true;
  };

  let code: AiError | null = null;
  let usage: { prompt: number | null; completion: number | null } | null = null;
  try {
    const totalMs = settings.timeoutSeconds * 1000;
    const result = await streamChat(
      target,
      {
        model: settings.model,
        messages,
        maxTokens: settings.maxTokens,
        temperature: settings.temperature,
      },
      { totalMs, idleMs: Math.min(60_000, totalMs) },
      (piece) => take(sanitizeModelText(filter.push(piece))) && !writer.stopped,
      controller.signal,
      (scope) => {
        if (scope !== settings.endpointScope) {
          db.update(schema.aiSettings)
            .set({ endpointScope: scope })
            .where(eq(schema.aiSettings.organizationId, thread.organizationId))
            .catch(() => {});
        }
      },
    );
    usage = result.usage;
    if (!truncated) take(sanitizeModelText(filter.end()));
  } catch (error) {
    code = error instanceof ModelError ? error.code : "internal";
    // Never log messages: a parser error can quote the model's text.
    if (!(error instanceof ModelError)) console.error(`ai ${row.id}: ${(error as Error)?.name ?? "error"}`);
  } finally {
    clearInterval(poll);
  }
  await writer.close().catch(() => {
    code ??= "internal";
  });
  if (writer.stopped) return; // the user pressed Stop: its state is already final
  if (truncated) code = "too-large";
  if (!code && text.trim() === "") code = "invalid-response";

  const structured = !code && isTriage ? parseTriageResult(text, loaded.urls) : null;
  await finish(row, {
    status: code ? "failed" : "complete",
    error: code,
    structured: structured ? { ...structured } : null,
    model: settings.model,
    promptTokens: usage?.prompt ?? null,
    completionTokens: usage?.completion ?? null,
    latencyMs: Math.round(performance.now() - started),
  });
}

/* -------------------------------------------------------------------------- */
/* Probes: load models, test connection                                        */
/* -------------------------------------------------------------------------- */

/** Runs one queued probe and writes its result; keys typed for the probe are deleted afterwards. */
export async function runProbe(probeId: string): Promise<void> {
  const [probe] = await db
    .select()
    .from(schema.aiProbe)
    .where(and(eq(schema.aiProbe.id, probeId), eq(schema.aiProbe.status, "pending")))
    .limit(1);
  if (!probe) return;
  let result: Record<string, unknown>;
  try {
    const target: ModelTarget = {
      baseUrl: probe.baseUrl,
      apiKey: await openKey(probe.secretId, probe.organizationId),
      acknowledgedHost: probe.ackHost,
    };
    if (probe.kind === "models") {
      const { models, scope } = await listModels(target, PROBE_MS);
      result = { ok: true, models, scope };
    } else {
      if (!probe.model) throw new ModelError("model-not-found");
      const test = await testCompletion(target, probe.model, PROBE_MS);
      result = { ok: true, ...test };
    }
  } catch (error) {
    const code: AiError = error instanceof ModelError ? error.code : "internal";
    if (!(error instanceof ModelError))
      console.error(`ai probe ${probe.id}: ${(error as Error)?.name ?? "error"}`);
    result = { ok: false, error: code, status: error instanceof ModelError ? error.status : null };
  }
  await db.update(schema.aiProbe).set({ status: "done", result }).where(eq(schema.aiProbe.id, probe.id));
  if (probe.tempSecret && probe.secretId) {
    await db.delete(schema.secret).where(eq(schema.secret.id, probe.secretId));
  }
}

/** Marks generations whose worker is gone as failed and removes old probes and their keys. */
export async function sweepAi(): Promise<void> {
  const stale = await db
    .update(msg)
    .set({ status: "failed", error: "interrupted" })
    .where(
      and(
        sql`${msg.status} in ('pending', 'streaming')`,
        sql`${msg.createdAt} < now() - ${`${STALE_MINUTES} minutes`}::interval`,
      ),
    )
    .returning({ id: msg.id, threadId: msg.threadId });
  for (const m of stale) await announceState(m.threadId, m.id).catch(() => {});
  const old = await db
    .delete(schema.aiProbe)
    .where(sql`${schema.aiProbe.createdAt} < now() - interval '1 hour'`)
    .returning({ secretId: schema.aiProbe.secretId, temp: schema.aiProbe.tempSecret });
  for (const p of old) {
    if (p.temp && p.secretId) await db.delete(schema.secret).where(eq(schema.secret.id, p.secretId));
  }
}
