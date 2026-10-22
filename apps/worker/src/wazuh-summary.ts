/**
 * "Summarise with AI" on the XDR page (ADR 0015). The worker is the only process that opens the
 * model's API key (ADR 0013), so it makes the call: the API stores a pending summary and queues
 * a job; the worker builds the prompt from the stored aggregates (numbers only, see
 * packages/core/src/xdr-summary.ts), asks the model through the same address policy as AI
 * triage and stores the answer. The answer is untrusted text: it is cleaned, cut, never
 * executed, never able to change a setting, and shown with the label "AI suggestion".
 */
import { AI_LIMITS, type AiError, type AiLanguage, sanitizeModelText, ThinkFilter } from "@garnetops/core/ai";
import { readSnapshot } from "@garnetops/core/wazuh";
import { buildSummaryFacts, buildSummaryMessages } from "@garnetops/core/xdr-summary";
import { schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { openKey } from "./ai.ts";
import { ModelError, type ModelTarget, streamChat } from "./ai-client.ts";
import { db } from "./db.ts";

export const WAZUH_SUMMARY_QUEUE = "xdr.summary";
const STALE_MINUTES = 15;

const w = schema.wazuhSummary;

export async function runWazuhSummary(summaryId: string): Promise<void> {
  const [row] = await db
    .update(w)
    .set({ status: "running" })
    .where(and(eq(w.id, summaryId), eq(w.status, "pending")))
    .returning();
  if (!row) return;
  const started = performance.now();
  const finish = async (update: Partial<typeof w.$inferInsert>): Promise<void> => {
    await db
      .update(w)
      .set({ ...update, finishedAt: new Date() })
      .where(and(eq(w.id, row.id), eq(w.status, "running")));
  };
  const fail = (code: AiError): Promise<void> => finish({ status: "failed", error: code });

  const [settings] = await db
    .select()
    .from(schema.aiSettings)
    .where(eq(schema.aiSettings.organizationId, row.organizationId))
    .limit(1);
  if (!settings) return fail("not-configured");
  if (!settings.enabled) return fail("disabled");

  const [connection] = await db
    .select()
    .from(schema.wazuhConnection)
    .where(eq(schema.wazuhConnection.id, row.connectionId))
    .limit(1);
  const [stored] = await db
    .select()
    .from(schema.wazuhSnapshot)
    .where(eq(schema.wazuhSnapshot.connectionId, row.connectionId))
    .limit(1);
  if (!connection || !stored) return fail("internal");

  // Only counts of agents by state; no agent is named.
  const a = schema.wazuhAgent;
  const states = await db
    .select({ status: a.status, n: sql<number>`count(*)::int` })
    .from(a)
    .where(and(eq(a.connectionId, row.connectionId), eq(a.isManager, false)))
    .groupBy(a.status);
  const count = (status: string) => states.find((s) => s.status === status)?.n ?? 0;
  const agents = {
    total: states.reduce((n, s) => n + s.n, 0),
    active: count("active"),
    disconnected: count("disconnected"),
    neverConnected: count("never_connected"),
    pending: count("pending"),
  };
  const facts = buildSummaryFacts(readSnapshot(stored.data), agents, connection.adapter ?? "wazuh4");
  const language: AiLanguage = row.language === "de" ? "de" : "en";
  const messages = buildSummaryMessages(facts, language);

  let apiKey: string | null;
  try {
    apiKey = await openKey(settings.apiKeySecretId, row.organizationId);
  } catch {
    return fail("internal");
  }
  const target: ModelTarget = {
    baseUrl: settings.baseUrl,
    apiKey,
    acknowledgedHost: settings.externalAckHost,
  };

  const controller = new AbortController();
  const filter = new ThinkFilter();
  let text = "";
  let truncated = false;
  const take = (visible: string): boolean => {
    if (!visible) return true;
    const room = AI_LIMITS.maxOutputChars - text.length;
    const part = visible.length > room ? visible.slice(0, Math.max(0, room)) : visible;
    text += part;
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
        maxTokens: Math.min(settings.maxTokens, 1024),
        temperature: settings.temperature,
      },
      { totalMs, idleMs: Math.min(60_000, totalMs) },
      (piece) => take(sanitizeModelText(filter.push(piece))),
      controller.signal,
    );
    usage = result.usage;
    if (!truncated) take(sanitizeModelText(filter.end()));
  } catch (error) {
    code = error instanceof ModelError ? error.code : "internal";
    // Never log messages: a parser error can quote the model's text.
    if (!(error instanceof ModelError))
      console.error(`xdr summary ${row.id}: ${(error as Error)?.name ?? "error"}`);
  }
  if (truncated) code = "too-large";
  if (!code && text.trim() === "") code = "invalid-response";
  await finish({
    status: code ? "failed" : "complete",
    error: code,
    content: code ? "" : text,
    model: settings.model,
    promptTokens: usage?.prompt ?? null,
    completionTokens: usage?.completion ?? null,
    latencyMs: Math.round(performance.now() - started),
  });
}

/** Marks summaries whose worker is gone as failed. */
export async function sweepWazuhSummaries(): Promise<void> {
  await db
    .update(w)
    .set({ status: "failed", error: "interrupted", finishedAt: new Date() })
    .where(
      and(
        sql`${w.status} in ('pending', 'running')`,
        sql`${w.createdAt} < now() - ${`${STALE_MINUTES} minutes`}::interval`,
      ),
    );
}
