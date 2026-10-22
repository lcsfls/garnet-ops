/**
 * "Summarise with AI" on the Attacks page (ADR 0016). Same life cycle as the XDR summary
 * (ADR 0015): the API stores a pending summary and queues a job; the worker, the only process
 * that opens the model's API key (ADR 0013), builds the prompt from the stored aggregates and
 * calls the model through the same address policy as AI triage. The prompt holds numbers per
 * country code and AS number only (packages/core/src/attack-summary.ts), for Wazuh and for UniFi IPS
 * events (ADR 0022 section 7.6): no IP address, no signature or category text, no organisation, agent,
 * device or site name. The answer is untrusted text: cleaned, cut, never executed,
 * never able to change a setting, and shown with the label "AI suggestion".
 */
import { AI_LIMITS, type AiError, type AiLanguage, sanitizeModelText, ThinkFilter } from "@garnetops/core/ai";
import {
  type AttackWindowInput,
  buildAttackFacts,
  buildAttackMessages,
} from "@garnetops/core/attack-summary";
import { WINDOWS } from "@garnetops/core/wazuh";
import { loadAttackSources, loadUnifiSources, loadUnifiTotals, schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { openKey } from "./ai.ts";
import { ModelError, type ModelTarget, streamChat } from "./ai-client.ts";
import { db } from "./db.ts";

export const ATTACK_SUMMARY_QUEUE = "attacks.summary";
const STALE_MINUTES = 15;

const w = schema.attackSummary;

export async function runAttackSummary(summaryId: string): Promise<void> {
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

  const aw = schema.wazuhAttackWindow;
  const stored = row.connectionId
    ? await db.select().from(aw).where(eq(aw.connectionId, row.connectionId))
    : [];
  // UniFi IPS events are part of the picture as soon as the organisation has stored some (ADR 0022). The 30 day totals
  // and the period before them cover the shorter windows too, so one look decides.
  const longest = await loadUnifiTotals(db, row.organizationId, "30d");
  const hasUnifi = longest.alerts + longest.previousAlerts > 0;
  if (stored.length === 0 && !hasUnifi) return fail("internal");
  const input: Partial<Record<(typeof WINDOWS)[number], AttackWindowInput>> = {};
  for (const window of WINDOWS) {
    const numbers = stored.find((x) => x.window === window);
    const unifi = hasUnifi ? await loadUnifiTotals(db, row.organizationId, window) : null;
    if (!numbers && !unifi) continue;
    input[window] = {
      ...(numbers && row.connectionId
        ? {
            wazuh: {
              attackAlerts: numbers.attackAlerts,
              previousAttackAlerts: numbers.previousAttackAlerts,
              distinctSources: numbers.distinctSources,
              previousDistinctSources: numbers.previousDistinctSources,
              sources: await loadAttackSources(db, row.connectionId, window),
            },
          }
        : {}),
      ...(unifi
        ? {
            unifi: {
              events: unifi.alerts,
              blocked: unifi.blocked,
              previousEvents: unifi.previousAlerts,
              previousBlocked: unifi.previousBlocked,
              distinctSources: unifi.distinctSources,
              previousDistinctSources: unifi.previousDistinctSources,
              // The UniFi sources alone, so the two origins are never merged in what the model sees.
              sources: await loadUnifiSources(db, row.organizationId, window),
            },
          }
        : {}),
    };
  }
  const facts = buildAttackFacts(input);
  const language: AiLanguage = row.language === "de" ? "de" : "en";
  const messages = buildAttackMessages(facts, language);

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
      console.error(`attack summary ${row.id}: ${(error as Error)?.name ?? "error"}`);
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
export async function sweepAttackSummaries(): Promise<void> {
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
