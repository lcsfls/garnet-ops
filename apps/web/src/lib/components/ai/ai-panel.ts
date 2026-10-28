import type { AiMessage, TriageResult } from "../../types.ts";

export const MAX_QUESTION = 2000;

/** An answer that is still being written. */
export const active = (m: AiMessage) => m.status === "pending" || m.status === "streaming";

/** "model-not-found" -> "modelNotFound": the key of its message. */
export const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

export const byteLength = (text: string) => new TextEncoder().encode(text).length;

export function triageText(result: TriageResult): string {
  return [result.summary, result.recommendation].filter(Boolean).join("\n\n");
}
