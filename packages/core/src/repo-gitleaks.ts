/**
 * The repository's own gitleaks configuration, as an opt-in (ADR 0049, addendum 2026-11-12). Pure: the worker reads the files
 * from its clone and passes their text here. The repository's configuration is used only on top of GarnetOps' own: its
 * `[extend]` table is replaced, so it cannot pull in another file, and a run with it can only add findings or set them aside
 * visibly, never drop them.
 */
import type { SecretHit } from "./secrets.ts";

/** Where gitleaks keeps a repository's configuration, in the order they are looked for. */
export const REPO_GITLEAKS_CONFIG_FILES = [".gitleaks.toml", "gitleaks.toml"] as const;
export const REPO_GITLEAKS_IGNORE_FILE = ".gitleaksignore";
/** Larger files are refused. */
export const REPO_GITLEAKS_MAX_BYTES = 64 * 1024;

export type RepoConfigProblem = "tooLarge" | "notText" | "extendForm" | "reservedRuleId" | "failed";

/**
 * The repository's configuration, ready to be extended by GarnetOps' own: the `[extend]` table becomes `useDefault = true` with
 * the repository's `disabledRules` (if any). Refused when it is too large, not text, sets `extend` in another form (inline or
 * dotted keys) or names a rule like one of GarnetOps' own.
 */
export function cleanRepoGitleaksConfig(text: string): { config: string } | { problem: RepoConfigProblem } {
  if (new TextEncoder().encode(text).length > REPO_GITLEAKS_MAX_BYTES) return { problem: "tooLarge" };
  if (text.includes("\u0000")) return { problem: "notText" };
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  if (lines.some((l) => /^\s*["']?extend["']?\s*[.=]/.test(l))) return { problem: "extendForm" };
  if (lines.some((l) => /^\s*id\s*=\s*["']garnetops-/i.test(l))) return { problem: "reservedRuleId" };

  const header = (l: string) => /^\s*\[/.test(l);
  const isExtend = (l: string) => /^\s*\[\s*["']?extend["']?\s*\]\s*(?:#.*)?$/.test(l);
  const kept: string[] = [];
  let disabled: string | null = null;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] as string;
    if (!isExtend(line)) {
      kept.push(line);
      continue;
    }
    // The table's keys up to the next header; only `disabledRules` survives, as written (it may span lines).
    let j = i + 1;
    while (j < lines.length && !header(lines[j] as string)) {
      const key = /^\s*disabledRules\s*=/.exec(lines[j] as string);
      if (key) {
        let value = (lines[j] as string).trim();
        let depth = bracketDepth(value);
        while (depth > 0 && j + 1 < lines.length) {
          j += 1;
          value += ` ${(lines[j] as string).trim()}`;
          depth = bracketDepth(value);
        }
        disabled = value;
      }
      j += 1;
    }
    i = j - 1;
  }
  const extend = ["[extend]", "useDefault = true", ...(disabled ? [disabled] : [])];
  return { config: `${kept.join("\n").trimEnd()}\n\n${extend.join("\n")}\n` };
}

/** Open minus closed brackets outside quoted strings. */
function bracketDepth(text: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "#") break;
    else if (ch === "[") depth += 1;
    else if (ch === "]") depth -= 1;
  }
  return depth;
}

/** One place of a value: the same in both runs whatever rule found it (a value's fingerprint does not depend on the rule). */
const placeKey = (h: SecretHit) =>
  `${h.fingerprint}\u0000${h.path}\u0000${h.line ?? ""}\u0000${h.commit ?? ""}`;

/**
 * Compares the strict run with the repository run (ADR 0049 addendum). Places only the strict run has are set aside by the
 * repository; places only the repository run has (its own rules) are added. Returns the hits to store and the keys of the places
 * set aside.
 */
export function mergeRepoRun(
  strict: SecretHit[],
  repo: SecretHit[],
): { hits: SecretHit[]; setAside: Set<string>; added: number } {
  const inRepo = new Set(repo.map(placeKey));
  const inStrict = new Set(strict.map(placeKey));
  const setAside = new Set(strict.filter((h) => !inRepo.has(placeKey(h))).map(placeKey));
  const extra = repo.filter((h) => !inStrict.has(placeKey(h)));
  // Several repository rules can match one place: one is enough.
  const seen = new Set<string>();
  const added = extra.filter((h) => {
    const key = placeKey(h);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { hits: [...strict, ...added], setAside, added: added.length };
}

/** Whether a hit's place was set aside by the repository. */
export const isSetAsideByRepository = (setAside: Set<string>, hit: SecretHit) => setAside.has(placeKey(hit));
