/**
 * Secret scanning in the scan pipeline (ADR 0049): runs gitleaks (in the scanner service when there is one), turns what it
 * found into keyed fingerprints, and keeps one `secret_finding` per secret per repository. A scan never closes a finding; it only
 * records where the secret is now. Nothing here sees a secret's value: the report arrives with SHA-256 digests in its place.
 */
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { newId } from "@garnetops/core";
import type { GateSecret } from "@garnetops/core/gates";
import { secretFingerprint } from "@garnetops/core/secret-fingerprint";
import {
  matchingIgnoreRule,
  parseGitleaksReport,
  type SecretHit,
  type SecretSeverity,
} from "@garnetops/core/secrets";
import { applySecretIgnoreRules, schema, secretIgnoreRules } from "@garnetops/db";
import type { SecretLocation } from "@garnetops/db/schema";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { runGitleaks, type SecretReports } from "./gitleaks-run.ts";
import { requestSecrets, ScannerRequestError } from "./scanner-client.ts";
import { openSecretText, sealSecret } from "./vault-secrets.ts";
import type { Tx } from "./vulnerability-store.ts";

const s = schema.secretFinding;

export interface SecretScanResult {
  /** "done": checked; "skipped": no gitleaks here or in the scanner service; "failed": gitleaks alone failed. */
  state: "done" | "skipped" | "failed";
  tree: SecretHit[];
  /** Hits in the history, when the history was checked. */
  history: SecretHit[] | null;
}

const RANK: Record<SecretSeverity, number> = { critical: 5, high: 4, medium: 3, low: 2 };
/** Places kept per finding and kind; the rest are counted. */
const MAX_LOCATIONS = 50;

/**
 * The organisation's fingerprint key: 32 random bytes, sealed in the vault, created on first use. An advisory lock keeps two
 * scans of the same organisation from creating two keys (their fingerprints would never match).
 */
async function fingerprintKey(organizationId: string): Promise<Buffer> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtext(${`secret-fingerprint-key:${organizationId}`}))`,
    );
    const [row] = await tx
      .select({ id: schema.secret.id })
      .from(schema.secret)
      .where(
        and(
          eq(schema.secret.organizationId, organizationId),
          eq(schema.secret.purpose, "secret-fingerprint-key"),
        ),
      )
      .orderBy(schema.secret.createdAt)
      .limit(1);
    if (row) {
      const text = await openSecretText(row.id, organizationId, "secret-fingerprint-key");
      if (!text) throw new Error("secret fingerprint key cannot be opened");
      return Buffer.from(text, "base64");
    }
    const key = randomBytes(32);
    await sealSecret(tx, organizationId, "secret-fingerprint-key", key.toString("base64"));
    return key;
  });
}

/**
 * Runs gitleaks on the clone and reads its findings. Never throws: a missing binary, an older scanner service or a failure of
 * gitleaks leaves the scan's dependency results alone and is recorded as "skipped" or "failed".
 */
export async function runSecretScan(
  src: string,
  out: string,
  organizationId: string,
  history: boolean,
): Promise<SecretScanResult> {
  const none = (state: "skipped" | "failed"): SecretScanResult => ({ state, tree: [], history: null });
  let file: string;
  try {
    const socket = env.GARNETOPS_SCANNER_SOCKET;
    if (socket) {
      file = join(out, "secrets.json");
      const dir = relative(env.GARNETOPS_SCANNER_WORK_DIR as string, src)
        .split(sep)
        .join("/");
      try {
        await requestSecrets(socket, dir, history, file);
      } catch (error) {
        // A scanner service from before secret scanning, or one without gitleaks.
        if (error instanceof ScannerRequestError && error.code === "not_found") return none("skipped");
        throw error;
      }
    } else if (env.GARNETOPS_GITLEAKS_BIN) {
      file = await runGitleaks(env.GARNETOPS_GITLEAKS_BIN, src, out, { history });
    } else {
      return none("skipped");
    }
    const reports = JSON.parse(await readFile(file, "utf8")) as SecretReports;
    const key = await fingerprintKey(organizationId);
    const fingerprint = (ruleId: string, digest: string, path: string) =>
      secretFingerprint(key, ruleId, digest, path);
    const tree = parseGitleaksReport(JSON.stringify(reports.tree ?? []), { root: src, fingerprint }).hits;
    const past =
      history && Array.isArray(reports.history)
        ? parseGitleaksReport(JSON.stringify(reports.history), { root: src, fingerprint }).hits
        : null;
    key.fill(0);
    return { state: "done", tree, history: past };
  } catch (error) {
    // The message names the step, never a value: the report holds digests only and is not printed.
    console.error(`secret scan: ${(error as Error).name}: ${(error as Error).message}`);
    return none("failed");
  }
}

/** The secrets in the checked files that nobody closed: what the gate rule `secret-found` counts. */
export async function gateSecrets(
  tx: Tx,
  repo: { id: string; organizationId: string },
  result: SecretScanResult,
): Promise<GateSecret[] | undefined> {
  if (result.state !== "done") return undefined;
  const { id: repositoryId, organizationId } = repo;
  const fingerprints = [...new Set(result.tree.map((h) => h.fingerprint))];
  if (fingerprints.length === 0) return [];
  const closed = await tx
    .select({ fingerprint: s.fingerprint })
    .from(s)
    .where(
      and(eq(s.repositoryId, repositoryId), inArray(s.fingerprint, fingerprints), sql`${s.state} <> 'open'`),
    );
  const shut = new Set(closed.map((c) => c.fingerprint));
  const rules = await secretIgnoreRules(tx, organizationId, repositoryId);
  const worst = new Map<string, SecretSeverity>();
  for (const hit of result.tree) {
    if (shut.has(hit.fingerprint)) continue;
    // A place an ignore rule covers does not count; the same value anywhere else still does.
    if (matchingIgnoreRule(rules, { repositoryId, ruleId: hit.ruleId, path: hit.path })) continue;
    const before = worst.get(hit.fingerprint);
    if (!before || RANK[hit.severity] > RANK[before]) worst.set(hit.fingerprint, hit.severity);
  }
  return [...worst.values()].map((severity) => ({ severity }));
}

interface Group {
  ruleId: string;
  severity: SecretSeverity;
  tree: SecretLocation[];
  history: SecretLocation[];
}

function group(result: SecretScanResult): Map<string, Group> {
  const groups = new Map<string, Group>();
  const take = (hit: SecretHit, kind: "tree" | "history") => {
    let g = groups.get(hit.fingerprint);
    if (!g) {
      g = { ruleId: hit.ruleId, severity: hit.severity, tree: [], history: [] };
      groups.set(hit.fingerprint, g);
    }
    if (RANK[hit.severity] > RANK[g.severity]) {
      g.severity = hit.severity;
      g.ruleId = hit.ruleId;
    }
    g[kind].push(
      kind === "tree"
        ? { path: hit.path, line: hit.line }
        : { path: hit.path, line: hit.line, commit: hit.commit ?? undefined, committedAt: hit.committedAt },
    );
  };
  for (const hit of result.tree) take(hit, "tree");
  for (const hit of result.history ?? []) take(hit, "history");
  return groups;
}

/**
 * Records a branch scan's secrets: new ones open, known ones moved to where they are now. A secret no longer in the files stays
 * as it was (open, revoked or dismissed) with `inTree` false: removing a file does not make a leaked value safe. Returns the open
 * secrets by severity found in this scan and how many were new.
 */
export async function persistSecrets(
  tx: Tx,
  scanId: string,
  repo: { id: string; organizationId: string },
  result: SecretScanResult,
  now: Date,
): Promise<{ counts: Record<string, number>; newSecrets: number } | null> {
  if (result.state !== "done") return null;
  const groups = group(result);
  const existing = await tx
    .select({ id: s.id, fingerprint: s.fingerprint, state: s.state, severityRank: s.severityRank })
    .from(s)
    .where(eq(s.repositoryId, repo.id));
  const byFingerprint = new Map(existing.map((e) => [e.fingerprint, e]));
  const historyChecked = result.history !== null;

  for (const [fingerprint, g] of groups) {
    const known = byFingerprint.get(fingerprint);
    const places = {
      inTree: g.tree.length > 0,
      treeLocations: g.tree.slice(0, MAX_LOCATIONS),
      treeLocationCount: g.tree.length,
      ...(historyChecked
        ? { historyLocations: g.history.slice(0, MAX_LOCATIONS), historyLocationCount: g.history.length }
        : {}),
      lastSeenScanId: scanId,
      lastSeenAt: now,
      updatedAt: now,
    };
    if (known) {
      await tx
        .update(s)
        .set({
          ...places,
          // A worse rule for the same value (a newer gitleaks) raises it; nothing lowers it.
          ...(RANK[g.severity] > known.severityRank
            ? { severity: g.severity, severityRank: RANK[g.severity], ruleId: g.ruleId }
            : {}),
        })
        .where(eq(s.id, known.id));
      continue;
    }
    await tx.insert(s).values({
      id: newId("sec"),
      organizationId: repo.organizationId,
      repositoryId: repo.id,
      ruleId: g.ruleId,
      severity: g.severity,
      severityRank: RANK[g.severity],
      fingerprint,
      state: "open",
      historyLocations: [],
      historyLocationCount: 0,
      ...places,
      firstSeenScanId: scanId,
      firstSeenAt: now,
    });
  }

  // Secrets this scan did not see in the files: they stay, with no place in the files; a history check that did not find them
  // either (the history was rewritten) empties their history places too.
  const gone = existing.filter((e) => !groups.has(e.fingerprint)).map((e) => e.id);
  if (gone.length > 0) {
    await tx
      .update(s)
      .set({
        inTree: false,
        treeLocations: [],
        treeLocationCount: 0,
        ...(historyChecked ? { historyLocations: [], historyLocationCount: 0 } : {}),
        updatedAt: now,
      })
      .where(inArray(s.id, gone));
  }
  if (historyChecked) {
    await tx
      .update(schema.repository)
      .set({ secretHistoryCheckedAt: now })
      .where(eq(schema.repository.id, repo.id));
  }
  // The organisation's ignore rules (ADR 0049 addendum), then what this scan saw that nobody closed or set aside.
  await applySecretIgnoreRules(tx, repo.organizationId, repo.id);
  const seen = await tx
    .select({ severity: s.severity, firstSeenScanId: s.firstSeenScanId })
    .from(s)
    .where(
      and(
        eq(s.repositoryId, repo.id),
        eq(s.lastSeenScanId, scanId),
        eq(s.state, "open"),
        isNull(s.ignoredBy),
      ),
    );
  const counts: Record<string, number> = {};
  for (const row of seen) counts[row.severity] = (counts[row.severity] ?? 0) + 1;
  return { counts, newSecrets: seen.filter((row) => row.firstSeenScanId === scanId).length };
}
