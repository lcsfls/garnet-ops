/**
 * Applies the organisation's ignore rules to its secrets (ADR 0049 addendum). Shared by the worker (after each scan of a
 * repository) and the API (when a rule is made or removed), so both decide the same way. A finding is set aside only when every
 * place it is known at matches a rule; anything else clears it, so removing a rule brings its findings back at once.
 */
import { ignoringRule, type SecretIgnoreRule } from "@garnetops/core/secrets";
import { and, eq, inArray, isNull, or } from "drizzle-orm";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";

/** The database or a transaction of it. */
type Executor = Pick<Database, "select" | "update">;

export async function secretIgnoreRules(
  db: Executor,
  organizationId: string,
  repositoryId?: string,
): Promise<SecretIgnoreRule[]> {
  const r = schema.secretIgnoreRule;
  return db
    .select({ id: r.id, repositoryId: r.repositoryId, pathPattern: r.pathPattern, ruleId: r.ruleId })
    .from(r)
    .where(
      and(
        eq(r.organizationId, organizationId),
        repositoryId ? or(isNull(r.repositoryId), eq(r.repositoryId, repositoryId)) : undefined,
      ),
    )
    .orderBy(r.createdAt, r.id);
}

/** Sets or clears `ignored_by` on the organisation's secrets (of one repository, if given). Returns how many changed. */
export async function applySecretIgnoreRules(
  db: Executor,
  organizationId: string,
  repositoryId?: string,
): Promise<number> {
  const s = schema.secretFinding;
  const rules = await secretIgnoreRules(db, organizationId, repositoryId);
  const rows = await db
    .select({
      id: s.id,
      repositoryId: s.repositoryId,
      ruleId: s.ruleId,
      ignoredBy: s.ignoredBy,
      treeLocations: s.treeLocations,
      treeLocationCount: s.treeLocationCount,
      historyLocations: s.historyLocations,
      historyLocationCount: s.historyLocationCount,
    })
    .from(s)
    .where(
      and(eq(s.organizationId, organizationId), repositoryId ? eq(s.repositoryId, repositoryId) : undefined),
    );
  const changes = new Map<string | null, string[]>();
  for (const row of rows) {
    // Only the first 50 places of each kind are kept; with more, the rest are unknown and nothing is set aside.
    const complete =
      row.treeLocations.length >= row.treeLocationCount &&
      row.historyLocations.length >= row.historyLocationCount;
    const rule = complete
      ? ignoringRule(rules, { ...row, places: [...row.treeLocations, ...row.historyLocations] })
      : null;
    const next = rule?.id ?? null;
    if (next === row.ignoredBy) continue;
    changes.set(next, [...(changes.get(next) ?? []), row.id]);
  }
  for (const [ignoredBy, ids] of changes) {
    await db.update(s).set({ ignoredBy, updatedAt: new Date() }).where(inArray(s.id, ids));
  }
  return [...changes.values()].reduce((sum, ids) => sum + ids.length, 0);
}
