/**
 * The fix proposals of the repositories a person sees (ADR 0014), computed from our own data: the open findings with a
 * fixed version and the manifests of each repository's last scan. Shared by the Fix proposals page, the overview's "Fix
 * first" and the finding detail, so all three name the same proposals.
 */
import { buildProposals, type FindingFact, type ManifestFact, type Proposal } from "@garnetops/core/fix-prs";
import type { ManifestKind } from "@garnetops/core/manifests";
import { repositoryVisibleTo, schema, type Viewer } from "@garnetops/db";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import { db } from "../db.ts";

/** Every proposal of the organisation (or one repository) from the open findings and the last manifests. */
export async function loadProposals(viewer: Viewer, repositoryId?: string) {
  const { organizationId } = viewer;
  const f = schema.finding;
  const repositories = await db
    .select({ id: schema.repository.id, name: schema.repository.name, url: schema.repository.url })
    .from(schema.repository)
    .where(
      and(
        repositoryVisibleTo(viewer),
        // Repositories set aside get no fix proposals in the organisation's list (ADR 0043).
        repositoryId ? eq(schema.repository.id, repositoryId) : isNull(schema.repository.inactiveAt),
      ),
    );
  if (repositories.length === 0)
    return { proposals: [], repositories: new Map<string, (typeof repositories)[number]>() };
  const ids = repositories.map((r) => r.id);
  const [findings, manifests] = await Promise.all([
    db
      .select({
        id: f.id,
        repositoryId: f.repositoryId,
        vulnerabilityId: f.vulnerabilityId,
        severity: f.severity,
        severityRank: f.severityRank,
        packageName: f.packageName,
        packageType: f.packageType,
        packageVersion: f.packageVersion,
        fixedIn: f.fixedIn,
        locations: f.locations,
      })
      .from(f)
      .where(
        and(
          eq(f.organizationId, organizationId),
          eq(f.state, "open"),
          inArray(f.repositoryId, ids),
          sql`jsonb_array_length(coalesce(${f.fixedIn}, '[]'::jsonb)) > 0`,
        ),
      ),
    db
      .select()
      .from(schema.repositoryManifest)
      .where(
        and(
          eq(schema.repositoryManifest.organizationId, organizationId),
          inArray(schema.repositoryManifest.repositoryId, ids),
        ),
      ),
  ]);
  const findingsOf = new Map<string, FindingFact[]>();
  for (const row of findings) {
    const list = findingsOf.get(row.repositoryId) ?? [];
    list.push({ ...row, fixedIn: row.fixedIn ?? [], locations: row.locations ?? [] });
    findingsOf.set(row.repositoryId, list);
  }
  const manifestsOf = new Map<string, ManifestFact[]>();
  for (const row of manifests) {
    const list = manifestsOf.get(row.repositoryId) ?? [];
    list.push({
      path: row.path,
      kind: row.kind as ManifestKind,
      blobSha: row.blobSha,
      dependencies: row.dependencies as never,
    });
    manifestsOf.set(row.repositoryId, list);
  }
  const proposals: Proposal[] = [];
  for (const repo of repositories) {
    proposals.push(
      ...buildProposals({
        repositoryId: repo.id,
        findings: findingsOf.get(repo.id) ?? [],
        manifests: manifestsOf.get(repo.id) ?? [],
      }),
    );
  }
  return { proposals, repositories: new Map(repositories.map((r) => [r.id, r])) };
}
