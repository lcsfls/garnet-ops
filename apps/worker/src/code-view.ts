/**
 * The code viewer's job (ADR 0048): a person asked for the code of a finding, the API queued a `code_request`. The worker checks
 * the request again (organisation, the person's role, the repository's visibility), clones the repository with its read
 * credential, at the commit of the scan that last saw the finding (or the branch head when the forge will not hand out that
 * commit), reads the declaring files and searches for usages, writes the excerpts to the request and removes the clone.
 * Nothing in the repository is executed.
 */
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { type CodeView, ecosystemOf } from "@garnetops/core/code-view";
import { isCommitSha } from "@garnetops/core/gates";
import { repositoryVisibleTo, schema } from "@garnetops/db";
import { and, eq, lt, sql } from "drizzle-orm";
import { readDeclarations, searchUsages } from "./code-read.ts";
import { db } from "./db.ts";
import { env } from "./env.ts";
import { cloneRepository, RepoCloneError } from "./repo-clone.ts";

export const CODE_QUEUE = "code.fetch";
/** Requests older than this are deleted in any state. */
const KEEP = sql`now() - interval '10 minutes'`;
const r = schema.codeRequest;

/** The same name as the manifest scanners write it; Python names compare normalised (PEP 503). */
function sameName(a: string, b: string, ecosystem: string): boolean {
  if (ecosystem !== "python") return a === b;
  const norm = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");
  return norm(a) === norm(b);
}

async function fail(id: string, message: string): Promise<void> {
  await db.update(r).set({ state: "failed", error: message }).where(eq(r.id, id));
}

export async function runCodeRequest(id: string): Promise<void> {
  const [request] = await db
    .update(r)
    .set({ state: "running" })
    .where(and(eq(r.id, id), eq(r.state, "queued"), sql`${r.createdAt} > ${KEEP}`))
    .returning();
  if (!request) return;

  // The person, again: still a member or above of the organisation, and the repository still visible to them.
  const viewer = { organizationId: request.organizationId, userId: request.requestedBy };
  const [membership] = await db
    .select({ role: schema.membership.role })
    .from(schema.membership)
    .where(
      and(
        eq(schema.membership.organizationId, request.organizationId),
        eq(schema.membership.userId, request.requestedBy),
      ),
    )
    .limit(1);
  const [repo] = await db
    .select()
    .from(schema.repository)
    .where(and(eq(schema.repository.id, request.repositoryId), repositoryVisibleTo(viewer)))
    .limit(1);
  const [finding] = await db
    .select()
    .from(schema.finding)
    .where(
      and(
        eq(schema.finding.id, request.findingId),
        eq(schema.finding.organizationId, request.organizationId),
        eq(schema.finding.repositoryId, request.repositoryId),
      ),
    )
    .limit(1);
  if (!membership || membership.role === "viewer" || !repo || !finding) {
    return fail(id, "The finding or its repository is no longer available to you.");
  }
  const [scan] = await db
    .select({ commitSha: schema.scan.commitSha })
    .from(schema.scan)
    .where(eq(schema.scan.id, finding.lastSeenScanId))
    .limit(1);
  const scanCommit = scan?.commitSha && isCommitSha(scan.commitSha) ? scan.commitSha : null;

  const root = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "code-"));
  try {
    const home = join(root, "home");
    await mkdir(home);
    // The commit the scan saw; a forge that will not hand out a single commit gets the branch head instead.
    let src = join(root, "at-commit");
    let cloned = await cloneRepository(repo, {
      dir: src,
      home,
      sshDir: join(root, "ssh"),
      ref: scanCommit,
    }).catch((error: unknown) => {
      if (scanCommit && error instanceof RepoCloneError) return null;
      throw error;
    });
    if (!cloned) {
      src = join(root, "head");
      cloned = await cloneRepository(repo, { dir: src, home, sshDir: join(root, "ssh-head") });
    }

    const ecosystem = ecosystemOf(finding.packageType);
    const manifests = await db
      .select({ path: schema.repositoryManifest.path, dependencies: schema.repositoryManifest.dependencies })
      .from(schema.repositoryManifest)
      .where(eq(schema.repositoryManifest.repositoryId, repo.id));
    const declaring = manifests
      .filter((m) => m.dependencies.some((d) => sameName(d.name, finding.packageName, ecosystem)))
      .map((m) => ({ path: m.path, role: "manifest" as const }));
    const lockfiles = (finding.locations ?? []).map((path) => ({ path, role: "lockfile" as const }));
    const declarations = await readDeclarations(src, finding.packageName, [...declaring, ...lockfiles]);
    const usages = await searchUsages(src, ecosystem, finding.packageName);
    const view: CodeView = {
      commit: cloned.commitSha,
      branch: repo.branch ?? cloned.branch,
      scanCommit,
      ecosystem,
      declarations,
      ...usages,
    };
    await db
      .update(r)
      .set({ state: "done", result: view as unknown as Record<string, unknown> })
      .where(eq(r.id, id));
  } catch (error) {
    if (error instanceof RepoCloneError) await fail(id, error.message);
    else {
      console.error(`code request ${id}:`, (error as Error).name, (error as Error).message);
      await fail(id, "The code could not be read. Try again later.");
    }
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => {});
  }
}

/** Requests are short-lived: whatever was not handed over within 10 minutes goes, in any state. */
export async function sweepCodeRequests(): Promise<void> {
  await db.delete(r).where(lt(r.createdAt, KEEP));
}
