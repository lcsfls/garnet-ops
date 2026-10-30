/**
 * Fix pull requests in the worker (ADR 0014). The worker is the only process that opens the
 * write token. For one request it reads the manifest through the forge's contents API, edits
 * the text with the pure functions in packages/core, creates a branch and commits the one
 * changed file to it, and opens a pull request with a fixed text. Nothing is cloned, nothing
 * from the repository is executed, and nothing is ever merged, approved or pushed to the
 * default branch.
 *
 * A request made through a person's own connected account (ADR 0039) uses that connection's
 * token instead, and only while the connection still belongs to the person who asked, is on the
 * repository's forge and has pull requests switched on. It never falls back to the write token.
 */
import {
  advisoryUrl,
  branchName,
  connectionCoversRepository,
  connectionWriteProblem,
  type FixPrReason,
  type FixPrVulnerability,
  parseRepoLocation,
  pullRequestUrl,
  renderPullRequest,
} from "@garnetops/core/fix-prs";
import { isSafeGitRef } from "@garnetops/core/gates";
import { editManifest, isSafePackageName, type ManifestKind, safeRepoPath } from "@garnetops/core/manifests";
import { open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNull, lt, or, sql } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import {
  branchHead,
  createBranch,
  deleteBranch,
  ForgeError,
  type ForgeTarget,
  openPullRequest,
  pullRequestState,
  readFile,
  repoInfo,
  writeFile,
} from "./forge.ts";
import { accountOf } from "./forge-connection.ts";
import { tellAboutFixPr } from "./user-notify.ts";

export const FIX_PR_QUEUE = "fix-pr.create";
export const FIX_PR_CHECK_QUEUE = "fix-pr.check";
export const FIX_PR_REFRESH_QUEUE = "fix-pr.refresh";
export const FIX_PR_TICK_QUEUE = "fix-pr.tick";

/** Pull requests are looked at again after this long without a check. */
const REFRESH_AFTER_MS = 10 * 60_000;
const REFRESH_BATCH = 200;

type AccessRow = typeof schema.repositoryWriteAccess.$inferSelect;
type RepoRow = typeof schema.repository.$inferSelect;
type FixPrRow = typeof schema.fixPr.$inferSelect;

/** The reason a forge failure is stored with. */
const reasonOf = (error: unknown): FixPrReason => (error instanceof ForgeError ? error.code : "unexpected");

/** Opens the write token of a repository and builds the forge target. The token lives only in the returned object. */
async function openTarget(
  repo: RepoRow,
  access: AccessRow,
): Promise<{ target: ForgeTarget; webBase: string }> {
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, access.secretId),
        eq(schema.secret.organizationId, repo.organizationId),
        eq(schema.secret.purpose, "forge-write-token"),
      ),
    )
    .limit(1);
  if (!secret) throw new ForgeError("token-rejected");
  const location = parseRepoLocation(repo.url);
  if (!location) throw new ForgeError("not-found");
  let token: string;
  try {
    const plain = open(
      secret.sealed,
      { organizationId: secret.organizationId, recordId: secret.id, purpose: "forge-write-token" },
      vaultPrivateKey,
    );
    token = plain.toString("utf8");
    plain.fill(0);
  } catch {
    // Sealed for another record, organisation or purpose, or not sealed at all: the credential is unusable.
    throw new ForgeError("token-rejected");
  }
  return {
    target: {
      kind: access.forgeKind,
      apiBaseUrl: access.apiBaseUrl,
      token,
      owner: location.owner,
      repo: location.repo,
    },
    webBase: location.webBase,
  };
}

/* -------------------------------------------------------------------------- */
/* The requester's own connection (ADR 0039)                                   */
/* -------------------------------------------------------------------------- */

type ConnectionRow = typeof schema.forgeConnection.$inferSelect;
type Opened = { target: ForgeTarget; webBase: string };

/**
 * The connection a request names, only while it still belongs to the person who made the request (in the same
 * organisation) and is on the repository's forge. A connection's token is never used for anybody but its owner.
 */
async function requesterConnection(row: FixPrRow, repo: RepoRow): Promise<ConnectionRow | null> {
  if (!row.connectionId || !row.requestedBy) return null;
  const [connection] = await db
    .select()
    .from(schema.forgeConnection)
    .where(
      and(
        eq(schema.forgeConnection.id, row.connectionId),
        eq(schema.forgeConnection.organizationId, row.organizationId),
        eq(schema.forgeConnection.userId, row.requestedBy),
      ),
    )
    .limit(1);
  if (!connection || !connectionCoversRepository(connection.webBaseUrl, repo.url)) return null;
  return connection;
}

/** Opens a connection's token (renewed first if it is about to expire) for one repository on its forge. */
async function openConnectionTarget(repo: RepoRow, connection: ConnectionRow): Promise<Opened> {
  const location = parseRepoLocation(repo.url);
  if (!location) throw new ForgeError("not-found");
  const account = await accountOf(connection);
  return {
    target: {
      kind: account.kind,
      apiBaseUrl: account.apiBaseUrl,
      token: account.token,
      owner: location.owner,
      repo: location.repo,
    },
    webBase: location.webBase,
  };
}

/**
 * The credential a request is carried out with: the repository's write token, or (`via` "connection") the requester's
 * own connection. "write" needs the connection's opt-in and, for a Gitea/Forgejo sign-in, the write scope; "read"
 * (the status refresh of the requester's own pull request) needs only the connection itself. A request made through a
 * connection never falls back to the repository's token.
 */
async function credentialFor(
  row: FixPrRow,
  purpose: "write" | "read",
): Promise<{ repo: RepoRow; open: () => Promise<Opened> } | { problem: FixPrReason }> {
  if (row.via === "connection") {
    const [repo] = await db
      .select()
      .from(schema.repository)
      .where(eq(schema.repository.id, row.repositoryId))
      .limit(1);
    if (!repo || repo.organizationId !== row.organizationId) return { problem: "repository-gone" };
    const connection = await requesterConnection(row, repo);
    if (!connection) return { problem: "connection-missing" };
    if (purpose === "write") {
      const problem = connectionWriteProblem(connection);
      if (problem) return { problem };
    }
    return { repo, open: () => openConnectionTarget(repo, connection) };
  }
  const access = await loadAccess(row.repositoryId);
  if (!access || access.access.organizationId !== row.organizationId) {
    return { problem: access ? "repository-gone" : "write-access-missing" };
  }
  return { repo: access.repo, open: () => openTarget(access.repo, access.access) };
}

async function loadAccess(repositoryId: string) {
  const [row] = await db
    .select({ repo: schema.repository, access: schema.repositoryWriteAccess })
    .from(schema.repository)
    .innerJoin(
      schema.repositoryWriteAccess,
      eq(schema.repositoryWriteAccess.repositoryId, schema.repository.id),
    )
    .where(eq(schema.repository.id, repositoryId))
    .limit(1);
  return row ?? null;
}

/* -------------------------------------------------------------------------- */
/* Checking the token                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Asks the forge whether the token reaches the repository and may push, and whether it is
 * broader than one repository. Writes nothing to the forge. The result is stored with the
 * write access and shown on the repository page.
 */
export async function checkWriteAccess(repositoryId: string): Promise<void> {
  const row = await loadAccess(repositoryId);
  if (!row) return;
  let status: "ok" | "failed" = "ok";
  let reason: string | null = null;
  let warning: string | null = null;
  try {
    const { target } = await openTarget(row.repo, row.access);
    const info = await repoInfo(target);
    if (info.archived || info.canPush === false) {
      status = "failed";
      reason = "no-push-access";
    }
    if (info.broadToken) warning = "broad-token";
  } catch (error) {
    status = "failed";
    reason = reasonOf(error);
    if (!(error instanceof ForgeError)) console.error(`fix-pr check ${repositoryId}:`, error);
  }
  await db
    .update(schema.repositoryWriteAccess)
    .set({ status, statusReason: reason, warning, checkedAt: new Date() })
    .where(
      and(
        eq(schema.repositoryWriteAccess.repositoryId, repositoryId),
        // A token replaced while the check ran is checked again by its own job.
        eq(schema.repositoryWriteAccess.secretId, row.access.secretId),
      ),
    );
}

/* -------------------------------------------------------------------------- */
/* Creating a pull request                                                     */
/* -------------------------------------------------------------------------- */

async function audit(row: FixPrRow, action: string, data: Record<string, unknown>) {
  await db.insert(schema.auditLog).values({
    organizationId: row.organizationId,
    actorUserId: row.requestedBy,
    action,
    targetType: "fix_pr",
    targetId: row.id,
    data: { repositoryId: row.repositoryId, package: row.packageName, ...data },
  });
}

async function fail(row: FixPrRow, reason: string) {
  await db
    .update(schema.fixPr)
    .set({ state: "failed", reason, updatedAt: new Date() })
    .where(eq(schema.fixPr.id, row.id));
  await audit(row, "fix_pr.failed", { reason, from: row.fromVersion, to: row.toVersion });
  await tellAboutFixPr(row, "fixPrFailed");
}

/**
 * Carries out one request: branch, one file changed, pull request. Failures are stored as a
 * short code on the row; nothing is thrown to the queue, because a retry could open a second
 * pull request.
 */
export async function runFixPr(fixPrId: string): Promise<void> {
  const [row] = await db
    .update(schema.fixPr)
    .set({ state: "running", updatedAt: new Date() })
    .where(and(eq(schema.fixPr.id, fixPrId), eq(schema.fixPr.state, "queued")))
    .returning();
  if (!row) return; // taken, finished or cancelled

  const credential = await credentialFor(row, "write");
  if ("problem" in credential) return fail(row, credential.problem);
  const { repo } = credential;
  const kind = row.ecosystem as ManifestKind;
  // The row was validated when it was created; values that reach the forge are checked again here.
  if (
    !isSafePackageName(row.packageName) ||
    !safeRepoPath(row.manifestPath) ||
    !/^[0-9A-Za-z.!+_-]{1,100}$/.test(row.toVersion) ||
    !/^[0-9A-Za-z.!+_-]{1,100}$/.test(row.fromVersion) ||
    !["npm", "pypi", "composer", "go", "cargo"].includes(row.ecosystem)
  ) {
    return fail(row, "rejected");
  }
  let created: { branch: string; target: ForgeTarget } | null = null;
  let opened: Opened | null = null;
  try {
    opened = await credential.open();
    const { target, webBase } = opened;
    // The forge decides whether this token may push here: a connection's token as much as a write token.
    const info = await repoInfo(target);
    if (info.archived || info.canPush === false) return fail(row, "no-push-access");
    const base = repo.branch ?? info.defaultBranch;
    if (!isSafeGitRef(base)) return fail(row, "rejected");
    const head = await branchHead(target, base);

    const file = await readFile(target, row.manifestPath, base).catch((error: unknown) => {
      // The scan saw this file; it is gone (or moved) on the branch now.
      if (error instanceof ForgeError && error.code === "not-found") return null;
      throw error;
    });
    if (!file) return fail(row, "manifest-missing");
    // The file the scan analysed, and no other: a changed manifest needs a new scan first.
    if (file.sha !== row.expectedBlobSha) return fail(row, "manifest-changed");
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(file.bytes);
    } catch {
      return fail(row, "edit-invalid");
    }
    const edit = editManifest(kind, text, { name: row.packageName, target: row.toVersion });
    if (!edit.ok) return fail(row, `edit-${edit.reason}`);

    const vulnerabilities = await vulnerabilityFacts(row.vulnerabilityIds);
    const [requester] = row.requestedBy
      ? await db
          .select({ name: schema.user.name })
          .from(schema.user)
          .where(eq(schema.user.id, row.requestedBy))
          .limit(1)
      : [];
    const text_ = renderPullRequest({
      packageName: row.packageName,
      ecosystem: kind,
      fromVersion: row.fromVersion,
      toVersion: row.toVersion,
      majorUpgrade: row.majorUpgrade,
      manifestPath: row.manifestPath,
      vulnerabilities,
      requestedBy: requester?.name ?? "a GarnetOps user",
    });

    const branch = branchName(row.packageName, row.toVersion);
    if (!isSafeGitRef(branch)) return fail(row, "rejected");
    try {
      await createBranch(target, branch, { branch: base, sha: head });
    } catch (error) {
      // Our name is already taken: an earlier attempt left it, or a person made it. Never reuse it.
      if (error instanceof ForgeError && (error.code === "conflict" || error.code === "rejected")) {
        return fail(row, "branch-exists");
      }
      throw error;
    }
    created = { branch, target };
    await writeFile(target, {
      path: row.manifestPath,
      branch,
      sha: file.sha,
      bytes: Buffer.from(edit.text, "utf8"),
      message: text_.commitMessage,
    }).catch((error: unknown) => {
      // The forge says the file is not the one we read any more.
      if (error instanceof ForgeError && (error.code === "conflict" || error.code === "rejected")) {
        throw new ForgeError("conflict", error.status);
      }
      throw error;
    });
    const number = await openPullRequest(target, {
      title: text_.title,
      body: text_.body,
      head: branch,
      base,
    });
    created = null; // the pull request keeps the branch
    const url = pullRequestUrl(target.kind, webBase, number);
    await db
      .update(schema.fixPr)
      .set({
        state: "open",
        reason: null,
        branch,
        baseBranch: base,
        prNumber: number,
        prUrl: url,
        openedAt: new Date(),
        lastCheckedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(schema.fixPr.id, row.id));
    await audit(row, "fix_pr.opened", {
      forge: target.kind,
      number,
      from: row.fromVersion,
      to: row.toVersion,
      branch,
      via: row.via,
    });
  } catch (error) {
    if (created) {
      // Leave no half-finished branch behind; a failure to clean up is not worth more than a log line.
      await deleteBranch(created.target, created.branch).catch(() => {});
    }
    if (!(error instanceof ForgeError)) console.error(`fix-pr ${fixPrId}:`, error);
    await fail(
      row,
      error instanceof ForgeError && error.code === "conflict" ? "manifest-changed" : reasonOf(error),
    );
  } finally {
    // The token lives only in memory, and only as long as this request.
    if (opened) opened.target.token = "";
  }
}

async function vulnerabilityFacts(ids: string[]): Promise<FixPrVulnerability[]> {
  if (ids.length === 0) return [];
  const rows = await db
    .select({
      id: schema.vulnerability.id,
      severity: schema.vulnerability.severity,
      urls: schema.vulnerability.urls,
    })
    .from(schema.vulnerability)
    .where(inArray(schema.vulnerability.id, ids.slice(0, 200)));
  const byId = new Map(rows.map((r) => [r.id, r]));
  return ids.map((id) => {
    const v = byId.get(id);
    return { id, severity: v?.severity ?? "unknown", url: advisoryUrl(id, v?.urls ?? []) };
  });
}

/* -------------------------------------------------------------------------- */
/* Status refresh                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Looks at the open pull requests on the forge and records merged and closed ones. A repository
 * whose token no longer works keeps its pull requests as they were, with the reason noted.
 */
export async function refreshFixPrs(
  options: { organizationId?: string; repositoryId?: string; force?: boolean } = {},
): Promise<number> {
  await sweepStale();
  const stale = new Date(Date.now() - REFRESH_AFTER_MS);
  const rows = await db
    .select()
    .from(schema.fixPr)
    .where(
      and(
        eq(schema.fixPr.state, "open"),
        options.organizationId ? eq(schema.fixPr.organizationId, options.organizationId) : undefined,
        options.repositoryId ? eq(schema.fixPr.repositoryId, options.repositoryId) : undefined,
        options.force
          ? undefined
          : or(isNull(schema.fixPr.lastCheckedAt), lt(schema.fixPr.lastCheckedAt, stale)),
      ),
    )
    .orderBy(sql`${schema.fixPr.lastCheckedAt} asc nulls first`)
    .limit(REFRESH_BATCH);
  // One credential per group: the repository's write token, or one person's connection (ADR 0039).
  const groups = new Map<string, FixPrRow[]>();
  for (const row of rows) {
    const key =
      row.via === "connection"
        ? `${row.repositoryId}|connection|${row.connectionId ?? ""}|${row.requestedBy ?? ""}`
        : `${row.repositoryId}|repository`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  const note = (prs: FixPrRow[], reason: string) =>
    db
      .update(schema.fixPr)
      .set({ reason, lastCheckedAt: new Date() })
      .where(
        inArray(
          schema.fixPr.id,
          prs.map((p) => p.id),
        ),
      );
  let checked = 0;
  for (const prs of groups.values()) {
    const credential = await credentialFor(prs[0] as FixPrRow, "read");
    if ("problem" in credential) {
      await note(prs, credential.problem);
      continue;
    }
    let opened: Opened;
    try {
      opened = await credential.open();
    } catch (error) {
      await note(prs, reasonOf(error));
      continue;
    }
    for (const pr of prs) {
      if (pr.prNumber === null) continue;
      try {
        const state = await pullRequestState(opened.target, pr.prNumber);
        const changed = await db
          .update(schema.fixPr)
          .set({
            state,
            reason: null,
            lastCheckedAt: new Date(),
            updatedAt: new Date(),
            ...(state === "open" ? {} : { closedAt: new Date() }),
          })
          .where(and(eq(schema.fixPr.id, pr.id), eq(schema.fixPr.state, "open")))
          .returning({ id: schema.fixPr.id });
        checked++;
        if (state !== "open") await audit(pr, `fix_pr.${state}`, { number: pr.prNumber });
        // Once: only the refresh that changed the row tells the people (ADR 0019).
        if (state === "merged" && changed.length > 0) await tellAboutFixPr(pr, "fixPrMerged");
      } catch (error) {
        await db
          .update(schema.fixPr)
          .set({ reason: reasonOf(error), lastCheckedAt: new Date() })
          .where(eq(schema.fixPr.id, pr.id));
        // A rate limit or a broken token will not get better within this batch.
        if (
          error instanceof ForgeError &&
          ["rate-limited", "token-rejected", "address-refused"].includes(error.code)
        )
          break;
      }
    }
    opened.target.token = "";
  }
  return checked;
}

/** Requests whose worker disappeared would block the same change for ever; they end as failed. */
export async function sweepStale(): Promise<void> {
  const lost = await db
    .update(schema.fixPr)
    .set({ state: "failed", reason: "interrupted", updatedAt: new Date() })
    .where(
      and(
        inArray(schema.fixPr.state, ["queued", "running"]),
        // A request that was queued or running this long lost its worker.
        lt(schema.fixPr.updatedAt, sql`now() - interval '20 minutes'`),
      ),
    )
    .returning({
      organizationId: schema.fixPr.organizationId,
      repositoryId: schema.fixPr.repositoryId,
      requestedBy: schema.fixPr.requestedBy,
    });
  for (const pr of lost) await tellAboutFixPr(pr, "fixPrFailed");
}

/** Registers the periodic status refresh: every 15 minutes, evaluated in UTC. */
export async function startFixPrScheduler(boss: PgBoss): Promise<void> {
  await boss.createQueue(FIX_PR_TICK_QUEUE);
  await boss.schedule(FIX_PR_TICK_QUEUE, "*/15 * * * *", null, { tz: "UTC" });
  await boss.work(FIX_PR_TICK_QUEUE, { batchSize: 1 }, async () => {
    await refreshFixPrs().catch((error: Error) => console.error("fix-pr refresh:", error.name));
  });
}
