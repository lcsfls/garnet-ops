/**
 * The open pull requests of the monitored repositories (ADR 0032), read by the worker with each repository's read
 * credential (never the write token of ADR 0014) every 15 minutes and on demand. What a forge says is hostile text: the
 * forge client cuts and cleans it, and the link is built from the repository address.
 */
import { newId } from "@garnetops/core";
import {
  defaultApiBase,
  detectForge,
  type ForgeKind,
  parseRepoLocation,
  pullRequestUrl,
} from "@garnetops/core/fix-prs";
import { schema } from "@garnetops/db";
import { and, eq, inArray, notInArray } from "drizzle-orm";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { ForgeError, type ForgeTarget, listOpenPullRequests } from "./forge.ts";
import { accountOf } from "./forge-connection.ts";
import { openSecretText } from "./vault-secrets.ts";

export const PULL_REQUEST_QUEUE = "pull-requests.refresh";
const PULL_REQUEST_TICK_QUEUE = "pull-requests.tick";

type RepoRow = typeof schema.repository.$inferSelect;

/**
 * Where to read a repository's pull requests, and with which token: its connection, else its https read token, else none
 * (a public repository). The forge comes from the connection, the fix pull request settings, or the host. Null when the
 * forge is unknown or the address names no owner and repository.
 */
async function targetOf(repo: RepoRow): Promise<ForgeTarget | null> {
  const location = parseRepoLocation(repo.url);
  if (!location) return null;
  if (repo.authKind === "connection" && repo.forgeConnectionId) {
    const [connection] = await db
      .select()
      .from(schema.forgeConnection)
      .where(
        and(
          eq(schema.forgeConnection.id, repo.forgeConnectionId),
          eq(schema.forgeConnection.organizationId, repo.organizationId),
        ),
      )
      .limit(1);
    if (!connection) throw new ForgeError("token-rejected");
    const account = await accountOf(connection);
    return { ...account, owner: location.owner, repo: location.repo };
  }
  const [access] = await db
    .select({
      kind: schema.repositoryWriteAccess.forgeKind,
      apiBaseUrl: schema.repositoryWriteAccess.apiBaseUrl,
    })
    .from(schema.repositoryWriteAccess)
    .where(eq(schema.repositoryWriteAccess.repositoryId, repo.id))
    .limit(1);
  const kind: ForgeKind | null = access?.kind ?? detectForge(location.host);
  if (!kind) return null;
  // Only the read token; an https token that never matched this forge simply fails with a code.
  const token =
    repo.authKind === "https-token"
      ? ((await openSecretText(repo.secretId, repo.organizationId, "forge-token")) ?? "")
      : "";
  return {
    kind,
    apiBaseUrl: access?.apiBaseUrl ?? defaultApiBase(kind, location.host),
    token,
    owner: location.owner,
    repo: location.repo,
  };
}

/** Reads one repository's open pull requests and replaces the stored ones. Never throws: problems are stored as codes. */
export async function refreshRepositoryPullRequests(repo: RepoRow): Promise<void> {
  const location = parseRepoLocation(repo.url);
  try {
    const target = await targetOf(repo);
    if (!target || !location) {
      await db
        .update(schema.repository)
        .set({ pullRequestsCheckedAt: new Date(), pullRequestsProblem: "forge-unknown" })
        .where(eq(schema.repository.id, repo.id));
      return;
    }
    const open = await listOpenPullRequests(target);
    target.token = "";
    await db.transaction(async (tx) => {
      const numbers = open.map((p) => p.number);
      await tx
        .delete(schema.pullRequest)
        .where(
          and(
            eq(schema.pullRequest.repositoryId, repo.id),
            numbers.length ? notInArray(schema.pullRequest.number, numbers) : undefined,
          ),
        );
      for (const p of open) {
        const values = {
          title: p.title,
          author: p.author,
          url: pullRequestUrl(target.kind, location.webBase, p.number),
          headRef: p.headRef,
          headSha: p.headSha,
          baseRef: p.baseRef,
          draft: p.draft,
          openedAt: p.openedAt,
          updatedAt: p.updatedAt,
          fetchedAt: new Date(),
        };
        await tx
          .insert(schema.pullRequest)
          .values({
            id: newId("pr"),
            organizationId: repo.organizationId,
            repositoryId: repo.id,
            number: p.number,
            ...values,
          })
          .onConflictDoUpdate({
            target: [schema.pullRequest.repositoryId, schema.pullRequest.number],
            set: values,
          });
      }
      await tx
        .update(schema.repository)
        .set({ pullRequestsCheckedAt: new Date(), pullRequestsProblem: null })
        .where(eq(schema.repository.id, repo.id));
    });
  } catch (error) {
    if (!(error instanceof ForgeError)) console.error("pull requests:", (error as Error)?.name);
    await db
      .update(schema.repository)
      .set({
        pullRequestsCheckedAt: new Date(),
        pullRequestsProblem: error instanceof ForgeError ? error.code : "unexpected",
      })
      .where(eq(schema.repository.id, repo.id));
  }
}

/** All repositories, or those of one organisation or one repository, one after another. */
export async function refreshPullRequests(
  options: { organizationId?: string; repositoryIds?: string[] } = {},
) {
  const repos = await db
    .select()
    .from(schema.repository)
    .where(
      and(
        options.organizationId ? eq(schema.repository.organizationId, options.organizationId) : undefined,
        options.repositoryIds?.length ? inArray(schema.repository.id, options.repositoryIds) : undefined,
      ),
    );
  for (const repo of repos) await refreshRepositoryPullRequests(repo);
  return repos.length;
}

/** Every 15 minutes, and on demand from the API (`PULL_REQUEST_QUEUE`). */
export async function startPullRequestRefresh(boss: PgBoss): Promise<void> {
  await boss.createQueue(PULL_REQUEST_QUEUE);
  await boss.createQueue(PULL_REQUEST_TICK_QUEUE);
  await boss.schedule(PULL_REQUEST_TICK_QUEUE, "*/15 * * * *", null, { tz: "UTC" });
  await boss.work(PULL_REQUEST_TICK_QUEUE, { batchSize: 1 }, async () => {
    await refreshPullRequests().catch((error: Error) => console.error("pull requests:", error.name));
  });
  await boss.work<{ organizationId: string; repositoryIds?: string[] }>(
    PULL_REQUEST_QUEUE,
    { batchSize: 1 },
    async ([job]) => {
      if (job) await refreshPullRequests(job.data);
    },
  );
}
