/**
 * Clones a repository the way scans do (ADR 0005, 0028, 0030), with its read credential: a deploy key on disk only for the clone, a
 * connection's token only to its own host, a stored token from the vault. Shared by scans and the code viewer (ADR 0048). Messages
 * of a `RepoCloneError` are safe to show; nothing else of git's output ever is.
 */
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { scanErrorMessage } from "@garnetops/core";
import { parseKnownHosts } from "@garnetops/core/ssh";
import { open, type SecretPurpose } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";
import { accountOf, SignInExpiredError } from "./forge-connection.ts";
import { type SshOptions, shallowClone, sshClient } from "./git.ts";

/** A clone that failed for a reason a person can act on; the message is user-safe. */
export class RepoCloneError extends Error {}
const UserFacingError = RepoCloneError;

export async function cloneRepository(
  repo: typeof schema.repository.$inferSelect,
  opts: { dir: string; home: string; sshDir: string; ref?: string | null; fullHistory?: boolean },
): Promise<{ commitSha: string; branch: string }> {
  let token: string | null = null;
  let ssh: SshOptions | null = null;
  if (repo.authKind === "ssh-deploy-key") {
    if (!repo.secretId) throw new UserFacingError(scanErrorMessage("deployKeyMissing"));
    const client = await sshClient().catch((e: Error) => {
      throw new UserFacingError(e.message);
    });
    await mkdir(opts.sshDir, { mode: 0o700 });
    const privateKeyFile = join(opts.sshDir, "id_ed25519");
    const knownHostsFile = join(opts.sshDir, "known_hosts");
    const key = await openSecret(repo, "ssh-private-key");
    await writeFile(privateKeyFile, key, { mode: 0o600 });
    key.fill(0);
    await writeFile(knownHostsFile, repo.sshKnownHosts ?? "", { mode: 0o600 });
    ssh = { ...client, privateKeyFile, knownHostsFile, pinned: Boolean(repo.sshKnownHosts) };
  } else if (repo.authKind === "connection") {
    token = await connectionToken(repo);
  } else if (repo.secretId) {
    const plain = await openSecret(repo, "forge-token");
    token = plain.toString("utf8");
    plain.fill(0);
  }
  return shallowClone({
    url: repo.url,
    dir: opts.dir,
    home: opts.home,
    branch: repo.branch,
    ref: opts.ref ?? null,
    token,
    ssh,
    fullHistory: opts.fullHistory === true,
  })
    .catch((e: Error) => {
      throw new UserFacingError(e.message);
    })
    .finally(async () => {
      token = null;
      if (!ssh) return;
      // The key lives on disk only for the clone itself.
      await rm(ssh.privateKeyFile, { force: true });
      if (!ssh.pinned) await pinHostKeys(repo.id, ssh.knownHostsFile);
    });
}

/** The read token of the personal connection a repository was added through (ADR 0030). */
async function connectionToken(repo: typeof schema.repository.$inferSelect): Promise<string> {
  if (!repo.forgeConnectionId) throw new UserFacingError(scanErrorMessage("connectionRemoved"));
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
  if (!connection) throw new UserFacingError(scanErrorMessage("connectionRemoved"));
  // Only the host the connection belongs to ever receives its token.
  if (new URL(repo.url).hostname !== new URL(connection.webBaseUrl).hostname) {
    throw new UserFacingError(scanErrorMessage("credentialMissing"));
  }
  const account = await accountOf(connection).catch(async (error) => {
    if (error instanceof SignInExpiredError) {
      // The owner sees it on the connection too, and signs in again.
      await db
        .update(schema.forgeConnection)
        .set({ state: "failed", problem: "sign-in-expired", updatedAt: new Date() })
        .where(eq(schema.forgeConnection.id, connection.id));
      throw new UserFacingError(scanErrorMessage("signInExpired"));
    }
    throw new UserFacingError(scanErrorMessage("credentialMissing"));
  });
  return account.token;
}

async function openSecret(
  repo: typeof schema.repository.$inferSelect,
  purpose: SecretPurpose,
): Promise<Buffer> {
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, repo.secretId as string),
        eq(schema.secret.organizationId, repo.organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!secret) throw new UserFacingError(scanErrorMessage("credentialMissing"));
  return open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose },
    vaultPrivateKey,
  );
}

/**
 * Trust on first use: the host keys ssh recorded on the first contact become the only keys
 * accepted from then on. Recorded even if authentication failed (the key was not added to
 * the forge yet), because the server already proved it holds the host key. Never overwrites
 * keys that are already pinned.
 */
async function pinHostKeys(repositoryId: string, knownHostsFile: string) {
  const content = await readFile(knownHostsFile, "utf8").catch(() => "");
  const hosts = parseKnownHosts(content);
  if (!hosts) return;
  await db
    .update(schema.repository)
    .set({
      sshKnownHosts: hosts.map((h) => `${h.host} ${h.type} ${h.key}`).join("\n"),
      sshKnownHostsPinnedAt: sql`now()`,
    })
    .where(and(eq(schema.repository.id, repositoryId), isNull(schema.repository.sshKnownHosts)));
}
