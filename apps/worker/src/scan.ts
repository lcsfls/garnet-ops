import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { newId, scanErrorMessage } from "@garnetops/core";
import { parseKnownHosts } from "@garnetops/core/ssh";
import { open, type SecretPurpose } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq, inArray, isNull, lt, or, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { env, vaultPrivateKey } from "./env.ts";
import { type SshOptions, shallowClone, sshClient } from "./git.ts";
import { addAdvisoryDates, type ParsedReport, parseReport, scanTarget } from "./grype.ts";
import { buildSbom, type Inventory, readSbom } from "./syft.ts";

const f = schema.finding;

class UserFacingError extends Error {}

async function directorySizeMb(dir: string, limitMb: number): Promise<number> {
  let bytes = 0;
  const limit = limitMb * 1024 * 1024;
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop() as string;
    for (const entry of await readdir(current, { withFileTypes: true })) {
      // Symlinks are not followed (core.symlinks=false also checks them out as plain files).
      if (entry.isDirectory()) stack.push(join(current, entry.name));
      else if (entry.isFile()) bytes += (await stat(join(current, entry.name))).size;
      if (bytes > limit) return bytes / 1024 / 1024;
    }
  }
  return bytes / 1024 / 1024;
}

async function fail(scanId: string, message: string) {
  await db
    .update(schema.scan)
    .set({ state: "failed", error: message, finishedAt: sql`now()` })
    .where(eq(schema.scan.id, scanId));
}

/**
 * Matches the job expiry in the API (queueScan): a running scan older than this lost its worker.
 * Start time and comparison both use the database clock, so a worker whose clock is off (or
 * jumps on an NTP correction) neither takes over a live scan nor leaves a dead one hanging.
 */
const STALE_RUNNING = sql`now() - interval '30 minutes'`;

export async function runScan(scanId: string): Promise<void> {
  // Claim a queued scan, or take over one whose worker died (pg-boss retries the job after it expires).
  const [scan] = await db
    .update(schema.scan)
    .set({ state: "running", startedAt: sql`now()` })
    .where(
      and(
        eq(schema.scan.id, scanId),
        or(
          eq(schema.scan.state, "queued"),
          and(eq(schema.scan.state, "running"), lt(schema.scan.startedAt, STALE_RUNNING)),
        ),
      ),
    )
    .returning();
  if (!scan) return; // already taken, finished or cancelled

  const [repo] = await db
    .select()
    .from(schema.repository)
    .where(eq(schema.repository.id, scan.repositoryId))
    .limit(1);
  if (!repo) return fail(scanId, scanErrorMessage("repositoryRemoved"));

  const root = await mkdtemp(join(env.GARNETOPS_WORK_DIR, "scan-"));
  try {
    const src = join(root, "src");
    const home = join(root, "home");
    const out = join(root, "out");
    const sshDir = join(root, "ssh");
    await Promise.all([mkdir(home), mkdir(out)]);

    let token: string | null = null;
    let ssh: SshOptions | null = null;
    if (repo.authKind === "ssh-deploy-key") {
      if (!repo.secretId) throw new UserFacingError(scanErrorMessage("deployKeyMissing"));
      const client = await sshClient().catch((e: Error) => {
        throw new UserFacingError(e.message);
      });
      await mkdir(sshDir, { mode: 0o700 });
      const privateKeyFile = join(sshDir, "id_ed25519");
      const knownHostsFile = join(sshDir, "known_hosts");
      const key = await openSecret(repo, "ssh-private-key");
      await writeFile(privateKeyFile, key, { mode: 0o600 });
      key.fill(0);
      await writeFile(knownHostsFile, repo.sshKnownHosts ?? "", { mode: 0o600 });
      ssh = { ...client, privateKeyFile, knownHostsFile, pinned: Boolean(repo.sshKnownHosts) };
    } else if (repo.secretId) {
      const plain = await openSecret(repo, "forge-token");
      token = plain.toString("utf8");
      plain.fill(0);
    }

    const cloned = await shallowClone({ url: repo.url, dir: src, home, branch: repo.branch, token, ssh })
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

    const sizeMb = await directorySizeMb(src, env.GARNETOPS_MAX_REPO_MB);
    if (sizeMb > env.GARNETOPS_MAX_REPO_MB) {
      throw new UserFacingError(scanErrorMessage("repositoryTooLarge", { limit: env.GARNETOPS_MAX_REPO_MB }));
    }

    // With syft: one SBOM is both the stored inventory and what grype matches, so the two agree.
    let inventory: Inventory | null = null;
    let target = `dir:${src}`;
    if (env.GARNETOPS_SYFT_BIN) {
      const sbomFile = await buildSbom(env.GARNETOPS_SYFT_BIN, src, out).catch(() => {
        throw new UserFacingError(scanErrorMessage("sbomFailed"));
      });
      inventory = await readSbom(sbomFile);
      target = `sbom:${sbomFile}`;
    }
    const json = await scanTarget(target, out).catch(() => {
      throw new UserFacingError(scanErrorMessage("scannerFailed"));
    });
    const parsed = parseReport(json, repo.id);
    addAdvisoryDates(parsed.vulnerabilities, env.GARNETOPS_GRYPE_DB_DIR);
    await persist(scan.id, repo, parsed, cloned, inventory);
  } catch (error) {
    if (error instanceof UserFacingError) await fail(scanId, error.message);
    else {
      console.error(`scan ${scanId}:`, error);
      await fail(scanId, scanErrorMessage("unexpected"));
    }
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => {});
  }
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

async function persist(
  scanId: string,
  repo: typeof schema.repository.$inferSelect,
  parsed: ParsedReport,
  cloned: { commitSha: string; branch: string },
  inventory: Inventory | null,
) {
  const now = new Date();
  const counts: Record<string, number> = {};
  for (const finding of parsed.findings.values())
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;

  await db.transaction(async (tx) => {
    const vulns = [...parsed.vulnerabilities.values()];
    for (let i = 0; i < vulns.length; i += 500) {
      await tx
        .insert(schema.vulnerability)
        .values(vulns.slice(i, i + 500).map((v) => ({ ...v, updatedAt: now })))
        .onConflictDoUpdate({
          target: schema.vulnerability.id,
          set: {
            namespace: sql`excluded.namespace`,
            severity: sql`excluded.severity`,
            cvssScore: sql`excluded.cvss_score`,
            cvssVector: sql`excluded.cvss_vector`,
            description: sql`excluded.description`,
            urls: sql`excluded.urls`,
            aliases: sql`excluded.aliases`,
            knownExploited: sql`excluded.known_exploited`,
            epss: sql`excluded.epss`,
            publishedAt: sql`excluded.published_at`,
            modifiedAt: sql`excluded.modified_at`,
            updatedAt: now,
          },
        });
    }

    const existing = await tx
      .select({ id: f.id, dedupKey: f.dedupKey, state: f.state, acceptedUntil: f.acceptedUntil })
      .from(f)
      .where(eq(f.repositoryId, repo.id));
    const byKey = new Map(existing.map((e) => [e.dedupKey, e]));

    let newFindings = 0;
    for (const p of parsed.findings.values()) {
      const prior = byKey.get(p.dedupKey);
      const common = {
        packageVersion: p.packageVersion,
        packagePurl: p.packagePurl,
        fixedIn: p.fixedIn,
        fixState: p.fixState,
        locations: p.locations,
        severity: p.severity,
        severityRank: p.severityRank,
        lastSeenScanId: scanId,
        lastSeenAt: now,
        updatedAt: now,
      };
      if (!prior) {
        newFindings++;
        await tx.insert(f).values({
          id: newId("fnd"),
          organizationId: repo.organizationId,
          repositoryId: repo.id,
          vulnerabilityId: p.vulnerabilityId,
          dedupKey: p.dedupKey,
          packageName: p.packageName,
          packageType: p.packageType,
          state: "open",
          firstSeenScanId: scanId,
          firstSeenAt: now,
          ...common,
        });
      } else if (prior.state === "resolved") {
        // It came back: reopen and count it as new in this scan.
        newFindings++;
        await tx
          .update(f)
          .set({ ...common, state: "open", resolvedAt: null, firstSeenScanId: scanId })
          .where(eq(f.id, prior.id));
      } else if (prior.state === "accepted" && prior.acceptedUntil && prior.acceptedUntil < now) {
        // An accepted risk expired: it needs a decision again.
        await tx
          .update(f)
          .set({ ...common, state: "open", acceptedReason: null, acceptedUntil: null, acceptedBy: null })
          .where(eq(f.id, prior.id));
      } else {
        await tx.update(f).set(common).where(eq(f.id, prior.id));
      }
    }

    const gone = existing
      .filter((e) => e.state !== "resolved" && !parsed.findings.has(e.dedupKey))
      .map((e) => e.id);
    for (let i = 0; i < gone.length; i += 500) {
      await tx
        .update(f)
        .set({ state: "resolved", resolvedAt: now, updatedAt: now })
        .where(inArray(f.id, gone.slice(i, i + 500)));
    }

    await tx
      .update(schema.scan)
      .set({
        state: "succeeded",
        finishedAt: now,
        branch: cloned.branch,
        commitSha: cloned.commitSha,
        // Without an SBOM only the vulnerable packages are known; null rather than a wrong total.
        packageCount: inventory ? inventory.total : null,
        severityCounts: counts,
        newFindings,
        resolvedFindings: gone.length,
        scannerVersions: {
          ...(parsed.grypeVersion ? { grype: parsed.grypeVersion } : {}),
          ...(inventory?.syftVersion ? { syft: inventory.syftVersion } : {}),
        },
        vulnDbBuiltAt: parsed.dbBuiltAt,
        error: null,
      })
      .where(eq(schema.scan.id, scanId));
    if (inventory) {
      await tx.delete(schema.repositoryPackage).where(eq(schema.repositoryPackage.repositoryId, repo.id));
      for (let i = 0; i < inventory.packages.length; i += 1000) {
        await tx.insert(schema.repositoryPackage).values(
          inventory.packages.slice(i, i + 1000).map((p) => ({
            id: newId("pkg"),
            organizationId: repo.organizationId,
            repositoryId: repo.id,
            scanId,
            ...p,
          })),
        );
      }
    }
    await tx
      .update(schema.repository)
      .set({ lastScanId: scanId, lastScanAt: now, updatedAt: now })
      .where(eq(schema.repository.id, repo.id));
  });
}
