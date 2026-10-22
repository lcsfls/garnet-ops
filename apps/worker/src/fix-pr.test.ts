/**
 * Fix pull requests in the worker (ADR 0014) against a fake forge (GitHub and Gitea/Forgejo
 * flavours, HTTPS with a throw-away certificate) and a throw-away PostgreSQL database on the
 * development server, with a real vault key. Checks the whole flow (branch, one file changed
 * with the blob-id precondition, pull request), every refusal and failure mapping, the status
 * refresh, the token check, and that the token never lands in a database row, an audit entry
 * or a log line. Skipped without the development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { blobSha, FakeForge } from "../test/fake-forge.ts";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-fixpr-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_fix";
const OTHER_ORG = "org_other";
const USER = "user_fix";
const TOKEN = "write-token-0123456789abcdef";
const MANIFEST = `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "4.18.1"
  }
}
`;
const EDITED = MANIFEST.replace("^4.17.20", "^4.17.21");

describe.skipIf(!adminUrl || !openssl)("fix pull requests", () => {
  let t: TestDatabase;
  let mod: typeof import("./fix-pr.ts");
  let forgeMod: typeof import("./forge.ts");
  let publicKey: ReturnType<typeof loadVaultPublicKey>;
  const logs: string[] = [];
  let ids = 0;

  beforeAll(async () => {
    const pair = generateVaultKeyPair();
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, pair.privateKeyPem, { mode: 0o600 });
    publicKey = loadVaultPublicKey(pair.publicKeyPem);
    t = await createTestDatabase(adminUrl as string, "worker_fixpr");
    // The worker's modules read their settings when they are first imported.
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
    });
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "Example Org" },
      { id: OTHER_ORG, name: "Other Org" },
    ]);
    await t.db
      .insert(schema.user)
      .values({ id: USER, name: "Erika `@everyone` Example", email: "erika@example.test" });
    mod = await import("./fix-pr.ts");
    forgeMod = await import("./forge.ts");
    for (const level of ["log", "error", "warn", "info"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(args.map(String).join(" "));
      });
    }
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    forgeMod?.setForgeTestHooks(null);
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  describe.each([
    ["github", "github" as const],
    ["gitea", "gitea" as const],
  ])("%s", (_name, flavour) => {
    let forge: FakeForge;

    /** A repository on the fake forge with write access, and a queued request for lodash. */
    async function seed(
      options: {
        token?: string;
        branch?: string | null;
        blob?: string;
        apiBaseUrl?: string;
        noAccess?: boolean;
        ecosystem?: string;
        manifestPath?: string;
        organizationId?: string;
      } = {},
    ) {
      const n = ++ids;
      const organizationId = options.organizationId ?? ORG;
      const repositoryId = `repo_fix${n}`;
      await t.db.insert(schema.repository).values({
        id: repositoryId,
        organizationId,
        name: `app-${n}`,
        url: forge.repositoryUrl.replace(/app\.git$/, `app${n}.git`),
        branch: options.branch === undefined ? "main" : options.branch,
        authKind: "none",
      });
      const secretId = `sec_fix${n}`;
      if (!options.noAccess) {
        await t.db.insert(schema.secret).values({
          id: secretId,
          organizationId,
          purpose: "forge-write-token",
          sealed: seal(
            options.token ?? TOKEN,
            { organizationId, recordId: secretId, purpose: "forge-write-token" },
            publicKey,
          ),
          vaultKeyId: publicKey.id,
        });
        await t.db.insert(schema.repositoryWriteAccess).values({
          repositoryId,
          organizationId,
          secretId,
          forgeKind: flavour,
          apiBaseUrl: options.apiBaseUrl ?? forge.apiBase,
          enabledBy: USER,
        });
      }
      for (const id of ["CVE-2099-0001", "GHSA-2ccf-ffrj-m4qw"]) {
        await t.db
          .insert(schema.vulnerability)
          .values({ id, severity: "high", urls: ["https://advisories.example.com/x"] })
          .onConflictDoNothing();
      }
      const fixPrId = `fpr_fix${n}`;
      await t.db.insert(schema.fixPr).values({
        id: fixPrId,
        organizationId,
        repositoryId,
        proposalKey: `${"a".repeat(23)}${n % 10}`,
        ecosystem: options.ecosystem ?? "npm",
        packageName: "lodash",
        fromVersion: "4.17.20",
        toVersion: "4.17.21",
        majorUpgrade: false,
        manifestPath: options.manifestPath ?? "package.json",
        expectedBlobSha: options.blob ?? blobSha(MANIFEST),
        severity: "high",
        vulnerabilityIds: ["CVE-2099-0001", "GHSA-2ccf-ffrj-m4qw"],
        state: "queued",
        requestedBy: USER,
      });
      return { repositoryId, fixPrId, secretId };
    }

    const row = async (id: string) =>
      (await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.id, id)))[0];

    beforeAll(async () => {
      forge = await new FakeForge(flavour, TOKEN, "team", "app", {
        files: { "package.json": MANIFEST },
      }).start();
      forgeMod.setForgeTestHooks({
        resolve: async () => ["192.168.1.20"],
        connectTo: () => "127.0.0.1",
        ca: forge.ca,
      });
    }, 60_000);

    afterAll(async () => {
      forgeMod.setForgeTestHooks(null);
      await forge?.stop();
    });

    beforeEach(() => {
      forge.requests.length = 0;
      forge.faults.length = 0;
    });

    afterEach(async () => {
      // Every test starts from a forge with only the default branch and no pull requests, and no repositories.
      await t.db.delete(schema.repository);
      for (const name of [...forge.branches.keys()]) if (name !== "main") forge.branches.delete(name);
      forge.pulls.length = 0;
      forge.branches.set("main", forge.branches.get("main") as never);
      forge.setFile("main", "package.json", MANIFEST);
    });

    it("opens a pull request: one branch, one file changed, a fixed text, nothing on the default branch", async () => {
      const { fixPrId } = await seed();
      await mod.runFixPr(fixPrId);
      const pr = await row(fixPrId);
      expect(pr).toMatchObject({
        state: "open",
        reason: null,
        branch: "garnetops/fix-lodash-4.17.21",
        baseBranch: "main",
        prNumber: 1,
      });
      // The address is built from the repository, never taken from the forge's answer.
      expect(pr?.prUrl).toBe(
        `https://forge.example.test:${forge.port}/team/app${pr?.repositoryId.replace("repo_fix", "")}/${flavour === "github" ? "pull" : "pulls"}/1`,
      );
      expect(forge.fileOn("garnetops/fix-lodash-4.17.21", "package.json")).toBe(EDITED);
      expect(forge.fileOn("main", "package.json")).toBe(MANIFEST);

      const pull = forge.pulls[0];
      expect(pull).toMatchObject({
        title: "fix(deps): update lodash from 4.17.20 to 4.17.21",
        head: "garnetops/fix-lodash-4.17.21",
        base: "main",
        state: "open",
      });
      expect(pull?.body).toContain("`lodash`: `4.17.20` → `4.17.21` in `package.json`");
      expect(pull?.body).toContain("[`CVE-2099-0001`](https://nvd.nist.gov/vuln/detail/CVE-2099-0001)");
      expect(pull?.body).toContain(
        "[`GHSA-2ccf-ffrj-m4qw`](https://github.com/advisories/GHSA-2ccf-ffrj-m4qw)",
      );
      expect(pull?.body).toContain("The lockfile is **not** updated");
      // The requester's name is shown as inert text: a mention cannot come out of it.
      expect(pull?.body).toContain("at the request of ``Erika `@everyone` Example``");

      // Only these requests wrote anything, and none of them to the default branch.
      const writes = forge.requests.filter((r) => r.method !== "GET");
      expect(writes).toHaveLength(3);
      const put = writes.find((r) => r.method === "PUT");
      expect((put?.body as { branch: string } | null)?.branch).toBe("garnetops/fix-lodash-4.17.21");
      expect((put?.body as { sha: string } | null)?.sha).toBe(blobSha(MANIFEST));
      expect(writes.every((r) => r.authorization === forge.authorization)).toBe(true);
      expect(forge.requests.some((r) => /merge|review|approv/.test(r.path))).toBe(false);

      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, fixPrId));
      expect(audit.map((a) => a.action)).toEqual(["fix_pr.opened"]);
      expect(audit[0]).toMatchObject({ organizationId: ORG, actorUserId: USER });
    });

    it("branches from the tracked branch; without one, from the forge's default branch", async () => {
      forge.branches.set("release", forge.branches.get("main") as never);
      forge.setFile("release", "package.json", MANIFEST);
      const release = await seed({ branch: "release", blob: blobSha(MANIFEST) });
      await mod.runFixPr(release.fixPrId);
      expect(await row(release.fixPrId)).toMatchObject({ state: "open", baseBranch: "release" });
      const dflt = await seed({ branch: null });
      forge.branches.delete("garnetops/fix-lodash-4.17.21");
      await mod.runFixPr(dflt.fixPrId);
      expect(await row(dflt.fixPrId)).toMatchObject({ state: "open", baseBranch: "main" });
      forge.branches.delete("release");
    });

    it("only the first worker takes a request, and a request that is not queued is left alone", async () => {
      const { fixPrId } = await seed();
      await Promise.all([mod.runFixPr(fixPrId), mod.runFixPr(fixPrId)]);
      expect(forge.pulls).toHaveLength(1);
      forge.requests.length = 0;
      await mod.runFixPr(fixPrId);
      expect(forge.requests).toHaveLength(0);
    });

    it("refuses a manifest that changed since the scan, and makes no branch", async () => {
      const { fixPrId } = await seed({ blob: blobSha("what the scan saw") });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "manifest-changed" });
      expect(forge.requests.filter((r) => r.method !== "GET")).toHaveLength(0);
      expect(forge.branches.size).toBe(1);
    });

    it("refuses a manifest that is gone", async () => {
      const { fixPrId } = await seed({ manifestPath: "web/package.json" });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "manifest-missing" });
      expect(forge.requests.filter((r) => r.method !== "GET")).toHaveLength(0);
    });

    it("the forge's own sha check catches a change between the read and the write; the branch is removed again", async () => {
      const { fixPrId } = await seed();
      forge.faults.push({ match: /^PUT /, status: flavour === "github" ? 409 : 422, once: true });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "manifest-changed" });
      expect(forge.branches.has("garnetops/fix-lodash-4.17.21")).toBe(false);
      expect(forge.pulls).toHaveLength(0);
    });

    it("refuses when the edit is not safe, with the reason", async () => {
      forge.setFile("main", "package.json", MANIFEST.replace("^4.17.20", ">=4 <5"));
      const edited = forge.fileOn("main", "package.json") as string;
      const { fixPrId } = await seed({ blob: blobSha(edited) });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "edit-complex-range" });
      forge.setFile("main", "package.json", "{ not json");
      const bad = await seed({ blob: blobSha("{ not json") });
      await mod.runFixPr(bad.fixPrId);
      expect(await row(bad.fixPrId)).toMatchObject({ state: "failed", reason: "edit-invalid" });
      forge.setFile("main", "package.json", '{"dependencies":{"lodash":"^4.17.20","lodash":"^4.17.1"}}');
      const dup = await seed({ blob: blobSha('{"dependencies":{"lodash":"^4.17.20","lodash":"^4.17.1"}}') });
      await mod.runFixPr(dup.fixPrId);
      expect(await row(dup.fixPrId)).toMatchObject({ state: "failed", reason: "edit-ambiguous" });
      expect(forge.requests.filter((r) => r.method !== "GET")).toHaveLength(0);
    });

    it("a file that is not UTF-8 is refused", async () => {
      const bytes = Buffer.from([0x7b, 0xff, 0xfe, 0x7d]);
      forge.branches.get("main")?.files.set("package.json", bytes);
      const { fixPrId } = await seed({ blob: blobSha(bytes) });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "edit-invalid" });
    });

    it("never reuses a branch that already exists", async () => {
      const head = forge.branches.get("main") as never;
      forge.branches.set("garnetops/fix-lodash-4.17.21", head);
      const { fixPrId } = await seed();
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "branch-exists" });
      expect(forge.branches.get("garnetops/fix-lodash-4.17.21")).toBe(head);
      expect(forge.requests.some((r) => r.method === "PUT")).toBe(false);
    });

    it.each([
      [/^GET [^?]*\/repos\/team\/app\d*$/, 401, "token-rejected"],
      [/^GET [^?]*\/repos\/team\/app\d*$/, 403, "forbidden"],
      [/^GET [^?]*\/repos\/team\/app\d*$/, 404, "not-found"],
      [/^GET [^?]*\/repos\/team\/app\d*$/, 429, "rate-limited"],
      [/^GET [^?]*\/repos\/team\/app\d*$/, 500, "http-error"],
      [/^GET .*\/branches\//, 404, "not-found"],
      [/^POST .*\/pulls$/, 422, "rejected"],
      [/^POST .*\/pulls$/, 403, "forbidden"],
    ])("%s answered with %i is stored as %s", async (match, status, reason) => {
      const { fixPrId } = await seed();
      forge.faults.push({ match, status });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason });
      // A failure after the branch was made leaves no branch behind.
      expect(forge.branches.has("garnetops/fix-lodash-4.17.21")).toBe(false);
      expect(forge.pulls).toHaveLength(0);
    });

    it("a redirect is refused and the token goes nowhere else", async () => {
      const { fixPrId } = await seed();
      forge.faults.push({ match: /^GET /, status: 302, headers: { location: "https://evil.example/steal" } });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "redirect" });
      expect(forge.requests).toHaveLength(1);
    });

    it("an oversized answer is refused", async () => {
      const { fixPrId } = await seed();
      forge.faults.push({ match: /^GET /, action: "huge" });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "too-large" });
    });

    it("an archived repository or a token without push permission fails clearly", async () => {
      const { fixPrId } = await seed();
      forge.faults.push({
        match: /^GET [^?]*\/repos\/team\/app\d*$/,
        status: 200,
        body: JSON.stringify({ default_branch: "main", permissions: { push: false } }),
      });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "no-push-access" });
    });

    it("a request whose write access was switched off fails without calling the forge", async () => {
      const { fixPrId } = await seed({ noAccess: true });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "write-access-missing" });
      expect(forge.requests).toHaveLength(0);
    });

    it("never uses a token that is not the repository's own: another purpose, another organisation's seal", async () => {
      const a = await seed();
      await t.db
        .update(schema.secret)
        .set({ purpose: "forge-token" })
        .where(eq(schema.secret.id, a.secretId));
      await mod.runFixPr(a.fixPrId);
      expect(await row(a.fixPrId)).toMatchObject({ state: "failed", reason: "token-rejected" });
      // A token sealed for another organisation, copied into this row: the vault binding rejects it.
      const b = await seed();
      await t.db
        .update(schema.secret)
        .set({
          sealed: seal(
            TOKEN,
            { organizationId: OTHER_ORG, recordId: b.secretId, purpose: "forge-write-token" },
            publicKey,
          ),
        })
        .where(eq(schema.secret.id, b.secretId));
      await mod.runFixPr(b.fixPrId);
      expect(await row(b.fixPrId)).toMatchObject({ state: "failed", reason: "token-rejected" });
      expect(forge.requests).toHaveLength(0);
    });

    it("refuses values that should never have been stored", async () => {
      const { fixPrId } = await seed();
      await t.db
        .update(schema.fixPr)
        .set({ packageName: "lodash; rm -rf /" })
        .where(eq(schema.fixPr.id, fixPrId));
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "rejected" });
      expect(forge.requests).toHaveLength(0);
    });

    it("an API address outside the allowed network is never contacted", async () => {
      const { fixPrId } = await seed({ apiBaseUrl: "https://169.254.169.254/api/v1" });
      await mod.runFixPr(fixPrId);
      expect(await row(fixPrId)).toMatchObject({ state: "failed", reason: "address-refused" });
      expect(forge.requests).toHaveLength(0);
    });

    describe("status refresh", () => {
      async function openPr() {
        const s = await seed();
        await mod.runFixPr(s.fixPrId);
        expect((await row(s.fixPrId))?.state).toBe("open");
        return s;
      }

      it("records merged and closed pull requests, leaves open ones open", async () => {
        const a = await openPr();
        forge.branches.delete("garnetops/fix-lodash-4.17.21");
        const b = await openPr();
        forge.setPull(1, { state: "closed", merged: true });
        forge.setPull(2, { state: "closed", merged: false });
        forge.requests.length = 0;
        await mod.refreshFixPrs({ force: true });
        expect(await row(a.fixPrId)).toMatchObject({ state: "merged", reason: null });
        expect((await row(a.fixPrId))?.closedAt).toBeInstanceOf(Date);
        expect(await row(b.fixPrId)).toMatchObject({ state: "closed" });
        // Only reads.
        expect(forge.requests.every((r) => r.method === "GET")).toBe(true);
        const audit = await t.db
          .select()
          .from(schema.auditLog)
          .where(eq(schema.auditLog.targetId, a.fixPrId));
        expect(audit.map((x) => x.action)).toContain("fix_pr.merged");
      });

      it("keeps the state and notes the reason when the forge cannot be asked", async () => {
        forge.branches.delete("garnetops/fix-lodash-4.17.21");
        const s = await openPr();
        forge.faults.push({ match: /^GET .*\/pulls\//, status: 401 });
        await mod.refreshFixPrs({ repositoryId: s.repositoryId, force: true });
        expect(await row(s.fixPrId)).toMatchObject({ state: "open", reason: "token-rejected" });
        forge.faults.length = 0;
        await mod.refreshFixPrs({ repositoryId: s.repositoryId, force: true });
        expect(await row(s.fixPrId)).toMatchObject({ state: "open", reason: null });
      });

      it("does not look again before the interval is over", async () => {
        forge.branches.delete("garnetops/fix-lodash-4.17.21");
        const s = await openPr();
        forge.requests.length = 0;
        await mod.refreshFixPrs({ repositoryId: s.repositoryId });
        expect(forge.requests).toHaveLength(0);
      });

      it("only touches the organisation it was asked about", async () => {
        forge.branches.delete("garnetops/fix-lodash-4.17.21");
        const s = await openPr();
        forge.requests.length = 0;
        await mod.refreshFixPrs({ organizationId: OTHER_ORG, force: true });
        expect(forge.requests).toHaveLength(0);
        expect((await row(s.fixPrId))?.state).toBe("open");
      });

      it("requests whose worker disappeared end as failed and free the change for a new request", async () => {
        const s = await seed();
        await t.db
          .update(schema.fixPr)
          .set({ state: "running", updatedAt: new Date(Date.now() - 30 * 60_000) })
          .where(eq(schema.fixPr.id, s.fixPrId));
        await mod.sweepStale();
        expect(await row(s.fixPrId)).toMatchObject({ state: "failed", reason: "interrupted" });
      });
    });

    describe("checking the token", () => {
      it("marks a working token ok", async () => {
        const { repositoryId } = await seed();
        await mod.checkWriteAccess(repositoryId);
        const [access] = await t.db
          .select()
          .from(schema.repositoryWriteAccess)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repositoryId));
        expect(access).toMatchObject({ status: "ok", statusReason: null, warning: null });
        expect(access?.checkedAt).toBeInstanceOf(Date);
        expect(forge.requests.every((r) => r.method === "GET")).toBe(true);
      });

      it.each([
        [401, "token-rejected"],
        [404, "not-found"],
      ])("marks a token the forge answers %i for as failed (%s)", async (status, reason) => {
        const { repositoryId } = await seed();
        forge.faults.push({ match: /^GET /, status });
        await mod.checkWriteAccess(repositoryId);
        const [access] = await t.db
          .select()
          .from(schema.repositoryWriteAccess)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repositoryId));
        expect(access).toMatchObject({ status: "failed", statusReason: reason });
      });

      it("flags a token without push permission", async () => {
        const { repositoryId } = await seed();
        forge.faults.push({
          match: /^GET [^?]*\/repos\/team\/app\d*$/,
          status: 200,
          body: JSON.stringify({ default_branch: "main", permissions: { push: false } }),
        });
        await mod.checkWriteAccess(repositoryId);
        const [access] = await t.db
          .select()
          .from(schema.repositoryWriteAccess)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repositoryId));
        expect(access).toMatchObject({ status: "failed", statusReason: "no-push-access" });
      });

      it.skipIf(flavour !== "github")(
        "warns when GitHub says the token is a classic token with the repo scope",
        async () => {
          const { repositoryId } = await seed();
          forge.faults.push({
            match: /^GET [^?]*\/repos\/team\/app\d*$/,
            status: 200,
            headers: { "x-oauth-scopes": "gist, repo, workflow" },
            body: JSON.stringify({ default_branch: "main", permissions: { push: true } }),
          });
          await mod.checkWriteAccess(repositoryId);
          const [access] = await t.db
            .select()
            .from(schema.repositoryWriteAccess)
            .where(eq(schema.repositoryWriteAccess.repositoryId, repositoryId));
          expect(access).toMatchObject({ status: "ok", warning: "broad-token" });
        },
      );
    });

    it("the token never lands in a database row, an audit entry or a log line", async () => {
      // Failures of every kind first, so their rows exist too.
      const bad = await seed();
      forge.faults.push({ match: /^GET /, status: 401, body: `{"message":"bad token ${TOKEN}"}` });
      await mod.runFixPr(bad.fixPrId);
      const dump = async () => {
        const parts: unknown[] = [];
        for (const table of [
          schema.fixPr,
          schema.auditLog,
          schema.repositoryWriteAccess,
          schema.repository,
          schema.secret,
          schema.user,
        ]) {
          parts.push(await t.db.select().from(table));
        }
        return JSON.stringify(parts);
      };
      expect(await dump()).not.toContain(TOKEN);
      expect(logs.join("\n")).not.toContain(TOKEN);
      expect(logs.join("\n")).not.toContain(Buffer.from(TOKEN).toString("base64"));
    });
  });
});
