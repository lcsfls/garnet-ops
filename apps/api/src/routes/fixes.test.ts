/**
 * Fix proposals, the per-repository write credential and fix pull requests (ADR 0014) against
 * a throw-away PostgreSQL database on the development server: who may read, enable and use
 * what, step-up, validation, that the token is only ever sealed (and sealed for its own
 * organisation, record and purpose), the proposals computed from findings and manifests,
 * filters, sorting and cursors, the AI suggestion, the pull request rows and the audit trail.
 * Sessions are replaced by a header-driven actor; the queue is a recorder. Skipped without the
 * development PostgreSQL.
 */
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  sent: [] as { name: string; data: Record<string, unknown>; options: Record<string, unknown> }[],
  db: null as unknown,
  vault: null as null | { publicKeyPem: string; privateKeyPem: string },
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_fixes");
  queue.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>, options: Record<string, unknown>) => {
        queue.sent.push({ name, data, options });
        return "job";
      },
    },
    QUEUES: {
      scanRepository: "scan.repository",
      fixPrCreate: "fix-pr.create",
      fixPrCheck: "fix-pr.check",
      fixPrRefresh: "fix-pr.refresh",
    },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: generate, loadVaultPublicKey } = await import("@garnetops/core/vault");
  queue.vault = generate();
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: loadVaultPublicKey(queue.vault.publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_fx_a";
const OTHER = "org_fx_b";
const STALE = 11 * 60;
const TOKEN = ["ghp_", "NotARealTokenJustFixtureText0123456789"].join("");
const MANIFEST_SHA = "a".repeat(40);

describe.skipIf(!adminUrl)("Fix proposals API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown; user?: string } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
      "x-user": options.user ?? "user_a",
      "x-ip": "198.51.100.7",
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json: json as Json | null, text };
  }
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  async function addRepo(
    overrides: Partial<typeof schema.repository.$inferInsert> = {},
    organizationId = ORG,
  ): Promise<string> {
    const id = `repo_fx${String(++counter).padStart(8, "0")}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId,
      name: `app-${counter}`,
      url: `https://git.example.lan/team/app-${counter}.git`,
      branch: "main",
      authKind: "none",
      ...overrides,
    });
    return id;
  }

  async function addFinding(
    repositoryId: string,
    f: {
      pkg: string;
      version: string;
      fixedIn: string[];
      vuln?: string;
      severity?: string;
      type?: string;
      locations?: string[];
      state?: "open" | "accepted" | "resolved";
    },
    organizationId = ORG,
  ) {
    const n = ++counter;
    const vulnerabilityId = f.vuln ?? `CVE-2099-${String(n).padStart(4, "0")}`;
    await t.db
      .insert(schema.vulnerability)
      .values({ id: vulnerabilityId, severity: f.severity ?? "high" })
      .onConflictDoNothing();
    const rank = { critical: 5, high: 4, medium: 3, low: 2 }[f.severity ?? "high"] ?? 0;
    const id = `fnd_fx${String(n).padStart(8, "0")}`;
    await t.db.insert(schema.finding).values({
      id,
      organizationId,
      repositoryId,
      vulnerabilityId,
      dedupKey: `${repositoryId}|${vulnerabilityId}|${f.type ?? "npm"}|${f.pkg}`,
      packageName: f.pkg,
      packageVersion: f.version,
      packageType: f.type ?? "npm",
      fixedIn: f.fixedIn,
      locations: f.locations ?? ["/package-lock.json"],
      severity: f.severity ?? "high",
      severityRank: rank,
      state: f.state ?? "open",
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    return id;
  }

  async function addManifest(
    repositoryId: string,
    path: string,
    kind: string,
    dependencies: {
      name: string;
      section?: string;
      spec: string;
      indirect?: boolean;
      dev?: boolean;
      blocked?: string;
    }[],
    organizationId = ORG,
  ) {
    await t.db.insert(schema.repositoryManifest).values({
      id: `mf_${++counter}`,
      organizationId,
      repositoryId,
      scanId: "scan_x",
      path,
      kind,
      blobSha: MANIFEST_SHA,
      size: 100,
      dependencies: dependencies.map((d) => ({
        name: d.name,
        section: d.section ?? "dependencies",
        spec: d.spec,
        indirect: d.indirect ?? false,
        dev: d.dev ?? false,
        ...(d.blocked ? { blocked: d.blocked } : {}),
      })),
    });
  }

  /** Write access with a sealed token, as the enable endpoint leaves it. */
  async function addAccess(
    repositoryId: string,
    extra: Partial<typeof schema.repositoryWriteAccess.$inferInsert> = {},
  ) {
    const secretId = `sec_fx${++counter}`;
    await t.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "forge-write-token",
      sealed: {},
      vaultKeyId: "k",
    });
    await t.db.insert(schema.repositoryWriteAccess).values({
      repositoryId,
      organizationId: ORG,
      secretId,
      forgeKind: "gitea",
      apiBaseUrl: "https://git.example.lan/api/v1",
      enabledBy: "user_a",
      status: "ok",
      ...extra,
    });
    return secretId;
  }

  /** A repository with a lodash finding that can be fixed by editing package.json. */
  async function editableRepo() {
    const repo = await addRepo();
    await addFinding(repo, { pkg: "lodash", version: "4.17.20", fixedIn: ["4.17.21"], severity: "critical" });
    await addManifest(repo, "package.json", "npm", [{ name: "lodash", spec: "^4.17.20" }]);
    return repo;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { fixRoutes } = await import("./fixes.ts");
    const { repositoryRoutes } = await import("./repositories.ts");
    t = queue.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values([
      { id: "user_a", name: "Erika Example", email: "erika@example.test" },
      { id: "user_b", name: "Max Example", email: "max@example.test" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "erika@example.test",
          name: "Erika Example",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: c.req.header("x-ip") ?? null,
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/fixes", fixRoutes as never);
    v1.route("/repositories", repositoryRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);
  beforeEach(async () => {
    queue.sent.length = 0;
    await t.db.delete(schema.rateLimit);
  });

  describe("proposals", () => {
    it("groups open fixable findings by package and manifest and picks the lowest fixing version", async () => {
      const repo = await addRepo();
      await addFinding(repo, { pkg: "lodash", version: "4.17.10", fixedIn: ["4.17.12"], severity: "medium" });
      await addFinding(repo, {
        pkg: "lodash",
        version: "4.17.10",
        fixedIn: ["4.17.21"],
        severity: "critical",
      });
      await addFinding(repo, { pkg: "express", version: "4.18.1", fixedIn: ["5.0.1"], severity: "high" });
      await addFinding(repo, { pkg: "minimist", version: "1.2.0", fixedIn: ["1.2.6"], severity: "low" });
      await addFinding(repo, { pkg: "nofix", version: "1.0.0", fixedIn: [], severity: "high" });
      await addFinding(repo, { pkg: "done", version: "1.0.0", fixedIn: ["1.0.1"], state: "accepted" });
      await addManifest(repo, "package.json", "npm", [
        { name: "lodash", spec: "^4.17.10" },
        { name: "express", spec: "4.18.1" },
      ]);
      const r = await call("GET", `/api/v1/fixes?repositoryId=${repo}`);
      expect(r.status).toBe(200);
      const items = r.json?.items as Json[];
      expect(items.map((i) => i.packageName)).toEqual(["lodash", "express", "minimist"]);
      expect(items[0]).toMatchObject({
        ecosystem: "npm",
        installedVersion: "4.17.10",
        targetVersion: "4.17.21",
        majorUpgrade: false,
        severity: "critical",
        manifestPath: "package.json",
        dependency: "direct",
        currentSpec: "^4.17.10",
        newSpec: "^4.17.21",
        action: "edit",
        reason: null,
        writeAccess: "off",
        creatable: false,
        pr: null,
        aiSuggestion: null,
      });
      expect(items[0]?.vulnerabilityIds).toHaveLength(2);
      expect(items[1]).toMatchObject({ targetVersion: "5.0.1", majorUpgrade: true, action: "edit" });
      expect(items[2]).toMatchObject({ dependency: "transitive", action: "manual", reason: "transitive" });
      expect(r.json?.total).toBe(3);
      expect(r.json?.counts).toEqual({ all: 3, edit: 2, manual: 1 });
    });

    it("explains why a proposal is manual", async () => {
      const repo = await addRepo();
      await addFinding(repo, { pkg: "range", version: "1.5.0", fixedIn: ["2.0.0"] });
      await addFinding(repo, { pkg: "git", version: "1.0.0", fixedIn: ["1.0.1"] });
      await addFinding(repo, { pkg: "same", version: "1.0.0", fixedIn: ["1.0.1"] });
      await addFinding(repo, {
        pkg: "unknown-eco",
        version: "1.0",
        fixedIn: ["1.1"],
        type: "gem",
        locations: ["/Gemfile.lock"],
      });
      await addFinding(repo, {
        pkg: "nolock",
        version: "1.0.0",
        fixedIn: ["1.0.1"],
        locations: ["/node_modules/x/package.json"],
      });
      await addFinding(repo, { pkg: "nofixver", version: "1.0.0", fixedIn: ["whatever"] });
      await addManifest(repo, "package.json", "npm", [
        { name: "range", spec: ">=1 <3" },
        { name: "git", spec: "git+https://example.com/x.git", blocked: "unsupported-source" },
        { name: "same", spec: "^1.0.1" },
        { name: "nolock", spec: "1.0.0" },
      ]);
      const r = await call("GET", `/api/v1/fixes?repositoryId=${repo}&pageSize=100`);
      const by = (name: string) => itemsOf(r).find((i) => i.packageName === name);
      expect(by("range")).toMatchObject({ action: "manual", reason: "complex-range" });
      expect(by("git")).toMatchObject({ action: "manual", reason: "unsupported-source" });
      expect(by("same")).toMatchObject({ action: "manual", reason: "already-satisfied" });
      expect(by("unknown-eco")).toMatchObject({
        action: "manual",
        reason: "unsupported-ecosystem",
        ecosystem: null,
      });
      expect(by("nolock")).toMatchObject({ action: "manual", reason: "no-manifest" });
      expect(by("nofixver")).toMatchObject({ action: "manual", reason: "no-version", targetVersion: null });
    });

    it("keeps organisations apart", async () => {
      const mine = await editableRepo();
      const theirs = await addRepo({}, OTHER);
      await addFinding(theirs, { pkg: "secret-package", version: "1.0.0", fixedIn: ["1.0.1"] }, OTHER);
      const r = await call("GET", "/api/v1/fixes?pageSize=100");
      const names = itemsOf(r).map((i) => i.packageName);
      expect(names).toContain("lodash");
      expect(names).not.toContain("secret-package");
      const other = await call("GET", `/api/v1/fixes?repositoryId=${mine}`, { org: OTHER });
      expect(other.json?.items).toEqual([]);
    });

    it("filters by search, severity, ecosystem, action and pull request state", async () => {
      const repo = await addRepo({ name: "zeta-service" });
      await addFinding(repo, {
        pkg: "alpha",
        version: "1.0.0",
        fixedIn: ["1.0.1"],
        severity: "critical",
        vuln: "CVE-2099-7001",
      });
      await addFinding(repo, {
        pkg: "beta",
        version: "1.0.0",
        fixedIn: ["1.0.1"],
        severity: "low",
        type: "python",
        locations: ["/requirements.txt"],
      });
      await addFinding(repo, { pkg: "gamma", version: "1.0.0", fixedIn: ["1.0.1"], severity: "medium" });
      await addManifest(repo, "package.json", "npm", [{ name: "alpha", spec: "^1.0.0" }]);
      await addManifest(repo, "requirements.txt", "pypi", [{ name: "beta", spec: "==1.0.0" }]);
      const q = (s: string) => call("GET", `/api/v1/fixes?repositoryId=${repo}&${s}`);
      const names = async (s: string) => itemsOf(await q(s)).map((i) => i.packageName);
      expect(await names("q=alph")).toEqual(["alpha"]);
      expect(await names("q=CVE-2099-7001")).toEqual(["alpha"]);
      expect(await names("q=zeta")).toHaveLength(3);
      expect(await names("q=requirements")).toEqual(["beta"]);
      expect(await names("severity=critical,low")).toEqual(["alpha", "beta"]);
      expect(await names("ecosystem=pypi")).toEqual(["beta"]);
      expect(await names("ecosystem=npm")).toEqual(["alpha", "gamma"]);
      expect(await names("action=edit")).toEqual(["alpha", "beta"]);
      expect(await names("action=manual")).toEqual(["gamma"]);
      expect(await names("pr=none")).toHaveLength(3);
      expect(await names("pr=open")).toEqual([]);
      expect((await q("severity=bogus")).status).toBe(422);
      expect((await q("sort=bogus")).status).toBe(422);
      expect((await q("pageSize=7")).status).toBe(422);
      // The counts of the action tabs ignore the action filter but keep the others.
      expect((await q("severity=critical,low&action=manual")).json?.counts).toEqual({
        all: 2,
        edit: 2,
        manual: 0,
      });
    });

    it("sorts by every column in both directions and pages with cursors both ways", async () => {
      const repoA = await addRepo({ name: "aaa" });
      const repoB = await addRepo({ name: "bbb" });
      const spec: [string, string, string, string[]][] = [
        ["pkg-a", "low", "npm", ["x"]],
        ["pkg-b", "critical", "npm", ["x", "y", "z"]],
        ["pkg-c", "medium", "python", ["x", "y"]],
        ["pkg-d", "high", "npm", ["x"]],
        ["pkg-e", "high", "npm", ["x", "y"]],
      ];
      for (const [i, [pkg, severity, type, vulns]] of spec.entries()) {
        for (const v of vulns) {
          await addFinding(i % 2 === 0 ? repoA : repoB, {
            pkg,
            version: "1.0.0",
            fixedIn: ["1.0.1"],
            severity,
            type,
            vuln: `CVE-2099-${pkg}-${v}`,
            locations: type === "python" ? ["/requirements.txt"] : ["/package-lock.json"],
          });
        }
      }
      const all = async (s: string) =>
        itemsOf(await call("GET", `/api/v1/fixes?pageSize=100&q=pkg-&${s}`)).map((i) => i.packageName);
      expect(await all("")).toEqual(["pkg-b", "pkg-e", "pkg-d", "pkg-c", "pkg-a"]);
      expect(await all("sort=severity&dir=desc")).toEqual(["pkg-a", "pkg-c", "pkg-d", "pkg-e", "pkg-b"]);
      expect(await all("sort=package")).toEqual(["pkg-a", "pkg-b", "pkg-c", "pkg-d", "pkg-e"]);
      expect(await all("sort=package&dir=desc")).toEqual(["pkg-e", "pkg-d", "pkg-c", "pkg-b", "pkg-a"]);
      expect(await all("sort=vulnerabilities")).toEqual(["pkg-b", "pkg-c", "pkg-e", "pkg-a", "pkg-d"]);
      expect((await all("sort=repository")).slice(0, 3)).toEqual(["pkg-a", "pkg-c", "pkg-e"]);
      expect((await all("sort=ecosystem"))[4]).toBe("pkg-c");
      expect(await all("sort=status")).toHaveLength(5);

      // Cursors: forward through the list, then back.
      const page = async (cursor?: string) =>
        (
          await call(
            "GET",
            `/api/v1/fixes?pageSize=25&q=pkg-&sort=package${cursor ? `&cursor=${cursor}` : ""}`,
          )
        ).json as Json;
      const seen: string[] = [];
      let cursor: string | undefined;
      // pageSize 25 is the smallest; seed enough rows to need more than one page.
      for (let i = 0; i < 30; i++) {
        await addFinding(repoA, {
          pkg: `pkg-z${String(i).padStart(2, "0")}`,
          version: "1.0.0",
          fixedIn: ["1.0.1"],
          severity: "low",
        });
      }
      for (let guard = 0; guard < 5; guard++) {
        const p = await page(cursor);
        seen.push(...(p.items as Json[]).map((i) => i.packageName));
        expect(p.total).toBe(35);
        if (!p.next) break;
        cursor = p.next as string;
      }
      expect(seen).toHaveLength(35);
      expect(seen).toEqual([...seen].sort());
      const second = await page(((await page()).next as string) ?? undefined);
      expect((second.items as Json[]).length).toBe(10);
      expect(second.prev).toBeTruthy();
      const back = await page(second.prev as string);
      expect((back.items as Json[]).map((i) => i.packageName)).toEqual(
        (await page()).items.map((i: Json) => i.packageName),
      );
      expect(back.prev).toBeNull();
      expect((await call("GET", "/api/v1/fixes?cursor=not-a-cursor")).status).toBe(400);
    });

    it("shows the pull request of a proposal and lets a finished one be asked again", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const first = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items[0] as Json;
      expect(first).toMatchObject({ writeAccess: "on", creatable: true, pr: null });
      await t.db.insert(schema.fixPr).values({
        id: "fpr_fx_open",
        organizationId: ORG,
        repositoryId: repo,
        proposalKey: first.key,
        ecosystem: "npm",
        packageName: "lodash",
        fromVersion: "4.17.20",
        toVersion: "4.17.21",
        manifestPath: "package.json",
        expectedBlobSha: MANIFEST_SHA,
        severity: "critical",
        vulnerabilityIds: first.vulnerabilityIds,
        state: "open",
        branch: "garnetops/fix-lodash-4.17.21",
        prNumber: 7,
        prUrl: "https://git.example.lan/team/app/pulls/7",
        requestedBy: "user_b",
      });
      const open = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items[0] as Json;
      expect(open.pr).toMatchObject({
        state: "open",
        number: 7,
        requestedBy: "Max Example",
        url: "https://git.example.lan/team/app/pulls/7",
      });
      expect(open.creatable).toBe(false);
      expect((await call("GET", `/api/v1/fixes?repositoryId=${repo}&pr=open`)).json?.total).toBe(1);
      expect((await call("GET", `/api/v1/fixes?repositoryId=${repo}&pr=none`)).json?.total).toBe(0);
      await t.db.update(schema.fixPr).set({ state: "closed" }).where(eq(schema.fixPr.id, "fpr_fx_open"));
      const closed = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items[0] as Json;
      expect(closed.pr?.state).toBe("closed");
      expect(closed.creatable).toBe(true);
    });

    it("adds the AI suggestion as read-only text, but takes the version from the vulnerability data", async () => {
      const repo = await editableRepo();
      const [finding] = await t.db.select().from(schema.finding).where(eq(schema.finding.repositoryId, repo));
      await t.db
        .insert(schema.chatThread)
        .values({ id: "thr_fx00000000000000001", organizationId: ORG, findingId: finding?.id as string });
      await t.db.insert(schema.chatMessage).values({
        id: "msg_fx1",
        threadId: "thr_fx00000000000000001",
        role: "assistant",
        kind: "triage",
        content: "{}",
        status: "complete",
        structured: {
          summary: "Reachable through the merge helper.",
          recommendation: "Update and run the tests.",
          confidence: "high",
          upgradeTo: "9.9.9",
        },
      });
      const item = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items[0] as Json;
      expect(item.aiSuggestion).toMatchObject({
        summary: "Reachable through the merge helper.",
        recommendation: "Update and run the tests.",
        confidence: "high",
        upgradeTo: "9.9.9",
      });
      expect(item.targetVersion).toBe("4.17.21");
      expect(item.newSpec).toBe("^4.17.21");
    });
  });

  describe("write access", () => {
    const enable = (extra: Record<string, unknown> = {}) => ({
      token: TOKEN,
      forgeKind: "gitea",
      apiBaseUrl: "https://git.example.lan/api/v1",
      ...extra,
    });

    it("is for owners and admins to switch on or off, with a recent sign-in; everybody can look", async () => {
      const repo = await addRepo();
      for (const role of ["viewer", "member"] as Role[]) {
        expect(
          (await call("PUT", `/api/v1/repositories/${repo}/write-access`, { role, body: enable() })).status,
        ).toBe(403);
        expect((await call("DELETE", `/api/v1/repositories/${repo}/write-access`, { role })).status).toBe(
          403,
        );
        expect((await call("POST", `/api/v1/repositories/${repo}/write-access/check`, { role })).status).toBe(
          403,
        );
        expect((await call("GET", `/api/v1/repositories/${repo}/write-access`, { role })).status).toBe(200);
      }
      const stale = await call("PUT", `/api/v1/repositories/${repo}/write-access`, {
        age: STALE,
        body: enable(),
      });
      expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
      const staleOff = await call("DELETE", `/api/v1/repositories/${repo}/write-access`, { age: STALE });
      expect([staleOff.status, problemCode(staleOff)]).toEqual([403, "step-up-required"]);
      expect(
        await t.db
          .select()
          .from(schema.repositoryWriteAccess)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repo)),
      ).toEqual([]);
      expect(queue.sent).toEqual([]);
      for (const role of ["admin", "owner"] as Role[]) {
        const r = await call("PUT", `/api/v1/repositories/${repo}/write-access`, { role, body: enable() });
        expect(r.status, role).toBe(200);
      }
    });

    it("seals the token for this organisation, record and purpose, and keeps it out of every answer, row and audit entry", async () => {
      const repo = await addRepo();
      const r = await call("PUT", `/api/v1/repositories/${repo}/write-access`, { body: enable() });
      expect(r.status).toBe(200);
      expect(r.text).not.toContain(TOKEN);
      expect(r.json).toMatchObject({
        enabled: true,
        supported: true,
        access: {
          forgeKind: "gitea",
          apiBaseUrl: "https://git.example.lan/api/v1",
          status: "unchecked",
          enabledBy: "Erika Example",
        },
      });
      const [access] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, access?.secretId as string));
      expect(secret).toMatchObject({
        organizationId: ORG,
        purpose: "forge-write-token",
        createdBy: "user_a",
      });
      expect(JSON.stringify(secret?.sealed)).not.toContain(TOKEN);
      const priv = loadVaultPrivateKey(queue.vault?.privateKeyPem as string);
      const binding = {
        organizationId: ORG,
        recordId: secret?.id as string,
        purpose: "forge-write-token" as const,
      };
      expect(open(secret?.sealed as never, binding, priv).toString("utf8")).toBe(TOKEN);
      // Copied to another record, organisation or purpose, it does not open.
      expect(() => open(secret?.sealed as never, { ...binding, organizationId: OTHER }, priv)).toThrow();
      expect(() => open(secret?.sealed as never, { ...binding, recordId: "sec_other" }, priv)).toThrow();
      expect(() => open(secret?.sealed as never, { ...binding, purpose: "forge-token" }, priv)).toThrow();
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, repo));
      expect(audit.map((a) => a.action)).toEqual(["fix_pr.write_access_enabled"]);
      expect(JSON.stringify(audit)).not.toContain(TOKEN);
      expect(audit[0]).toMatchObject({ actorUserId: "user_a", organizationId: ORG, ip: "198.51.100.7" });
      expect(queue.sent).toEqual([
        { name: "fix-pr.check", data: { repositoryId: repo }, options: expect.any(Object) },
      ]);
      // Not even a repository read shows more than the state.
      const detail = await call("GET", `/api/v1/repositories/${repo}`);
      expect(detail.text).not.toContain(TOKEN);
      expect(detail.json?.writeAccess).toMatchObject({ enabled: true, access: { forgeKind: "gitea" } });
      expect(detail.json?.writeAccess.access).not.toHaveProperty("secretId");
    });

    it("replacing the token deletes the old one for good", async () => {
      const repo = await addRepo();
      await call("PUT", `/api/v1/repositories/${repo}/write-access`, { body: enable() });
      const [before] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      await t.db
        .update(schema.repositoryWriteAccess)
        .set({ status: "failed", statusReason: "token-rejected" })
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      const r = await call("PUT", `/api/v1/repositories/${repo}/write-access`, {
        body: enable({ token: `${TOKEN}-new` }),
      });
      expect(r.status).toBe(200);
      expect(r.json?.access.status).toBe("unchecked");
      const [after] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      expect(after?.secretId).not.toBe(before?.secretId);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, before?.secretId as string)),
      ).toEqual([]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, repo));
      expect(audit.map((a) => a.action)).toEqual([
        "fix_pr.write_access_enabled",
        "fix_pr.write_token_replaced",
      ]);
    });

    it("switching off deletes the sealed token and the access", async () => {
      const repo = await addRepo();
      await call("PUT", `/api/v1/repositories/${repo}/write-access`, { body: enable() });
      const [access] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      const r = await call("DELETE", `/api/v1/repositories/${repo}/write-access`);
      expect(r.status).toBe(204);
      expect(
        await t.db
          .select()
          .from(schema.repositoryWriteAccess)
          .where(eq(schema.repositoryWriteAccess.repositoryId, repo)),
      ).toEqual([]);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, access?.secretId as string)),
      ).toEqual([]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, repo));
      expect(audit.map((a) => a.action)).toContain("fix_pr.write_access_disabled");
      expect((await call("DELETE", `/api/v1/repositories/${repo}/write-access`)).status).toBe(204);
      expect((await call("GET", `/api/v1/repositories/${repo}/write-access`)).json).toMatchObject({
        enabled: false,
        access: null,
      });
    });

    it("deleting the repository deletes the write token too", async () => {
      const repo = await addRepo();
      await call("PUT", `/api/v1/repositories/${repo}/write-access`, { body: enable() });
      const [access] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      expect((await call("DELETE", `/api/v1/repositories/${repo}`)).status).toBe(204);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, access?.secretId as string)),
      ).toEqual([]);
    });

    it("validates the token, the forge and the API address; a bad request is not a step-up demand", async () => {
      const repo = await addRepo();
      const put = (body: unknown, extra: { age?: number } = {}) =>
        call("PUT", `/api/v1/repositories/${repo}/write-access`, { body, ...extra });
      for (const body of [
        enable({ token: "short" }),
        enable({ token: "has a space in it" }),
        enable({ token: `line\nbreak${TOKEN}` }),
        enable({ token: "x".repeat(501) }),
        enable({ forgeKind: "gitlab" }),
        enable({ apiBaseUrl: "http://git.example.lan/api/v1" }),
        enable({ apiBaseUrl: "https://git.example.lan/api/v3" }),
        enable({ apiBaseUrl: "https://localhost/api/v1" }),
        enable({ apiBaseUrl: "https://169.254.169.254/api/v1" }),
        enable({ apiBaseUrl: "https://user:pw@git.example.lan/api/v1" }),
        enable({ forgeKind: "github", apiBaseUrl: "https://git.example.lan/api/v1" }),
        {},
      ]) {
        const r = await put(body, { age: STALE });
        expect(r.status, JSON.stringify(body).slice(0, 80)).toBe(422);
      }
      expect(
        await t.db.select().from(schema.secret).where(eq(schema.secret.purpose, "forge-write-token")),
      ).not.toContainEqual(expect.objectContaining({ organizationId: OTHER }));
      expect((await put(enable({ forgeKind: "forgejo" }))).status).toBe(200);
    });

    it("derives the API address from the repository host when none is given", async () => {
      const gh = await addRepo({ url: "https://github.com/team/app.git" });
      const detail = await call("GET", `/api/v1/repositories/${gh}/write-access`);
      expect(detail.json?.suggested).toEqual({ forgeKind: "github", apiBaseUrl: "https://api.github.com" });
      const r = await call("PUT", `/api/v1/repositories/${gh}/write-access`, {
        body: { token: TOKEN, forgeKind: "github" },
      });
      expect(r.json?.access).toMatchObject({ forgeKind: "github", apiBaseUrl: "https://api.github.com" });
      const ghe = await addRepo({ url: "git@ghe.example.lan:team/app.git", authKind: "ssh-deploy-key" });
      const r2 = await call("PUT", `/api/v1/repositories/${ghe}/write-access`, {
        body: { token: TOKEN, forgeKind: "github" },
      });
      expect(r2.json?.access.apiBaseUrl).toBe("https://ghe.example.lan/api/v3");
    });

    it("refuses a repository address that names no owner and repository", async () => {
      const repo = await addRepo({ url: "https://git.example.lan/a/b/c/d.git" });
      // Too many segments are read as a path prefix; one segment is not a repository.
      const odd = await addRepo({ url: "https://git.example.lan/onlyone" });
      expect((await call("GET", `/api/v1/repositories/${odd}/write-access`)).json).toMatchObject({
        supported: false,
        suggested: null,
      });
      const r = await call("PUT", `/api/v1/repositories/${odd}/write-access`, { body: enable() });
      expect([r.status, problemCode(r)]).toEqual([422, "unsupported-repository"]);
      expect(repo).toBeTruthy();
    });

    it("keeps organisations apart", async () => {
      const repo = await addRepo();
      for (const [method, body] of [
        ["GET", undefined],
        ["PUT", enable()],
        ["DELETE", undefined],
      ] as [string, unknown][]) {
        expect(
          (await call(method, `/api/v1/repositories/${repo}/write-access`, { org: OTHER, body })).status,
          method,
        ).toBe(404);
      }
      expect(
        (await call("POST", `/api/v1/repositories/${repo}/write-access/check`, { org: OTHER })).status,
      ).toBe(404);
    });

    it("a check needs the access to exist and queues the worker", async () => {
      const repo = await addRepo();
      expect((await call("POST", `/api/v1/repositories/${repo}/write-access/check`)).status).toBe(409);
      await addAccess(repo, { status: "failed", statusReason: "token-rejected" });
      expect((await call("POST", `/api/v1/repositories/${repo}/write-access/check`)).status).toBe(202);
      expect(queue.sent.map((s) => s.name)).toEqual(["fix-pr.check"]);
      const [access] = await t.db
        .select()
        .from(schema.repositoryWriteAccess)
        .where(eq(schema.repositoryWriteAccess.repositoryId, repo));
      expect(access).toMatchObject({ status: "unchecked", statusReason: null });
    });

    it("limits how often it can be changed", async () => {
      const repo = await addRepo();
      let last = 200;
      for (let i = 0; i < 12; i++)
        last = (await call("PUT", `/api/v1/repositories/${repo}/write-access`, { body: enable() })).status;
      expect(last).toBe(429);
    });
  });

  describe("creating a pull request", () => {
    const create = (
      repositoryId: string,
      key: string,
      extra: { role?: Role; age?: number; org?: string; user?: string } = {},
    ) => call("POST", "/api/v1/fixes/prs", { body: { repositoryId, key }, ...extra });
    const firstKey = async (repo: string) =>
      itemsOf(await call("GET", `/api/v1/fixes?repositoryId=${repo}`))[0]?.key as string;

    it("queues the worker, stores the request from our own data, and audits", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const key = await firstKey(repo);
      const r = await create(repo, key);
      expect(r.status).toBe(202);
      const id = r.json?.id as string;
      const [row] = await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.id, id));
      expect(row).toMatchObject({
        organizationId: ORG,
        repositoryId: repo,
        proposalKey: key,
        ecosystem: "npm",
        packageName: "lodash",
        fromVersion: "4.17.20",
        toVersion: "4.17.21",
        manifestPath: "package.json",
        expectedBlobSha: MANIFEST_SHA,
        severity: "critical",
        state: "queued",
        requestedBy: "user_a",
        majorUpgrade: false,
      });
      expect(queue.sent).toEqual([
        { name: "fix-pr.create", data: { fixPrId: id }, options: expect.objectContaining({ retryLimit: 0 }) },
      ]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({
        action: "fix_pr.created",
        actorUserId: "user_a",
        organizationId: ORG,
        targetType: "fix_pr",
      });
      expect(audit[0]?.data).toMatchObject({
        package: "lodash",
        from: "4.17.20",
        to: "4.17.21",
        manifest: "package.json",
        forge: "gitea",
      });
      // The list now shows it as being created, and a second click is refused.
      const item = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items[0] as Json;
      expect(item.pr).toMatchObject({ state: "queued" });
      expect(item.creatable).toBe(false);
      const again = await create(repo, key);
      expect([again.status, problemCode(again)]).toEqual([409, "already-open"]);
      expect(queue.sent).toHaveLength(1);
    });

    it("lets owners, admins and members click, never viewers", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const key = await firstKey(repo);
      const viewer = await create(repo, key, { role: "viewer" });
      expect([viewer.status, problemCode(viewer)]).toEqual([403, "forbidden"]);
      expect(await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.repositoryId, repo))).toEqual([]);
      expect((await create(repo, key, { role: "member" })).status).toBe(202);
      // Each role gets its own repository so the live-request rule does not interfere.
      for (const role of ["admin", "owner"] as Role[]) {
        const other = await editableRepo();
        await addAccess(other);
        expect((await create(other, await firstKey(other), { role })).status, role).toBe(202);
      }
    });

    it("needs a recent sign-in", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const r = await create(repo, await firstKey(repo), { age: STALE });
      expect([r.status, problemCode(r)]).toEqual([403, "step-up-required"]);
      expect(await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.repositoryId, repo))).toEqual([]);
      expect(queue.sent).toEqual([]);
    });

    it("only where write access is on and works", async () => {
      const repo = await editableRepo();
      const key = await firstKey(repo);
      const off = await create(repo, key);
      expect([off.status, problemCode(off)]).toEqual([409, "write-access-off"]);
      await addAccess(repo, { status: "failed", statusReason: "token-rejected" });
      const failed = await create(repo, key);
      expect([failed.status, problemCode(failed)]).toEqual([409, "write-access-failed"]);
      expect(failed.json?.reason).toBe("token-rejected");
      expect(queue.sent).toEqual([]);
    });

    it("only for proposals GarnetOps can carry out, computed here and not taken from the client", async () => {
      const repo = await addRepo();
      await addAccess(repo);
      await addFinding(repo, { pkg: "transitive-only", version: "1.0.0", fixedIn: ["1.0.1"] });
      await addFinding(repo, { pkg: "range", version: "1.5.0", fixedIn: ["2.0.0"] });
      await addManifest(repo, "package.json", "npm", [{ name: "range", spec: ">=1 <3" }]);
      const items = (await call("GET", `/api/v1/fixes?repositoryId=${repo}`)).json?.items as Json[];
      for (const item of items) {
        const r = await create(repo, item.key);
        expect([r.status, problemCode(r)], item.packageName).toEqual([422, "not-editable"]);
        expect(r.json?.reason).toBe(item.reason);
      }
      const unknown = await create(repo, "0".repeat(24));
      expect(unknown.status).toBe(404);
      for (const bad of ["", "short", "x".repeat(24), "../../etc/passwd"]) {
        expect((await create(repo, bad)).status, bad).toBe(422);
      }
      // A client cannot name a version: the body is only repository and key.
      const editable = await editableRepo();
      await addAccess(editable);
      const r = await call("POST", "/api/v1/fixes/prs", {
        body: {
          repositoryId: editable,
          key: await firstKey(editable),
          toVersion: "9.9.9",
          manifestPath: "../../x",
        },
      });
      expect(r.status).toBe(202);
      const [row] = await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.id, r.json?.id));
      expect(row).toMatchObject({ toVersion: "4.17.21", manifestPath: "package.json" });
      expect(queue.sent).toHaveLength(1);
    });

    it("keeps organisations apart", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const key = await firstKey(repo);
      expect((await create(repo, key, { org: OTHER })).status).toBe(404);
      expect((await call("GET", "/api/v1/fixes/prs", { org: OTHER })).json?.items).toEqual([]);
    });

    it("is rate limited per person", async () => {
      const repo = await editableRepo();
      await addAccess(repo);
      const key = await firstKey(repo);
      let last = 0;
      for (let i = 0; i < 12; i++) last = (await create(repo, key)).status;
      expect(last).toBe(429);
      // Another person is not affected.
      expect((await create(repo, key, { user: "user_b" })).status).toBe(409);
    });
  });

  describe("creating a pull request through a connected account (ADR 0039)", () => {
    /** A connection on the repositories' forge (git.example.lan), checked by the worker, pull requests on. */
    async function addConnection(
      userId: string,
      overrides: Partial<typeof schema.forgeConnection.$inferInsert> = {},
    ): Promise<string> {
      const n = ++counter;
      const secretId = `sec_fxc${n}`;
      await t.db.insert(schema.secret).values({
        id: secretId,
        organizationId: overrides.organizationId ?? ORG,
        purpose: "forge-connection-token",
        sealed: {},
        vaultKeyId: "k",
      });
      const id = `fcn_fx${n}`;
      await t.db.insert(schema.forgeConnection).values({
        id,
        organizationId: ORG,
        userId,
        forgeKind: "gitea",
        webBaseUrl: "https://git.example.lan",
        apiBaseUrl: "https://git.example.lan/api/v1",
        secretId,
        accountLogin: userId === "user_a" ? "erika" : "max",
        state: "ok",
        pullRequests: true,
        pullRequestsAt: new Date(),
        ...overrides,
      });
      return id;
    }
    const viaConnection = (repositoryId: string, key: string, extra: { user?: string; age?: number } = {}) =>
      call("POST", "/api/v1/fixes/prs", {
        body: { repositoryId, key, via: "connection" },
        role: "member",
        ...extra,
      });
    const firstItem = async (repo: string, user = "user_a") =>
      itemsOf(await call("GET", `/api/v1/fixes?repositoryId=${repo}`, { user, role: "member" }))[0] as Json;

    beforeEach(async () => {
      await t.db.delete(schema.forgeConnection);
    });

    it("opens it in the caller's name with the caller's own connection, without a repository write token", async () => {
      const repo = await editableRepo();
      const mine = await addConnection("user_a");
      // Max's connection on the same forge is never a candidate for Erika.
      await addConnection("user_b");
      const item = await firstItem(repo);
      expect(item).toMatchObject({
        writeAccess: "off",
        creatable: false,
        creatableViaConnection: true,
        connection: { id: mine, forgeKind: "gitea", accountLogin: "erika" },
      });
      const r = await viaConnection(repo, item.key);
      expect(r.status).toBe(202);
      const [row] = await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.id, r.json?.id));
      expect(row).toMatchObject({
        state: "queued",
        requestedBy: "user_a",
        via: "connection",
        connectionId: mine,
        toVersion: "4.17.21",
      });
      expect(queue.sent).toEqual([
        {
          name: "fix-pr.create",
          data: { fixPrId: r.json?.id },
          options: expect.objectContaining({ retryLimit: 0 }),
        },
      ]);
      const audit = await t.db.select().from(schema.auditLog).where(eq(schema.auditLog.targetId, r.json?.id));
      expect(audit).toHaveLength(1);
      expect(audit[0]).toMatchObject({ action: "fix_pr.created", actorUserId: "user_a" });
      expect(audit[0]?.data).toMatchObject({ via: "connection", connection: mine, forge: "gitea" });
      // The list shows the pull request and how it was opened.
      const after = await firstItem(repo);
      expect(after.pr).toMatchObject({ state: "queued", via: "connection" });
      expect(after.creatableViaConnection).toBe(false);
      expect((await viaConnection(repo, item.key)).status).toBe(409);
    });

    it("never uses another person's connection: without an own one it is 409 no-connection", async () => {
      const repo = await editableRepo();
      const theirs = await addConnection("user_b");
      const item = await firstItem(repo);
      expect(item).toMatchObject({ connection: null, creatableViaConnection: false });
      // Max sees his own.
      expect((await firstItem(repo, "user_b")).connection).toMatchObject({ id: theirs, accountLogin: "max" });
      const r = await viaConnection(repo, item.key);
      expect([r.status, problemCode(r)]).toEqual([409, "no-connection"]);
      expect(await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.repositoryId, repo))).toEqual([]);
      // A connection on another forge does not count either.
      await addConnection("user_a", {
        webBaseUrl: "https://other.example.lan",
        apiBaseUrl: "https://other.example.lan/api/v1",
      });
      const other = await viaConnection(repo, item.key);
      expect([other.status, problemCode(other)]).toEqual([409, "no-connection"]);
      expect(queue.sent).toEqual([]);
    });

    it.each([
      [{ pullRequests: false, pullRequestsAt: null }, "connection-pull-requests-off"],
      [{ authMethod: "sign-in" as const, writeScope: false }, "connection-write-scope-missing"],
      [{ state: "failed" as const, problem: "token-rejected" }, "connection-failed"],
    ])("refuses an own connection that cannot open it (%o → %s)", async (overrides, code) => {
      const repo = await editableRepo();
      await addConnection("user_a", overrides);
      const item = await firstItem(repo);
      expect(item).toMatchObject({ connection: null, creatableViaConnection: false });
      const r = await viaConnection(repo, item.key);
      expect([r.status, problemCode(r)]).toEqual([409, code]);
      expect(queue.sent).toEqual([]);
    });

    it("needs a recent sign-in, like every pull request", async () => {
      const repo = await editableRepo();
      await addConnection("user_a");
      const r = await viaConnection(repo, (await firstItem(repo)).key, { age: STALE });
      expect([r.status, problemCode(r)]).toEqual([403, "step-up-required"]);
      expect(queue.sent).toEqual([]);
    });

    it("without via, the repository's write token is used as before, whatever connection the caller has", async () => {
      const repo = await editableRepo();
      await addConnection("user_a");
      const key = (await firstItem(repo)).key;
      const off = await call("POST", "/api/v1/fixes/prs", { body: { repositoryId: repo, key } });
      expect([off.status, problemCode(off)]).toEqual([409, "write-access-off"]);
      await addAccess(repo);
      const r = await call("POST", "/api/v1/fixes/prs", {
        body: { repositoryId: repo, key, via: "repository" },
      });
      expect(r.status).toBe(202);
      const [row] = await t.db.select().from(schema.fixPr).where(eq(schema.fixPr.id, r.json?.id));
      expect(row).toMatchObject({ via: "repository", connectionId: null });
      expect(
        (await call("POST", "/api/v1/fixes/prs", { body: { repositoryId: repo, key, via: "other" } })).status,
      ).toBe(422);
    });
  });

  describe("pull requests and refresh", () => {
    it("lists the pull requests, newest first, with filters", async () => {
      const repo = await editableRepo();
      for (const [i, state] of (["open", "merged", "failed"] as const).entries()) {
        await t.db.insert(schema.fixPr).values({
          id: `fpr_fxl${i}`,
          organizationId: ORG,
          repositoryId: repo,
          proposalKey: `${String(i).repeat(24)}`,
          ecosystem: "npm",
          packageName: `pkg${i}`,
          fromVersion: "1.0.0",
          toVersion: "1.0.1",
          manifestPath: "package.json",
          expectedBlobSha: MANIFEST_SHA,
          severity: "high",
          vulnerabilityIds: ["CVE-2099-0001"],
          state,
          reason: state === "failed" ? "manifest-changed" : null,
          requestedBy: "user_a",
          createdAt: new Date(Date.now() + i * 1000),
        });
      }
      const all = await call("GET", `/api/v1/fixes/prs?repositoryId=${repo}`);
      expect(itemsOf(all).map((i) => i.packageName)).toEqual(["pkg2", "pkg1", "pkg0"]);
      expect(all.json?.items[0]).toMatchObject({
        state: "failed",
        reason: "manifest-changed",
        requestedBy: "Erika Example",
      });
      expect(all.json?.total).toBe(3);
      const merged = await call("GET", `/api/v1/fixes/prs?repositoryId=${repo}&state=merged`);
      expect(itemsOf(merged).map((i) => i.packageName)).toEqual(["pkg1"]);
      expect((await call("GET", "/api/v1/fixes/prs?state=bogus")).status).toBe(422);
    });

    it("queues a refresh for members and above, limited per person", async () => {
      expect((await call("POST", "/api/v1/fixes/refresh", { role: "viewer", body: {} })).status).toBe(403);
      const r = await call("POST", "/api/v1/fixes/refresh", { role: "member", body: {} });
      expect(r.status).toBe(202);
      expect(queue.sent[0]).toMatchObject({ name: "fix-pr.refresh", data: { organizationId: ORG } });
      expect(
        (await call("POST", "/api/v1/fixes/refresh", { body: { repositoryId: "repo_nope" } })).status,
      ).toBe(404);
      expect(
        (await call("POST", "/api/v1/fixes/refresh", { org: OTHER, body: { repositoryId: "repo_nope" } }))
          .status,
      ).toBe(404);
    });
  });

  describe("Renovate configuration", () => {
    it("generates a renovate.json from the proposals of the repository", async () => {
      const repo = await addRepo();
      await addFinding(repo, { pkg: "lodash", version: "4.17.20", fixedIn: ["4.17.21"] });
      await addFinding(repo, {
        pkg: "requests",
        version: "2.25.0",
        fixedIn: ["2.31.0"],
        type: "python",
        locations: ["/requirements.txt"],
      });
      await addFinding(repo, {
        pkg: "jarlib",
        version: "1.0",
        fixedIn: ["1.1"],
        type: "java-archive",
        locations: ["/pom.xml"],
      });
      for (const role of ["viewer", "member"] as Role[]) {
        const r = await call("GET", `/api/v1/repositories/${repo}/renovate-config`, { role });
        expect(r.status).toBe(200);
        const config = JSON.parse(r.json?.json) as Json;
        expect(config.vulnerabilityAlerts.enabled).toBe(true);
        expect(
          config.packageRules.map((x: Json) => [
            x.matchManagers[0],
            x.matchPackageNames[0],
            x.allowedVersions,
          ]),
        ).toEqual([
          ["npm", "lodash", ">=4.17.21"],
          ["pip_requirements", "requests", ">=2.31.0"],
        ]);
        expect(r.json?.packages).toBe(2);
      }
      expect((await call("GET", `/api/v1/repositories/${repo}/renovate-config`, { org: OTHER })).status).toBe(
        404,
      );
    });
  });
});
