/**
 * Private repositories (ADR 0030) against a throw-away PostgreSQL database on the development server: a member's
 * private repository, its findings, scans, packages, gate runs and early warnings stay out of every list, count,
 * search and lookup of everybody else (admins included), until it is shared; sharing as a member is a request that
 * an admin decides; personal forge connections are their owner's alone, and the picker adds private repositories
 * from the stored list only. Sessions are replaced by a header-driven actor; the queue is a recorder. Skipped
 * without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const holder = vi.hoisted(() => ({
  db: null as unknown,
  sent: [] as { name: string; data: Record<string, unknown> }[],
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_visibility");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>) => {
        holder.sent.push({ name, data });
        return "job";
      },
    },
    QUEUES: {
      scanRepository: "scan.repository",
      fixPrCreate: "fix-pr.create",
      fixPrCheck: "fix-pr.check",
      fixPrRefresh: "fix-pr.refresh",
      forgeConnectionRefresh: "forge-connection.refresh",
    },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: load(gen().publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_vis";
/** Alex owns the private repository; Sam is another member; Kim is an admin. */
const ALEX = { user: "user_alex", role: "member" as Role };
const SAM = { user: "user_sam", role: "member" as Role };
const KIM = { user: "user_kim", role: "admin" as Role };
const TOKEN = ["glpat_", "NotARealTokenJustFixtureText0123"].join("");

describe.skipIf(!adminUrl)("private repositories and personal connections", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(
    method: string,
    path: string,
    who: { user: string; role: Role },
    body?: unknown,
  ): Promise<{ status: number; json: Json | null; text: string }> {
    const res = await app.request(path, {
      method,
      headers: {
        "x-user": who.user,
        "x-role": who.role,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json: Json | null = null;
    try {
      json = text ? (JSON.parse(text) as Json) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json, text };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const routes = {
      repositories: (await import("./repositories.ts")).repositoryRoutes,
      sharing: (await import("./sharing.ts")).repositorySharingRoutes,
      shareRequests: (await import("./sharing.ts")).shareRequestRoutes,
      findings: (await import("./findings.ts")).findingRoutes,
      scans: (await import("./scans.ts")).scanRoutes,
      search: (await import("./search.ts")).searchRoutes,
      statistics: (await import("./statistics.ts")).statisticsRoutes,
      overview: (await import("./overview.ts")).overviewRoutes,
      packages: (await import("./packages.ts")).packageRoutes,
      earlyWarnings: (await import("./early-warnings.ts")).earlyWarningRoutes,
      gates: (await import("./gates.ts")).gateRoutes,
      fixes: (await import("./fixes.ts")).fixRoutes,
      connections: (await import("./forge-connections.ts")).forgeConnectionRoutes,
      pullRequests: (await import("./pull-requests.ts")).pullRequestRoutes,
    };
    t = holder.db as TestDatabase;
    const d = t.db;
    await d.insert(schema.organization).values({ id: ORG, name: "Example" });
    await d.insert(schema.user).values([
      { id: ALEX.user, name: "Alex Example", email: "alex@example.test" },
      { id: SAM.user, name: "Sam Example", email: "sam@example.test" },
      { id: KIM.user, name: "Kim Example", email: "kim@example.test" },
    ]);
    await d.insert(schema.membership).values([
      { organizationId: ORG, userId: ALEX.user, role: "member" },
      { organizationId: ORG, userId: SAM.user, role: "member" },
      { organizationId: ORG, userId: KIM.user, role: "admin" },
    ]);
    await d.insert(schema.vulnerability).values({ id: "CVE-2099-0101", severity: "critical" });
    for (const [id, name, visibility] of [
      ["repo_shared", "shared-app", "organization"],
      ["repo_private", "secret-app", "private"],
    ] as const) {
      await d.insert(schema.repository).values({
        id,
        organizationId: ORG,
        name,
        url: `https://git.example.lan/team/${name}.git`,
        authKind: "none",
        visibility,
        ownerUserId: ALEX.user,
      });
      await d.insert(schema.scan).values({
        id: `scan_${id}`,
        organizationId: ORG,
        repositoryId: id,
        state: "succeeded",
        trigger: "manual",
        finishedAt: new Date(),
      });
      await d
        .update(schema.repository)
        .set({ lastScanId: `scan_${id}`, lastScanAt: new Date() })
        .where(eq(schema.repository.id, id));
      await d.insert(schema.finding).values({
        id: `fnd_${id}`,
        organizationId: ORG,
        repositoryId: id,
        vulnerabilityId: "CVE-2099-0101",
        dedupKey: id,
        packageName: `${name}-lib`,
        packageVersion: "1.0.0",
        packageType: "npm",
        severity: "critical",
        severityRank: 5,
        state: "open",
        fixedIn: ["1.0.1"],
        firstSeenScanId: `scan_${id}`,
        lastSeenScanId: `scan_${id}`,
        firstSeenAt: new Date(Date.now() - 3600_000),
        lastSeenAt: new Date(),
      });
      await d.insert(schema.repositoryPackage).values({
        id: `pkg_${id}`,
        organizationId: ORG,
        repositoryId: id,
        scanId: `scan_${id}`,
        name: `${name}-lib`,
        version: "1.0.0",
        type: "npm",
        purl: `pkg:npm/${name}-lib@1.0.0`,
      });
      await d.insert(schema.gateRun).values({
        id: `gate_${id}`,
        organizationId: ORG,
        repositoryId: id,
        scanId: `scan_${id}`,
        result: "blocked",
        matches: {},
      });
      await d.insert(schema.earlyWarning).values({
        id: `ew_${id}`,
        organizationId: ORG,
        repositoryId: id,
        vulnerabilityId: "CVE-2099-0101",
        packageName: `${name}-lib`,
        packageVersion: "1.0.0",
        packageType: "npm",
        severity: "critical",
        severityRank: 5,
      });
      await d.insert(schema.pullRequest).values({
        id: `pr_${id}`,
        organizationId: ORG,
        repositoryId: id,
        number: 1,
        title: `${name}: update dependencies`,
        url: `https://git.example.lan/team/${name}/pulls/1`,
        headSha: "c".repeat(40),
      });
    }

    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/repositories", routes.repositories as never);
    v1.route("/repositories/:id", routes.sharing as never);
    v1.route("/share-requests", routes.shareRequests as never);
    v1.route("/findings", routes.findings as never);
    v1.route("/scans", routes.scans as never);
    v1.route("/search", routes.search as never);
    v1.route("/statistics", routes.statistics as never);
    v1.route("/overview", routes.overview as never);
    v1.route("/packages", routes.packages as never);
    v1.route("/early-warnings", routes.earlyWarnings as never);
    v1.route("/gates", routes.gates as never);
    v1.route("/fixes", routes.fixes as never);
    v1.route("/forge-connections", routes.connections as never);
    v1.route("/pull-requests", routes.pullRequests as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);

  beforeEach(async () => {
    holder.sent.length = 0;
    await t.db.delete(schema.rateLimit);
  });

  /** Everything that names a repository in what a person can read, as one text. */
  async function everything(who: { user: string; role: Role }): Promise<string> {
    const paths = [
      "/api/v1/repositories",
      "/api/v1/repositories/counts",
      "/api/v1/findings?state=all",
      "/api/v1/findings/counts",
      "/api/v1/scans",
      "/api/v1/search?q=app",
      "/api/v1/statistics",
      "/api/v1/overview",
      "/api/v1/packages",
      "/api/v1/early-warnings",
      "/api/v1/gates/runs",
      "/api/v1/gates/latest",
      "/api/v1/fixes",
      "/api/v1/pull-requests",
      "/api/v1/pull-requests/sources",
    ];
    const texts: string[] = [];
    for (const path of paths) {
      const r = await call("GET", path, who);
      expect(r.status, path).toBe(200);
      texts.push(r.text);
    }
    return texts.join("\n");
  }

  it("keeps a private repository out of everything other people read, admins included", async () => {
    for (const who of [SAM, KIM]) {
      const text = await everything(who);
      expect(text).toContain("shared-app");
      expect(text).not.toMatch(/secret-app|repo_private|fnd_repo_private|scan_repo_private/);
    }
    const own = await everything(ALEX);
    expect(own).toContain("secret-app");
    const counts = await call("GET", "/api/v1/findings/counts", SAM);
    expect(counts.json?.open).toMatchObject({ critical: 1 });
    expect((await call("GET", "/api/v1/findings/counts", ALEX)).json?.open).toMatchObject({ critical: 2 });
  });

  it("answers 404 for the ids of someone else's private repository and what belongs to it", async () => {
    for (const path of [
      "/api/v1/repositories/repo_private",
      "/api/v1/repositories/repo_private/trend",
      "/api/v1/repositories/repo_private/patches",
      "/api/v1/findings/fnd_repo_private",
      "/api/v1/findings/fnd_repo_private/notes",
      "/api/v1/scans/scan_repo_private",
      "/api/v1/repositories/repo_private/write-access",
    ]) {
      expect((await call("GET", path, KIM)).status, path).toBe(404);
      expect((await call("GET", path, ALEX)).status, path).toBe(200);
    }
    expect((await call("POST", "/api/v1/repositories/repo_private/scans", SAM)).status).toBe(404);
    // Accepting someone else's private finding answers exactly like a finding that does not exist.
    const accept = (id: string) =>
      call("POST", `/api/v1/findings/${id}/accept`, SAM, {
        reason: "Accepted for this test only",
        until: new Date(Date.now() + 86_400_000).toISOString(),
      });
    expect((await accept("fnd_repo_private")).status).toBe((await accept("fnd_does_not_exist")).status);
    const [still] = await t.db.select().from(schema.finding).where(eq(schema.finding.id, "fnd_repo_private"));
    expect(still?.state).toBe("open");
    expect((await call("DELETE", "/api/v1/repositories/repo_private", KIM)).status).toBe(404);
    expect((await call("POST", "/api/v1/pull-requests/pr_repo_private/check", SAM)).status).toBe(404);
  });

  it("shares on request: a member asks, an admin sees only name and who asks, and approves", async () => {
    expect((await call("POST", "/api/v1/repositories/repo_private/share", SAM)).status).toBe(404);
    const asked = await call("POST", "/api/v1/repositories/repo_private/share", ALEX);
    expect(asked.json).toEqual({ visibility: "private", shareRequested: true });
    expect((await call("GET", "/api/v1/share-requests", SAM)).status).toBe(403);
    const list = await call("GET", "/api/v1/share-requests", KIM);
    expect(list.json).toEqual([
      {
        id: "repo_private",
        name: "secret-app",
        requestedAt: expect.any(String),
        requestedBy: "Alex Example",
      },
    ]);
    // Still private while it waits.
    expect(await everything(SAM)).not.toContain("secret-app");
    expect((await call("POST", "/api/v1/share-requests/repo_private/approve", KIM)).status).toBe(204);
    expect(await everything(SAM)).toContain("secret-app");
    const audit = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.targetId, "repo_private"));
    expect(audit.map((a) => a.action)).toEqual(["repository.share_requested", "repository.shared"]);

    // An admin can make it private again for its owner.
    expect((await call("POST", "/api/v1/repositories/repo_private/unshare", SAM)).status).toBe(403);
    expect((await call("POST", "/api/v1/repositories/repo_private/unshare", KIM)).json).toMatchObject({
      visibility: "private",
    });
    expect(await everything(SAM)).not.toContain("secret-app");
    expect(await everything(KIM)).not.toContain("secret-app");
  });

  it("keeps connections personal and adds picked repositories privately, from the stored list only", async () => {
    const created = await call("POST", "/api/v1/forge-connections", ALEX, {
      forgeKind: "gitea",
      webBaseUrl: "https://git.example.lan/",
      token: TOKEN,
    });
    expect(created.status).toBe(201);
    expect(created.json).toMatchObject({
      forgeKind: "gitea",
      webBaseUrl: "https://git.example.lan",
      apiBaseUrl: "https://git.example.lan/api/v1",
      state: "unchecked",
    });
    expect(created.text).not.toContain(TOKEN);
    const id = created.json?.id as string;
    expect(holder.sent).toEqual([
      {
        name: "forge-connection.refresh",
        data: { connectionId: id, organizationId: ORG, userId: ALEX.user },
      },
    ]);
    const [secret] = await t.db
      .select()
      .from(schema.secret)
      .where(eq(schema.secret.purpose, "forge-connection-token"));
    expect(JSON.stringify(secret?.sealed)).not.toContain(TOKEN);

    // Nobody else sees or uses it, admins included.
    expect((await call("GET", "/api/v1/forge-connections", KIM)).json).toEqual([]);
    for (const [method, path] of [
      ["GET", `/api/v1/forge-connections/${id}/repositories`],
      ["POST", `/api/v1/forge-connections/${id}/refresh`],
      ["DELETE", `/api/v1/forge-connections/${id}`],
    ] as const) {
      expect((await call(method, path, KIM)).status, path).toBe(404);
    }
    expect(
      (
        await call(
          "POST",
          "/api/v1/forge-connections",
          { user: "user_v", role: "viewer" },
          {
            forgeKind: "gitea",
            webBaseUrl: "https://git.example.lan",
            token: TOKEN,
          },
        )
      ).status,
    ).toBe(403);
    for (const webBaseUrl of [
      "http://git.example.lan",
      "https://169.254.169.254",
      "https://u:p@git.example.lan",
    ]) {
      const bad = await call("POST", "/api/v1/forge-connections", SAM, {
        forgeKind: "gitea",
        webBaseUrl,
        token: TOKEN,
      });
      expect(bad.status, webBaseUrl).toBe(422);
    }

    // The worker's list, as it would store it.
    await t.db.insert(schema.forgeConnectionRepository).values([
      {
        connectionId: id,
        forgeId: "11",
        fullName: "team/shared-app",
        cloneUrl: "https://git.example.lan/team/shared-app.git",
        private: false,
      },
      {
        connectionId: id,
        forgeId: "12",
        fullName: "team/new-app",
        cloneUrl: "https://git.example.lan/team/new-app.git",
        private: true,
        description: "<b>hi</b>",
      },
    ]);
    const list = await call("GET", `/api/v1/forge-connections/${id}/repositories`, ALEX);
    expect(list.json?.items).toEqual([
      expect.objectContaining({
        forgeId: "12",
        fullName: "team/new-app",
        added: null,
        description: "<b>hi</b>",
      }),
      expect.objectContaining({
        forgeId: "11",
        fullName: "team/shared-app",
        added: { repositoryId: "repo_shared" },
      }),
    ]);

    const picked = await call("POST", `/api/v1/forge-connections/${id}/repositories`, ALEX, {
      forgeIds: ["11", "12", "99"],
    });
    expect(picked.status).toBe(201);
    expect(picked.json?.created).toEqual([
      { id: expect.any(String), name: "new-app", scanId: expect.any(String) },
    ]);
    expect(picked.json?.skipped).toEqual(
      expect.arrayContaining([
        { forgeId: "99", reason: "unknown" },
        { forgeId: "11", reason: "duplicate" },
      ]),
    );
    const [repo] = await t.db.select().from(schema.repository).where(eq(schema.repository.name, "new-app"));
    expect(repo).toMatchObject({
      url: "https://git.example.lan/team/new-app.git",
      authKind: "connection",
      forgeConnectionId: id,
      visibility: "private",
      ownerUserId: ALEX.user,
    });
    expect(await everything(SAM)).not.toContain("new-app");

    // Removing the connection with its private repositories leaves no token behind.
    const removed = await call("DELETE", `/api/v1/forge-connections/${id}?removeRepositories=1`, ALEX);
    expect(removed.status).toBe(204);
    expect(await t.db.select().from(schema.repository).where(eq(schema.repository.name, "new-app"))).toEqual(
      [],
    );
    expect(
      await t.db.select().from(schema.secret).where(eq(schema.secret.purpose, "forge-connection-token")),
    ).toEqual([]);
  });
});
