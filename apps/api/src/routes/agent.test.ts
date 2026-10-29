/**
 * The host agent API and the hosts pages (ADR 0034) against a throw-away PostgreSQL database: enrolment with a one-time code,
 * signed requests (wrong key, old time, replay, removed host), what an inventory and a package list store, the module switch, and
 * what signed-in people see (repository links only for visible repositories, enrolment codes only for admins). Skipped without
 * the development PostgreSQL.
 */
import { newAgentKeyPair, signRequest } from "@garnetops/core/agent";
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
  const t = await create(target, "api_agent");
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
    QUEUES: { imageMatch: "hosts.match" },
  };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

const ORG = "org_agent_a";
const OTHER = "org_agent_b";
const IMAGE = "a".repeat(64);
const IMAGE2 = "b".repeat(64);
const C1 = "1".repeat(64);
const C2 = "2".repeat(64);

describe.skipIf(!adminUrl)("host agent API (ADR 0034)", () => {
  let t: TestDatabase;
  let app: Hono;
  const keys = newAgentKeyPair();
  let hostId = "";

  async function session(
    method: string,
    path: string,
    opts: { role?: string; org?: string; age?: number; body?: unknown } = {},
  ) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-role": opts.role ?? "admin",
        "x-org": opts.org ?? ORG,
        "x-user": "user_alex",
        "x-age": String(opts.age ?? 0),
        ...(opts.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    return {
      status: res.status,
      json: text ? (JSON.parse(text) as Record<string, unknown> & unknown[]) : null,
    };
  }
  async function agent(
    path: string,
    body: unknown,
    opts: { host?: string; key?: string; now?: number; header?: string } = {},
  ) {
    const text = JSON.stringify(body);
    const header =
      opts.header ??
      signRequest({
        hostId: opts.host ?? hostId,
        privateKeyPem: opts.key ?? keys.privateKeyPem,
        method: "POST",
        path,
        body: text,
        now: opts.now,
      });
    const res = await app.request(path, {
      method: "POST",
      headers: { authorization: header, "content-type": "application/json" },
      body: text,
    });
    const out = await res.text();
    return { status: res.status, json: out ? (JSON.parse(out) as Record<string, unknown>) : null, header };
  }
  const code = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const setModule = (org: string, enabled: boolean) =>
    t.db
      .insert(schema.hostSettings)
      .values({ organizationId: org, enabled })
      .onConflictDoUpdate({ target: schema.hostSettings.organizationId, set: { enabled } });
  const inventory = (over: Record<string, unknown> = {}) => ({
    hostname: "web-01.example.lan",
    agentVersion: "0.0.12",
    dockerVersion: "27.3.1",
    os: "Debian GNU/Linux 12",
    containers: [
      {
        id: C1,
        name: "/app",
        image: "git.example.test/team/app:1.2.3",
        imageId: `sha256:${IMAGE}`,
        state: "running",
      },
      { id: C2, name: "/proxy", image: "caddy:2.8.4", imageId: `sha256:${IMAGE2}`, state: "running" },
    ],
    images: [
      {
        id: `sha256:${IMAGE}`,
        tags: ["git.example.test/team/app:1.2.3"],
        digests: [`git.example.test/team/app@sha256:${"c".repeat(64)}`],
        os: "linux",
        architecture: "amd64",
        labels: {
          "org.opencontainers.image.source": "https://git.example.test/team/app.git",
          "org.opencontainers.image.revision": "0123456789abcdef0123456789abcdef01234567",
          "com.example.password": "hunter2",
        },
      },
      { id: `sha256:${IMAGE2}`, tags: ["caddy:2.8.4"], digests: [], labels: {} },
    ],
    ...over,
  });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { agentRoutes } = await import("./agent.ts");
    const { hostRoutes } = await import("./hosts.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values([
      { id: "user_alex", name: "Alex Example", email: "alex@example.test" },
      { id: "user_sam", name: "Sam Example", email: "sam@example.test" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "alex@example.test",
          name: "Alex Example",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/hosts", hostRoutes as never);
    app = new Hono()
      .onError(handleError)
      .route("/api/v1/agent", agentRoutes as never)
      .route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(() => {
    holder.sent.length = 0;
  });

  it("enrols a host once with a code an admin created, only while the module is on", async () => {
    expect((await session("POST", "/api/v1/hosts/enrolments", { body: {} })).status).toBe(409);
    await setModule(ORG, true);
    expect((await session("POST", "/api/v1/hosts/enrolments", { role: "member", body: {} })).status).toBe(
      403,
    );
    const created = await session("POST", "/api/v1/hosts/enrolments", { body: { label: "Web 1" } });
    expect(created.status).toBe(201);
    const enrolment = created.json as unknown as { code: string; image: string; serverUrl: string };
    expect(enrolment.code).toMatch(/^goe_/);
    expect(enrolment.serverUrl).toBe("https://garnetops.example.test");
    expect(enrolment.image).toMatch(/^ghcr\.io\/lcsfls\/garnetops-agent:/);
    // Stored as a hash only.
    expect(JSON.stringify(await t.db.select().from(schema.agentEnrolment))).not.toContain(
      enrolment.code.slice(4),
    );
    expect((await session("GET", "/api/v1/hosts/enrolments")).json).toHaveLength(1);

    const body = {
      code: enrolment.code,
      publicKey: keys.publicKey,
      hostname: "web-01",
      agentVersion: "0.0.12",
    };
    // Switched off in between: the code stays unspent.
    await setModule(ORG, false);
    expect((await agent("/api/v1/agent/enrol", body, { header: "" })).status).toBe(409);
    await setModule(ORG, true);
    const ok = await agent("/api/v1/agent/enrol", body, { header: "" });
    expect(ok.status).toBe(201);
    hostId = String(ok.json?.hostId);
    expect(hostId).toMatch(/^hst_/);
    const again = await agent(
      "/api/v1/agent/enrol",
      { ...body, publicKey: newAgentKeyPair().publicKey },
      { header: "" },
    );
    expect([again.status, code(again)]).toEqual([401, "invalid-enrolment-code"]);
    const [host] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(host).toMatchObject({
      name: "Web 1",
      hostname: "web-01",
      publicKey: keys.publicKey,
      enrolledBy: "user_alex",
    });
    expect((await session("GET", "/api/v1/hosts/enrolments")).json).toHaveLength(0);
    const audits = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "host.enrolled"));
    expect(audits).toHaveLength(1);
  });

  it("refuses an expired code", async () => {
    const created = await session("POST", "/api/v1/hosts/enrolments", { body: {} });
    const { code: value, id } = created.json as unknown as { code: string; id: string };
    await t.db
      .update(schema.agentEnrolment)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(schema.agentEnrolment.id, id));
    const r = await agent(
      "/api/v1/agent/enrol",
      { code: value, publicKey: keys.publicKey, hostname: "x", agentVersion: "1" },
      { header: "" },
    );
    expect(r.status).toBe(401);
  });

  it("accepts only requests signed with the host's key, in time and once", async () => {
    const path = "/api/v1/agent/inventory";
    expect((await agent(path, inventory(), { key: newAgentKeyPair().privateKeyPem })).status).toBe(401);
    expect((await agent(path, inventory(), { now: Date.now() - 10 * 60_000 })).status).toBe(401);
    expect((await agent(path, inventory(), { header: "Bearer x" })).status).toBe(401);
    expect((await agent(path, inventory(), { host: "hst_unknown" })).status).toBe(401);
    const first = await agent(path, inventory());
    expect(first.status).toBe(200);
    // The same signed request again is a replay.
    const replay = await app.request(path, {
      method: "POST",
      headers: { authorization: first.header, "content-type": "application/json" },
      body: JSON.stringify(inventory()),
    });
    expect(replay.status).toBe(401);
    // A signature for another path does not open this one.
    const header = signRequest({
      hostId,
      privateKeyPem: keys.privateKeyPem,
      method: "POST",
      path: "/api/v1/agent/packages",
      body: JSON.stringify(inventory()),
    });
    expect((await agent(path, inventory(), { header })).status).toBe(401);
  });

  it("stores the inventory cleaned, links images by their source label and asks for missing packages", async () => {
    const r = await agent("/api/v1/agent/inventory", inventory());
    expect(r.status).toBe(200);
    expect([...((r.json?.needPackages as string[] | undefined) ?? [])].sort()).toEqual([IMAGE, IMAGE2]);
    const containers = await t.db
      .select()
      .from(schema.hostContainer)
      .where(eq(schema.hostContainer.hostId, hostId));
    expect(containers.map((c) => c.name).sort()).toEqual(["app", "proxy"]);
    const [image] = await t.db
      .select()
      .from(schema.containerImage)
      .where(eq(schema.containerImage.imageId, IMAGE));
    expect(image?.sourceKey).toBe("git.example.test/team/app");
    expect(JSON.stringify(image)).not.toContain("hunter2");

    // A container that stopped is gone at the next inventory.
    const next = inventory();
    next.containers = next.containers.slice(0, 1);
    expect((await agent("/api/v1/agent/inventory", next)).status).toBe(200);
    expect(
      await t.db.select().from(schema.hostContainer).where(eq(schema.hostContainer.hostId, hostId)),
    ).toHaveLength(1);
    await agent("/api/v1/agent/inventory", inventory());
  });

  it("takes the packages of an image this host runs, and queues the match", async () => {
    const pkgs = [
      {
        name: "openssl",
        version: "3.0.11-1",
        type: "deb",
        purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
      },
      {
        name: "openssl",
        version: "3.0.11-1",
        type: "deb",
        purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
      },
    ];
    const unknown = await agent("/api/v1/agent/packages", { imageId: "f".repeat(64), packages: pkgs });
    expect(unknown.status).toBe(404);
    const ok = await agent("/api/v1/agent/packages", { imageId: IMAGE, distro: "debian 12", packages: pkgs });
    expect(ok.status).toBe(202);
    expect(ok.json?.packages).toBe(1);
    expect(holder.sent).toEqual([{ name: "hosts.match", data: { organizationId: ORG, imageId: IMAGE } }]);
    const [image] = await t.db
      .select()
      .from(schema.containerImage)
      .where(eq(schema.containerImage.imageId, IMAGE));
    expect(image).toMatchObject({ distro: "debian 12", packageCount: 1 });
    // Known now: a second list for the same image is refused, and the next inventory asks only for the other image.
    const again = await agent("/api/v1/agent/packages", { imageId: IMAGE, packages: [] });
    expect([again.status, code(again)]).toEqual([409, "already-known"]);
    // Known now: the next inventory asks only for the other image.
    expect((await agent("/api/v1/agent/inventory", inventory())).json?.needPackages).toEqual([IMAGE2]);
  });

  it("shows hosts, containers and images; the repository link only to people who see the repository", async () => {
    await t.db.insert(schema.repository).values({
      id: "repo_agent_app",
      organizationId: ORG,
      name: "app",
      url: "https://git.example.test/team/app.git",
      authKind: "connection",
      visibility: "private",
      ownerUserId: "user_alex",
    });
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2026-0001", severity: "critical" });
    await t.db.insert(schema.containerImageFinding).values({
      id: "cif_1",
      organizationId: ORG,
      imageId: IMAGE,
      vulnerabilityId: "CVE-2026-0001",
      packageName: "openssl",
      packageVersion: "3.0.11-1",
      packageType: "deb",
      severity: "critical",
      severityRank: 5,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    const list = await session("GET", "/api/v1/hosts", { role: "viewer" });
    expect(list.status).toBe(200);
    expect(list.json?.[0]).toMatchObject({
      name: "Web 1",
      containers: 2,
      images: 2,
      open: { critical: 1 },
      reporting: true,
    });

    const detail = await session("GET", `/api/v1/hosts/${hostId}`, { role: "viewer" });
    const app1 = (
      detail.json as unknown as { containers: { name: string; repository: unknown }[] }
    ).containers.find((c) => c.name === "app");
    expect(app1?.repository).toEqual({ id: "repo_agent_app", name: "app" });
    // Sam does not see Alex's private repository.
    const asSam = await app.request(`/api/v1/hosts/images/${IMAGE}`, {
      headers: { "x-role": "admin", "x-org": ORG, "x-user": "user_sam", "x-age": "0" },
    });
    expect(((await asSam.json()) as { repository: unknown }).repository).toBeNull();
    const image = await session("GET", `/api/v1/hosts/images/${IMAGE}`);
    expect(image.json).toMatchObject({ repository: { id: "repo_agent_app" }, packageCount: 1 });
    expect((image.json as unknown as { findings: unknown[] }).findings).toHaveLength(1);
    const running = await session("GET", "/api/v1/hosts/by-repository/repo_agent_app");
    expect(running.json).toHaveLength(1);
    expect(running.json?.[0]).toMatchObject({
      name: "app",
      hostName: "Web 1",
      revision: "0123456789abcdef0123456789abcdef01234567",
    });
    // Another organisation sees nothing of it.
    await setModule(OTHER, true);
    expect((await session("GET", `/api/v1/hosts/${hostId}`, { org: OTHER })).status).toBe(404);
    expect((await session("GET", `/api/v1/hosts/images/${IMAGE}`, { org: OTHER })).status).toBe(404);
  });

  it("switches the registry check on only with an acknowledgement and a recent sign-in", async () => {
    expect(
      (await session("PUT", "/api/v1/hosts/settings", { body: { registryChecks: { enabled: true } } }))
        .status,
    ).toBe(422);
    expect(
      (
        await session("PUT", "/api/v1/hosts/settings", {
          age: 3600,
          body: { registryChecks: { enabled: true, acknowledged: true } },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await session("PUT", "/api/v1/hosts/settings", {
          body: { registryChecks: { enabled: true, acknowledged: true } },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        (await session("GET", "/api/v1/hosts/settings")).json as unknown as {
          registryChecks: { enabled: boolean };
        }
      ).registryChecks.enabled,
    ).toBe(true);
  });

  it("refuses the agent while the module is off, and for good once the host is removed", async () => {
    await setModule(ORG, false);
    expect((await agent("/api/v1/agent/inventory", inventory())).status).toBe(409);
    await setModule(ORG, true);
    expect((await session("DELETE", `/api/v1/hosts/${hostId}`, { role: "member" })).status).toBe(403);
    expect((await session("DELETE", `/api/v1/hosts/${hostId}`)).status).toBe(204);
    expect((await agent("/api/v1/agent/inventory", inventory())).status).toBe(401);
    // Its images went with it, no other host runs them.
    expect(
      await t.db.select().from(schema.containerImage).where(eq(schema.containerImage.organizationId, ORG)),
    ).toEqual([]);
    expect(await t.db.select().from(schema.containerImageFinding)).toEqual([]);
  });
});
