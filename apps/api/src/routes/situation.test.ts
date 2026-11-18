/**
 * The situation API (ADR 0052) against a throw-away database on the development server: one vulnerability across repositories,
 * running containers and hosts; what fixes each system; what could not be checked; private repositories (ADR 0030); and the hosts
 * module switched off. Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_situation");
  holder.db = t;
  return { db: t.db, pool: t.pool, QUEUES: {}, boss: null };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_sit";
const NGINX = "CVE-2099-1000";
const DJANGO = "CVE-2099-2000";
const KERNEL = "CVE-2099-3000";

describe.skipIf(!adminUrl)("situation API", () => {
  let t: TestDatabase;
  let app: Hono;
  let n = 0;

  async function get(path: string, user = "usr_sam") {
    const res = await app.request(`/api/v1/situation${path}`, {
      headers: { "x-org": ORG, "x-user": user },
    });
    const text = await res.text();
    return { status: res.status, json: (text.startsWith("{") ? JSON.parse(text) : null) as Json | null };
  }

  /** A list of the answer (`items` unless named), empty when the answer has none. */
  const list = (body: Json | null, key: "items" | "systems" | "notChecked" = "items") =>
    (body?.[key] ?? []) as Json[];

  async function repo(id: string, name: string, patch: Partial<typeof schema.repository.$inferInsert> = {}) {
    await t.db.insert(schema.repository).values({
      id,
      organizationId: ORG,
      name,
      url: `https://git.example.test/team/${name}.git`,
      authKind: "none",
      lastScanId: "scan_ok",
      ...patch,
    });
  }
  const finding = (repositoryId: string, vulnerabilityId: string, packageName: string, fixedIn: string[]) =>
    t.db.insert(schema.finding).values({
      id: `fnd_sit${++n}`,
      organizationId: ORG,
      repositoryId,
      vulnerabilityId,
      dedupKey: `sit-${n}`,
      packageName,
      packageVersion: "5.0.14",
      packageType: "python",
      fixedIn,
      severity: "high",
      severityRank: 4,
      state: "open",
      firstSeenScanId: "scan_ok",
      lastSeenScanId: "scan_ok",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
  async function host(id: string, name: string, patch: Partial<typeof schema.agentHost.$inferInsert> = {}) {
    await t.db.insert(schema.agentHost).values({
      id,
      organizationId: ORG,
      name,
      hostname: `${name}.example.lan`,
      publicKey: "k".repeat(43),
      enrolledAt: new Date(),
      lastSeenAt: new Date(),
      lastInventoryAt: new Date(),
      hostPackagesAt: new Date(),
      hostPackagesMatchedAt: new Date(),
      ...patch,
    });
  }
  async function container(hostId: string, name: string, imageId: string, imageRef: string) {
    await t.db.insert(schema.hostContainer).values({
      hostId,
      containerId: `c${++n}`,
      organizationId: ORG,
      name,
      imageRef,
      imageId,
      state: "running",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
  }
  async function image(imageId: string, patch: Partial<typeof schema.containerImage.$inferInsert> = {}) {
    await t.db.insert(schema.containerImage).values({
      organizationId: ORG,
      imageId,
      packages: [],
      packagesAt: new Date(),
      matchedAt: new Date(),
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      ...patch,
    });
  }
  const imageFinding = (
    imageId: string,
    vulnerabilityId: string,
    packageName: string,
    packageType: string,
    fixedIn: string[],
  ) =>
    t.db.insert(schema.containerImageFinding).values({
      id: `cif_sit${++n}`,
      organizationId: ORG,
      imageId,
      vulnerabilityId,
      packageName,
      packageVersion: "1.27.0",
      packageType,
      fixedIn,
      severity: "critical",
      severityRank: 5,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { situationRoutes } = await import("./situation.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.user).values([
      { id: "usr_sam", name: "Sam", email: "sam@example.com" },
      { id: "usr_alex", name: "Alex", email: "alex@example.com" },
    ]);
    await t.db.insert(schema.hostSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.vulnerability).values([
      { id: NGINX, severity: "critical", knownExploited: true, description: "A flaw in HTTP/2 handling." },
      { id: DJANGO, severity: "high" },
      { id: KERNEL, severity: "medium" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: "member",
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/situation", situationRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;

    // Repositories: a shared one that builds an image, Alex's private one, one never scanned, one whose last scan failed.
    await repo("repo_shop", "shop");
    await repo("repo_private", "alex-tool", { visibility: "private", ownerUserId: "usr_alex" });
    await repo("repo_new", "new-app", { lastScanId: null });
    await repo("repo_broken", "broken-app");
    await t.db.insert(schema.scan).values([
      {
        id: "scan_ok",
        organizationId: ORG,
        repositoryId: "repo_shop",
        state: "succeeded",
        trigger: "manual",
      },
      {
        id: "scan_bad",
        organizationId: ORG,
        repositoryId: "repo_broken",
        state: "failed",
        trigger: "manual",
      },
    ]);
    await finding("repo_shop", DJANGO, "django", ["5.2.8"]);
    await finding("repo_private", DJANGO, "django", ["5.2.8"]);

    // Hosts: one with nginx from apt and an old kernel, one that stopped reporting, one that reports no host packages.
    await host("agh_web", "web-1");
    await host("agh_old", "old-1", { lastInventoryAt: new Date(Date.now() - 3 * 86_400_000) });
    await host("agh_docker", "docker-1", { hostPackagesAt: null, hostPackagesMatchedAt: null });
    await t.db.insert(schema.hostPackageFinding).values({
      id: "hpf_sit1",
      organizationId: ORG,
      hostId: "agh_web",
      vulnerabilityId: NGINX,
      packageName: "nginx",
      packageVersion: "1.26.0-1",
      packageType: "deb",
      fixedIn: ["1.26.3-1"],
      severity: "critical",
      severityRank: 5,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    await t.db.insert(schema.hostKernelFinding).values({
      id: "hkf_sit1",
      organizationId: ORG,
      hostId: "agh_web",
      vulnerabilityId: KERNEL,
      packageName: "linux-image-amd64",
      packageVersion: "6.1.0-1",
      fixedIn: [],
      severity: "medium",
      severityRank: 3,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });

    // Containers on docker-1: the official nginx image, the shop's own image (built by repo_shop), Alex's image, one unchecked.
    await image("img_nginx");
    await image("img_shop", { sourceKey: "git.example.test/team/shop" });
    await image("img_alex", { sourceKey: "git.example.test/team/alex-tool" });
    await image("img_blank", { packages: null, matchedAt: null });
    await container("agh_docker", "proxy", "img_nginx", "nginx:1.27");
    await container("agh_docker", "shop-web", "img_shop", "registry.example.test/shop:1.4");
    await container("agh_docker", "alex-web", "img_alex", "registry.example.test/alex-tool:1");
    await container("agh_docker", "mystery", "img_blank", "registry.example.test/mystery:1");
    await imageFinding("img_nginx", NGINX, "nginx", "binary", ["1.27.4"]);
    await imageFinding("img_shop", NGINX, "nginx", "deb", ["1.26.3-1"]);
    await imageFinding("img_shop", DJANGO, "django", "python", ["5.2.8"]);
    await imageFinding("img_alex", DJANGO, "django", "python", ["5.2.8"]);
  });

  afterAll(async () => {
    await t?.drop();
  });

  it("lists each vulnerability once over repositories, containers and hosts, known exploited first", async () => {
    const { json } = await get("");
    expect(json?.counts).toEqual({ all: 3, exploited: 1, critical: 2, high: 0 });
    expect(
      list(json, "items").map((i) => [i.id, i.severity, i.repositories, i.containers, i.hosts, i.systems]),
    ).toEqual([
      [NGINX, "critical", 0, 2, 1, 3],
      // Sam does not see Alex's private repository, but its container is a system on a host everybody sees.
      [DJANGO, "critical", 1, 2, 0, 3],
      [KERNEL, "medium", 0, 0, 1, 1],
    ]);
    expect(json?.items[0]).toMatchObject({ knownExploited: true, fixKnown: true, packages: ["nginx"] });
    expect(json?.items[2]).toMatchObject({ fixKnown: false });
    expect((await get("?show=exploited")).json?.total).toBe(1);
    expect(list((await get("?q=django")).json).map((i) => i.id)).toEqual([DJANGO]);
    expect(list((await get("?kind=repository")).json).map((i) => i.id)).toEqual([DJANGO]);
    expect((await get("?cursor=x")).status).toBe(422);
    // Alex sees the private repository too.
    expect(list((await get("", "usr_alex")).json)[1]).toMatchObject({
      id: DJANGO,
      repositories: 2,
    });
  });

  it("says per system what fixes it: the server, the repository, or nobody yet", async () => {
    const { json } = await get(`/${NGINX}`);
    expect(json?.vulnerability).toMatchObject({ id: NGINX, severity: "critical", knownExploited: true });
    const systems = Object.fromEntries(list(json, "systems").map((s) => [`${s.kind}:${s.name}`, s]));
    // nginx from the host's package manager: an update on the server.
    expect(systems["host:web-1"]).toMatchObject({
      status: "affected",
      fixPath: "server-package",
      packages: [{ name: "nginx", version: "1.26.0-1", type: "deb", fixedIn: ["1.26.3-1"] }],
    });
    // The official image, built by nobody here: pull a newer one.
    expect(systems["container:proxy"]).toMatchObject({
      fixPath: "server-image",
      repository: null,
      host: { id: "agh_docker", name: "docker-1" },
      container: { imageRef: "nginx:1.27" },
    });
    // The shop's own image carries the distribution's nginx: its base image, a commit in the repository.
    expect(systems["container:shop-web"]).toMatchObject({
      fixPath: "repository-base-image",
      repository: { id: "repo_shop", name: "shop" },
    });
    expect(json?.counts).toMatchObject({
      affected: 3,
      notReachable: 0,
      byPath: { "server-package": 1, "server-image": 1, "repository-base-image": 1, vendor: 0 },
    });
  });

  it("lists what it could not check, and never counts it as checked", async () => {
    const { json } = await get(`/${NGINX}`);
    expect(
      list(json, "notChecked")
        .map((x) => [x.kind, x.name, x.reason])
        .sort(),
    ).toEqual(
      [
        ["container", "mystery (docker-1)", "image-not-checked"],
        ["host", "docker-1", "host-packages-not-reported"],
        ["host", "old-1", "not-reporting"],
        ["repository", "broken-app", "scan-failed"],
        ["repository", "new-app", "never-scanned"],
      ].sort(),
    );
    // Checked and without it: the shop repository and Alex's container. The private repository is not Sam's to count.
    expect(json?.counts).toMatchObject({ notChecked: 5, checked: 2 });
  });

  it("keeps a private repository out of other people's situation, and a flaw without a fix is nobody's action yet", async () => {
    const sam = (await get(`/${DJANGO}`)).json;
    const names = list(sam, "systems")
      .map((s) => `${s.kind}:${s.name}`)
      .sort();
    expect(names).toEqual(["container:alex-web", "container:shop-web", "repository:shop"]);
    expect(JSON.stringify(sam)).not.toContain('alex-tool"');
    const alexWeb = list(sam, "systems").find((s) => s.name === "alex-web");
    // Without the link to a repository Sam cannot see, the container reads as an image to pull.
    expect(alexWeb).toMatchObject({ repository: null, fixPath: "server-image" });
    const shopWeb = list(sam, "systems").find((s) => s.name === "shop-web");
    expect(shopWeb).toMatchObject({ fixPath: "repository-dependency", repository: { name: "shop" } });
    const alex = (await get(`/${DJANGO}`, "usr_alex")).json;
    expect(list(alex, "systems").find((s) => s.name === "alex-web")).toMatchObject({
      fixPath: "repository-dependency",
      repository: { id: "repo_private" },
    });
    expect(list(alex, "systems").some((s) => s.kind === "repository" && s.name === "alex-tool")).toBe(true);

    const kernel = (await get(`/${KERNEL}`)).json;
    expect(kernel?.systems).toHaveLength(1);
    expect(kernel?.systems[0]).toMatchObject({
      kind: "host",
      name: "web-1",
      kernel: true,
      fixPath: "vendor",
    });
    expect((await get("/CVE-2099-9999")).status).toBe(404);
    expect((await get("/..%2f..")).status).toBe(404);
  });

  it("leaves hosts and containers out while the hosts module is off", async () => {
    await t.db
      .update(schema.hostSettings)
      .set({ enabled: false })
      .where(eq(schema.hostSettings.organizationId, ORG));
    try {
      const { json } = await get("");
      expect(json?.hostsOn).toBe(false);
      expect(list(json, "items").map((i) => [i.id, i.systems])).toEqual([[DJANGO, 1]]);
      // A vulnerability only hosts have is not a page while they are off.
      expect((await get(`/${NGINX}`)).status).toBe(404);
    } finally {
      await t.db
        .update(schema.hostSettings)
        .set({ enabled: true })
        .where(eq(schema.hostSettings.organizationId, ORG));
    }
  });
});
