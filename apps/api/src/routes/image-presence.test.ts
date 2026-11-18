/**
 * Whether a repository finding's package is in a running image built from the repository (ADR 0054), against a throw-away
 * database on the development server: the list's mark and its two filters, the counts, the export, the detail with the containers
 * it rests on, what has no answer, and that nothing leaks between organisations. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "api_image_presence");
  holder.db = t;
  return { db: t.db, pool: t.pool };
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
const ORG = "org_ip_a";
const OTHER = "org_ip_b";
const NET = "golang.org/x/net";

describe.skipIf(!adminUrl)("a repository finding's package in a running image", () => {
  let t: TestDatabase;
  let app: Hono;
  let n = 0;

  async function get(path: string, org = ORG) {
    const res = await app.request(`/api/v1/findings${path}`, { headers: { "x-org": org } });
    const text = await res.text();
    return {
      status: res.status,
      text,
      json: (text.startsWith("{") ? JSON.parse(text) : null) as Json | null,
    };
  }
  const list = async (query = "", org = ORG) =>
    ((await get(`?pageSize=100${query}`, org)).json?.items ?? []) as Json[];
  const marks = async (query = "", org = ORG) =>
    Object.fromEntries((await list(query, org)).map((row) => [row.id, row.image]));

  const repo = (id: string, name: string, organizationId = ORG) =>
    t.db.insert(schema.repository).values({
      id,
      organizationId,
      name,
      url: `https://git.example.test/team/${name}.git`,
      authKind: "none",
    });
  const finding = (
    id: string,
    repositoryId: string,
    packageName: string,
    packageType: string,
    packageVersion: string,
    organizationId = ORG,
  ) =>
    t.db.insert(schema.finding).values({
      id,
      organizationId,
      repositoryId,
      vulnerabilityId: "CVE-2099-5000",
      dedupKey: id,
      packageName,
      packageVersion,
      packageType,
      fixedIn: ["9.9.9"],
      severity: "high",
      severityRank: 4,
      state: "open",
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
  const pkg = (name: string, version: string, type: string) => ({
    name,
    version,
    type,
    purl: `pkg:${type}/${name}@${version}`,
  });
  async function image(
    imageId: string,
    name: string,
    packages: ReturnType<typeof pkg>[] | null,
    organizationId = ORG,
  ) {
    await t.db.insert(schema.containerImage).values({
      organizationId,
      imageId,
      // The label an image carries: the address of the repository it was built from.
      sourceKey: `git.example.test/team/${name}`,
      packages,
      packagesAt: packages ? new Date() : null,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
  }
  const run = (hostId: string, name: string, imageId: string, organizationId = ORG) =>
    t.db.insert(schema.hostContainer).values({
      hostId,
      containerId: `c${++n}`,
      organizationId,
      name,
      imageRef: `registry.example.test/team/${name}:1`,
      imageId,
      state: "running",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
  const host = (id: string, name: string, organizationId = ORG) =>
    t.db.insert(schema.agentHost).values({
      id,
      organizationId,
      name,
      hostname: `${name}.example.lan`,
      publicKey: "k".repeat(43),
      enrolledAt: new Date(),
      lastSeenAt: new Date(),
    });
  const hosts = (enabled: boolean, organizationId = ORG) =>
    t.db
      .insert(schema.hostSettings)
      .values({ organizationId, enabled })
      .onConflictDoUpdate({ target: schema.hostSettings.organizationId, set: { enabled } });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { findingRoutes } = await import("./findings.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-5000", severity: "high" });
    await t.db.insert(schema.user).values({ id: "u", name: "Sam", email: "sam@example.com" });
    await hosts(true);
    await hosts(true, OTHER);

    // A Go service with a web front end: the image is the binary and static files, as in a "from scratch" build.
    await repo("repo_arrs", "arrs");
    await finding("fnd_net", "repo_arrs", NET, "go-module", "v0.60.0");
    await finding("fnd_compress", "repo_arrs", "github.com/example/compress", "go-module", "v1.20.0");
    await finding("fnd_kit", "repo_arrs", "@sveltejs/kit", "npm", "3.0.1");
    // Names differ in case between a lockfile and a package list; the image runs an older build.
    await finding("fnd_django", "repo_arrs", "Django", "python", "5.0.14");
    // The same name as another kind of package is another package.
    await finding("fnd_type", "repo_arrs", "certs", "npm", "1.0.0");
    await host("hst_ip1", "edge-1");
    await host("hst_ip2", "edge-2");
    await image("sha256:arrs1", "arrs", [
      pkg(NET, "v0.60.0", "go-module"),
      pkg("django", "5.0.10", "python"),
      pkg("certs", "2024.1", "deb"),
    ]);
    await image("sha256:arrs0", "arrs", []);
    await run("hst_ip1", "arrs", "sha256:arrs1");
    await run("hst_ip2", "arrs-old", "sha256:arrs0");
    // An image nobody runs is no evidence.
    await image("sha256:arrs-stale", "arrs", [pkg("github.com/example/compress", "v1.20.0", "go-module")]);

    // A repository no agent reports a container of, and one whose image is not read yet.
    await repo("repo_tool", "tool");
    await finding("fnd_tool", "repo_tool", NET, "go-module", "v0.60.0");
    await repo("repo_worker", "worker");
    await finding("fnd_worker", "repo_worker", NET, "go-module", "v0.60.0");
    await image("sha256:worker", "worker", null);
    await run("hst_ip1", "worker", "sha256:worker");

    // Another organisation with a repository at the same address, and its own image.
    await repo("repo_theirs", "arrs", OTHER);
    await finding("fnd_theirs", "repo_theirs", NET, "go-module", "v0.60.0", OTHER);
    await finding("fnd_theirs_kit", "repo_theirs", "@sveltejs/kit", "npm", "3.0.1", OTHER);

    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        { userId: "u", organizationId: c.req.header("x-org"), role: "viewer" } as never,
      );
      await next();
    });
    v1.route("/findings", findingRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("marks each finding of the list: in a running image, not in it, or no answer", async () => {
    expect(await marks()).toEqual({
      fnd_net: "in-image",
      fnd_django: "in-image",
      fnd_compress: "not-in-image",
      fnd_kit: "not-in-image",
      fnd_type: "not-in-image",
      // No container, or an image not read: no answer, never "not in the image".
      fnd_tool: null,
      fnd_worker: null,
    });
  });

  it("filters by it in the list, the counts and the export; findings without an answer are in neither", async () => {
    const ids = async (query: string) => (await list(query)).map((row) => row.id).sort();
    expect(await ids("&image=in")).toEqual(["fnd_django", "fnd_net"]);
    expect(await ids("&image=not-in")).toEqual(["fnd_compress", "fnd_kit", "fnd_type"]);
    expect(await ids("&image=in&q=django")).toEqual(["fnd_django"]);
    expect(await ids("&image=in&repositoryId=repo_tool")).toEqual([]);
    expect((await get("?image=maybe")).status).toBe(422);
    expect((await get("?image=in")).json?.total).toBe(2);

    expect((await get("/counts?image=in")).json?.states).toEqual({ open: 2, accepted: 0, resolved: 0 });
    expect((await get("/counts?image=not-in")).json?.open).toEqual({ high: 3 });
    expect((await get("/counts")).json?.states.open).toBe(7);

    const csv = await get("/export?format=csv&image=in");
    expect(csv.status).toBe(200);
    expect(csv.text).toContain(NET);
    expect(csv.text).not.toContain("@sveltejs/kit");
    const txt = await get("/export?format=txt&image=not-in");
    expect(txt.text).toContain("Only packages not found in the running images");
    expect(txt.text).toContain("@sveltejs/kit");
    expect(txt.text).not.toContain(NET);
  });

  it("shows on a finding the containers the answer rests on, with the version in each", async () => {
    const net = (await get("/fnd_net")).json?.image;
    expect(net).toMatchObject({ state: "in-image", reason: null, caveat: null });
    // Where it is comes first.
    expect(net.containers).toEqual([
      {
        hostId: "hst_ip1",
        hostName: "edge-1",
        name: "arrs",
        imageRef: "registry.example.test/team/arrs:1",
        read: true,
        version: "v0.60.0",
      },
      {
        hostId: "hst_ip2",
        hostName: "edge-2",
        name: "arrs-old",
        imageRef: "registry.example.test/team/arrs-old:1",
        read: true,
        version: null,
      },
    ]);
    // In the image in another version than the repository declares.
    const django = (await get("/fnd_django")).json?.image;
    expect(django.state).toBe("in-image");
    expect(django.containers[0].version).toBe("5.0.10");

    // A front-end package that is not installed in the image can still be compiled into its script files.
    const kit = (await get("/fnd_kit")).json?.image;
    expect(kit).toMatchObject({ state: "not-in-image", reason: null, caveat: "bundled" });
    expect(kit.containers.map((c: Json) => c.version)).toEqual([null, null]);
    expect((await get("/fnd_compress")).json?.image).toMatchObject({ state: "not-in-image", caveat: null });

    expect((await get("/fnd_tool")).json?.image).toEqual({
      state: null,
      reason: "no-image",
      caveat: null,
      containers: [],
    });
    const worker = (await get("/fnd_worker")).json?.image;
    expect(worker).toMatchObject({ state: null, reason: "not-read" });
    expect(worker.containers).toMatchObject([{ name: "worker", read: false, version: null }]);
  });

  it("keeps organisations apart, and has no answer while the Agents module is off", async () => {
    // The other organisation has a repository at the same address and no container of its own.
    expect(await marks("", OTHER)).toEqual({ fnd_theirs: null, fnd_theirs_kit: null });
    expect(await list("&image=in", OTHER)).toEqual([]);
    expect(await list("&image=not-in", OTHER)).toEqual([]);
    expect((await get("/fnd_theirs", OTHER)).json?.image).toMatchObject({ state: null, reason: "no-image" });
    expect((await get("/fnd_net", OTHER)).status).toBe(404);
    // With its own container it gets its own answer, from its own image.
    await host("hst_ip3", "theirs-1", OTHER);
    await image("sha256:theirs", "arrs", [pkg("@sveltejs/kit", "3.0.1", "npm")], OTHER);
    await run("hst_ip3", "arrs", "sha256:theirs", OTHER);
    expect(await marks("", OTHER)).toEqual({ fnd_theirs: "not-in-image", fnd_theirs_kit: "in-image" });
    expect((await marks()).fnd_kit).toBe("not-in-image");

    await hosts(false);
    expect(Object.values(await marks())).toEqual([null, null, null, null, null, null, null]);
    expect(await list("&image=in")).toEqual([]);
    expect(await list("&image=not-in")).toEqual([]);
    expect((await get("/fnd_net")).json?.image).toEqual({
      state: null,
      reason: "module-off",
      caveat: null,
      containers: [],
    });
    await hosts(true);
  });

  it("reads a package list that is not a list as not read, and changes no finding", async () => {
    await t.db
      .update(schema.containerImage)
      .set({ packages: sql`'{"name": "golang.org/x/net"}'::jsonb` })
      .where(eq(schema.containerImage.imageId, "sha256:arrs1"));
    // The other running image of the repository is read and empty.
    expect((await marks()).fnd_net).toBe("not-in-image");
    expect((await get("/fnd_net")).json?.image.containers.map((c: Json) => c.read)).toEqual([false, true]);
    expect((await list("&image=in")).map((row) => row.id)).toEqual([]);
    const states = await t.db.select({ state: schema.finding.state }).from(schema.finding);
    expect(new Set(states.map((s) => s.state))).toEqual(new Set(["open"]));
  });
});
