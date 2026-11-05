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
    QUEUES: { imageMatch: "hosts.match", kernelMatch: "hosts.kernel", hostPackagesMatch: "hosts.packages" },
  };
});
/** Where the test puts a stand-in for the built systemd agent (ADR 0037). */
const BINS = vi.hoisted(() => `${process.env.TMPDIR ?? "/tmp"}/garnetops-agent-bins-${process.pid}`);
vi.mock("../env.ts", () => ({
  env: { PUBLIC_URL: "https://garnetops.example.test/", AGENT_BINARIES_DIR: BINS },
  isProduction: false,
}));
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

  it("names the running kernel as the distribution's package and queues its match only when it changed", async () => {
    const kernel = {
      release: "6.8.0-45-generic",
      versionSignature: "Ubuntu 6.8.0-45.45-generic 6.8.12",
      osName: "Ubuntu 24.04.1 LTS",
      osVersion: "24.04",
      architecture: "x86_64",
    };
    expect((await agent("/api/v1/agent/inventory", inventory({ kernel }))).status).toBe(200);
    const [host] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(host).toMatchObject({
      kernelRelease: "6.8.0-45-generic",
      osName: "Ubuntu 24.04.1 LTS",
      kernelProblem: null,
      kernelPackage: { name: "linux-image-6.8.0-45-generic", version: "6.8.0-45.45", distro: "ubuntu-24.04" },
    });
    expect(holder.sent.filter((s) => s.name === "hosts.kernel")).toEqual([
      { name: "hosts.kernel", data: { hostId } },
    ]);
    // The same kernel again: nothing to match.
    holder.sent.length = 0;
    await agent("/api/v1/agent/inventory", inventory({ kernel }));
    expect(holder.sent.filter((s) => s.name === "hosts.kernel")).toEqual([]);
    // A kernel that cannot be named is said so, not guessed.
    await agent("/api/v1/agent/inventory", inventory({ kernel: { ...kernel, versionSignature: null } }));
    const [unnamed] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(unnamed).toMatchObject({ kernelPackage: null, kernelProblem: "unknownVersion" });
    await agent("/api/v1/agent/inventory", inventory({ kernel }));
  });

  it("never checks the kernel of a host that is a container, and clears what an earlier report matched", async () => {
    const kernel = {
      release: "6.8.0-45-generic",
      versionSignature: "Ubuntu 6.8.0-45.45-generic 6.8.12",
      osName: "Ubuntu 24.04.1 LTS",
      osVersion: "24.04",
    };
    await agent("/api/v1/agent/inventory", inventory({ kernel }));
    await t.db
      .insert(schema.vulnerability)
      .values({ id: "CVE-2026-0019", severity: "high" })
      .onConflictDoNothing();
    const finding = {
      organizationId: ORG,
      hostId,
      vulnerabilityId: "CVE-2026-0019",
      packageName: "linux-image-6.8.0-45-generic",
      packageVersion: "6.8.0-45.45",
      severity: "high",
      severityRank: 4,
    };
    await t.db
      .insert(schema.hostKernelFinding)
      .values({ id: "hkf_container", ...finding, firstSeenAt: new Date(), lastSeenAt: new Date() });
    await t.db
      .insert(schema.runtimeEarlyWarning)
      .values({ id: "rew_container", ...finding, kind: "kernel", subjectId: hostId, packageType: "deb" });
    holder.sent.length = 0;
    // An old server ignores the field; this one stops matching the kernel and drops the earlier findings.
    expect(
      (await agent("/api/v1/agent/inventory", inventory({ kernel, insideContainer: "lxc" }))).status,
    ).toBe(200);
    const [host] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(host).toMatchObject({ kernelPackage: null, kernelProblem: "container", kernelMatchedAt: null });
    expect(
      await t.db.select().from(schema.hostKernelFinding).where(eq(schema.hostKernelFinding.hostId, hostId)),
    ).toEqual([]);
    expect(holder.sent.filter((s) => s.name === "hosts.kernel")).toEqual([]);
    const [warning] = await t.db
      .select()
      .from(schema.runtimeEarlyWarning)
      .where(eq(schema.runtimeEarlyWarning.id, "rew_container"));
    expect(warning?.state).toBe("cleared");
    // A Proxmox VE kernel reported by a Debian container (or a Docker agent in one) is never named as a Debian package.
    await agent(
      "/api/v1/agent/inventory",
      inventory({
        kernel: {
          release: "6.8.12-4-pve",
          procVersion:
            "Linux version 6.8.12-4-pve (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4",
          osName: "Debian GNU/Linux 12 (bookworm)",
          osVersion: "12",
        },
      }),
    );
    const [pve] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(pve).toMatchObject({ kernelPackage: null, kernelProblem: "proxmoxKernel" });
    await agent("/api/v1/agent/inventory", inventory({ kernel }));
  });

  it("takes the packages of the host itself from the systemd agent only when they changed, and shows their findings", async () => {
    const pkgs = [
      {
        name: "bash",
        version: "5.2.15-2+b7",
        type: "deb",
        purl: "pkg:deb/debian/bash@5.2.15-2+b7?arch=amd64&distro=debian-12",
      },
    ];
    const digest = "d".repeat(64);
    const first = await agent(
      "/api/v1/agent/inventory",
      inventory({ runtime: "systemd", hostPackagesDigest: digest }),
    );
    expect(first.json?.needHostPackages).toBe(true);
    const sent = await agent("/api/v1/agent/host-packages", { distro: "debian 12", digest, packages: pkgs });
    expect([sent.status, sent.json?.packages]).toEqual([202, 1]);
    expect(holder.sent).toContainEqual({ name: "hosts.packages", data: { hostId } });
    // The same list again is not asked for; a wrong digest format is refused.
    const again = await agent(
      "/api/v1/agent/inventory",
      inventory({ runtime: "systemd", hostPackagesDigest: digest }),
    );
    expect(again.json?.needHostPackages).toBe(false);
    expect((await agent("/api/v1/agent/host-packages", { digest: "x", packages: pkgs })).status).toBe(422);

    await t.db
      .insert(schema.vulnerability)
      .values({ id: "CVE-2026-0007", severity: "high" })
      .onConflictDoNothing();
    await t.db.insert(schema.hostPackageFinding).values({
      id: "hpf_1",
      organizationId: ORG,
      hostId,
      vulnerabilityId: "CVE-2026-0007",
      packageName: "bash",
      packageVersion: "5.2.15-2+b7",
      packageType: "deb",
      severity: "high",
      severityRank: 4,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    const list = await session("GET", "/api/v1/hosts", { role: "viewer" });
    expect(list.json?.[0]).toMatchObject({
      runtime: "systemd",
      hostPackages: { count: 1, distro: "debian 12", open: { high: 1 } },
    });
    const detail = await session("GET", `/api/v1/hosts/${hostId}`, { role: "viewer" });
    expect(
      (detail.json as unknown as { hostPackages: { findings: unknown[] } }).hostPackages.findings,
    ).toHaveLength(1);
    expect((await session("GET", "/api/v1/hosts/attention")).json).toMatchObject({ count: 1 });
    await t.db.delete(schema.hostPackageFinding);
  });

  it("keeps what the host's apt lists offer and says per finding what can be patched now", async () => {
    const recent = new Date(Date.now() - 3600_000).toISOString();
    const apt = {
      listsUpdatedAt: recent,
      arch: "amd64",
      sources: [
        {
          id: 0,
          host: "mirror.example.lan",
          path: "debian",
          suite: "bookworm",
          components: ["main"],
          origin: "Debian",
          codename: "bookworm",
          date: recent,
        },
        {
          id: 1,
          host: "mirror.example.lan",
          path: "debian-security",
          suite: "bookworm-security",
          components: ["main"],
          origin: "Debian",
          codename: "bookworm-security",
          date: recent,
        },
        {
          id: 2,
          host: "packages.sury.org",
          path: "php",
          suite: "bookworm",
          components: ["main"],
          origin: "deb.sury.org",
          date: recent,
        },
      ],
      packages: [
        {
          name: "bash",
          arch: "amd64",
          installed: "5.2.15-2+b7",
          from: [0],
          offers: [{ source: 1, version: "5.2.15-2+b8" }],
        },
        {
          name: "php8.2-cli",
          arch: "amd64",
          installed: "8.2.20-1+0~20240607.47+debian12~1.gbp1234",
          from: [2],
          offers: [],
        },
      ],
    };
    expect((await agent("/api/v1/agent/inventory", inventory({ runtime: "systemd", apt }))).status).toBe(200);
    const [stored] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(stored?.aptFacts?.sources).toHaveLength(3);
    expect(stored?.aptFactsAt).toBeInstanceOf(Date);

    await t.db
      .insert(schema.vulnerability)
      .values([
        { id: "CVE-2026-0201", severity: "high" },
        { id: "CVE-2026-0202", severity: "medium" },
      ])
      .onConflictDoNothing();
    const base = {
      organizationId: ORG,
      hostId,
      packageType: "deb",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    };
    await t.db.insert(schema.hostPackageFinding).values([
      {
        id: "hpf_apt_1",
        ...base,
        vulnerabilityId: "CVE-2026-0201",
        packageName: "bash",
        packageVersion: "5.2.15-2+b7",
        fixedIn: ["5.2.15-2+b8"],
        fixState: "fixed",
        severity: "high",
        severityRank: 4,
      },
      {
        id: "hpf_apt_2",
        ...base,
        vulnerabilityId: "CVE-2026-0202",
        packageName: "bash",
        packageVersion: "5.2.15-2+b7",
        fixedIn: ["5.2.15-2+b9"],
        fixState: "fixed",
        severity: "medium",
        severityRank: 3,
      },
    ]);
    const detail = await session("GET", `/api/v1/hosts/${hostId}`, { role: "viewer" });
    const packages = (detail.json as unknown as { hostPackages: Record<string, unknown> }).hostPackages as {
      findings: { vulnerabilityId: string; patch: { state: string; command: string | null } }[];
      patch: Record<string, unknown>;
    };
    expect(packages.findings.map((f) => [f.vulnerabilityId, f.patch.state, f.patch.command])).toEqual([
      ["CVE-2026-0201", "patchable-now", "sudo apt install --only-upgrade bash"],
      ["CVE-2026-0202", "waiting-for-mirror", null],
    ]);
    expect(packages.patch).toMatchObject({
      counts: { "patchable-now": 1, "waiting-for-mirror": 1 },
      listsAgeDays: 0,
      command: "sudo apt install --only-upgrade bash",
      hints: [
        {
          kind: "securityFromMirror",
          host: "mirror.example.lan",
          line: "deb http://deb.debian.org/debian-security bookworm-security main",
        },
      ],
      thirdParty: [{ origin: "deb.sury.org", packages: [{ name: "php8.2-cli" }] }],
      php: [{ version: "8.2.20", packages: ["php8.2-cli"] }],
    });
    // A report without the field (an older agent) leaves nothing stale behind; a broken one does not break the inventory.
    expect(
      (await agent("/api/v1/agent/inventory", inventory({ runtime: "systemd", apt: { sources: "x" } })))
        .status,
    ).toBe(200);
    const [cleared] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(cleared).toMatchObject({ aptFacts: null, aptFactsAt: null });
    await t.db.delete(schema.hostPackageFinding);
  });

  it("keeps the SSH server's facts, judges its configuration report-only (sshole aside), and still takes agents without them", async () => {
    const setting = (value: string, isDefault = false, match: string[] = []) => ({
      value,
      default: isDefault,
      match,
    });
    const sshd = (passwordAuthentication: string) => ({
      server: "openssh",
      package: { name: "openssh-server", version: "10.0_p1-r9" },
      libc: "musl",
      program: "/usr/sbin/sshd",
      pamLinked: false,
      config: {
        read: true,
        files: ["/etc/ssh/sshd_config"],
        skipped: [{ path: "/etc/ssh/sshd_config.d/local.conf", reason: "unreadable" }],
        settings: {
          passwordAuthentication: setting(passwordAuthentication, passwordAuthentication === "yes"),
          kbdInteractiveAuthentication: setting("yes", true),
          permitRootLogin: setting("prohibit-password", true, ["yes"]),
          usePam: setting("no", true),
          permitEmptyPasswords: setting("no", true),
          pubkeyAuthentication: setting("yes", true),
        },
      },
    });
    const attentionBefore = (await session("GET", "/api/v1/hosts/attention")).json;
    const sent = await agent(
      "/api/v1/agent/inventory",
      inventory({
        runtime: "systemd",
        serviceManager: "openrc",
        sshd: sshd("yes"),
        containers: [],
        images: [],
      }),
    );
    expect(sent.status).toBe(200);
    const [stored] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(stored).toMatchObject({
      serviceManager: "openrc",
      sshdFacts: { server: "openssh", libc: "musl" },
    });
    expect(stored?.sshdFactsAt).toBeInstanceOf(Date);

    type Ssh = {
      findings: { rule: string; severity: string; scope: string; basis?: string }[];
      pam: boolean | null;
      program: string | null;
    };
    const detail = async () =>
      (await session("GET", `/api/v1/hosts/${hostId}`, { role: "viewer" })).json as unknown as {
        serviceManager: string | null;
        ssh: Ssh | null;
        hostPackages: { findings: { id: string; severity: string; configurationNote: unknown }[] };
      };
    // The database does not know the CVE yet: the upstream version decides.
    let host = await detail();
    expect(host.serviceManager).toBe("openrc");
    expect(host.ssh?.pam).toBe(false);
    expect(host.ssh?.program).toBe("/usr/sbin/sshd");
    expect(host.ssh?.findings).toEqual([
      { rule: "sshole", severity: "critical", scope: "global", basis: "version" },
      { rule: "root-login", severity: "high", scope: "match" },
      { rule: "password-authentication", severity: "medium", scope: "global" },
    ]);
    // Configuration findings are report-only, but sshole counts in the menu while the database does not list it yet.
    const attention = (await session("GET", "/api/v1/hosts/attention")).json as unknown as {
      count: number;
      worst: string | null;
    };
    expect(attention.worst).toBe("critical");
    expect(attention.count).toBeGreaterThanOrEqual(1);
    expect((await session("GET", "/api/v1/hosts", { role: "viewer" })).json?.[0]).toMatchObject({
      serviceManager: "openrc",
    });

    // Once the database has the CVE and the host's openssh has the finding, the finding decides.
    await t.db
      .insert(schema.vulnerability)
      .values({ id: "CVE-2026-123158", severity: "critical" })
      .onConflictDoNothing();
    await t.db.insert(schema.hostPackageFinding).values({
      id: "hpf_sshole",
      organizationId: ORG,
      hostId,
      vulnerabilityId: "CVE-2026-123158",
      packageName: "openssh-server",
      packageVersion: "10.0_p1-r9",
      packageType: "apk",
      fixedIn: ["10.0_p1-r10"],
      fixState: "fixed",
      severity: "critical",
      severityRank: 5,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    host = await detail();
    expect(host.ssh?.findings[0]).toEqual({
      rule: "sshole",
      severity: "critical",
      scope: "global",
      basis: "finding",
    });
    expect(host.hostPackages.findings[0]).toMatchObject({ id: "hpf_sshole", configurationNote: null });

    // Password logins off: the finding stays critical, with a note why it cannot be used here.
    await agent(
      "/api/v1/agent/inventory",
      inventory({ runtime: "systemd", sshd: sshd("no"), containers: [], images: [] }),
    );
    host = await detail();
    expect(host.ssh?.findings.map((f) => f.rule)).toEqual(["root-login"]);
    expect(host.hostPackages.findings[0]).toMatchObject({
      id: "hpf_sshole",
      severity: "critical",
      configurationNote: { kind: "not-exploitable", reasons: ["password-authentication-off"] },
    });
    // The database knows the CVE and this host's packages were matched without a finding: a backported fix, nothing to say.
    await t.db.delete(schema.hostPackageFinding);
    await t.db
      .update(schema.agentHost)
      .set({ hostPackagesMatchedAt: new Date() })
      .where(eq(schema.agentHost.id, hostId));
    await agent(
      "/api/v1/agent/inventory",
      inventory({ runtime: "systemd", sshd: sshd("yes"), containers: [], images: [] }),
    );
    host = await detail();
    expect(host.ssh?.findings.map((f) => f.rule)).toEqual(["root-login", "password-authentication"]);
    // Neither the configuration nor a vulnerability finding counts now: the menu is as it was.
    expect((await session("GET", "/api/v1/hosts/attention")).json).toEqual(attentionBefore);

    // An older agent sends neither field; a broken field is dropped without failing the report.
    expect(
      (await agent("/api/v1/agent/inventory", inventory({ runtime: "systemd", sshd: { server: "telnet" } })))
        .status,
    ).toBe(200);
    const [cleared] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, hostId));
    expect(cleared).toMatchObject({ sshdFacts: null, sshdFactsAt: null, serviceManager: null });
    expect((await detail()).ssh).toBeNull();
    await t.db
      .update(schema.agentHost)
      .set({ hostPackagesMatchedAt: null })
      .where(eq(schema.agentHost.id, hostId));
  });

  it("serves the install script and the binaries it was built with, and no code in either", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const { createHash } = await import("node:crypto");
    await mkdir(BINS, { recursive: true });
    const bytes = Buffer.from("stand-in for the amd64 agent");
    await writeFile(`${BINS}/garnetops-agent-linux-amd64`, bytes);
    const sum = createHash("sha256").update(bytes).digest("hex");
    const script = await app.request("/api/v1/agent/install.sh");
    const text = await script.text();
    expect(script.status).toBe(200);
    expect(text).toContain("GARNETOPS_URL='https://garnetops.example.test'");
    expect(text).toContain(`SHA256_amd64='${sum}'`);
    expect(text).toContain("SHA256_arm64=''");
    expect(text).toContain("NoNewPrivileges=yes");
    // In a container the sandbox is tried before anything is installed; without it the script names the next step.
    expect(text).toContain("systemd-detect-virt --container");
    expect(text).toContain("-p PrivateTmp=yes -p PrivateDevices=yes");
    expect(text).toContain("Options > Features > Nesting");
    expect(text).toContain("OpenRC");
    expect(text).not.toMatch(/goe_[A-Za-z0-9_-]{43}/);
    const download = await app.request("/api/v1/agent/download/linux-amd64");
    expect(download.status).toBe(200);
    expect(download.headers.get("x-content-sha256")).toBe(sum);
    expect(Buffer.from(await download.arrayBuffer()).equals(bytes)).toBe(true);
    expect((await app.request("/api/v1/agent/download/linux-arm64")).status).toBe(404);
    expect((await app.request("/api/v1/agent/download/..%2F..%2Fetc%2Fpasswd")).status).toBe(404);
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
      kernel: { release: "6.8.0-45-generic", open: { critical: 0, total: 0 } },
      name: "Web 1",
      containers: 2,
      images: 2,
      open: { critical: 1 },
      reporting: true,
    });
    // The navigation counts the host: it runs an image with a critical vulnerability.
    const attention = await session("GET", "/api/v1/hosts/attention", { role: "viewer" });
    expect(attention.json).toEqual({ count: 1, worst: "critical" });

    await t.db.insert(schema.hostKernelFinding).values({
      id: "hkf_1",
      organizationId: ORG,
      hostId,
      vulnerabilityId: "CVE-2026-0001",
      packageName: "linux-image-6.8.0-45-generic",
      packageVersion: "6.8.0-45.45",
      fixState: "not-fixed",
      severity: "critical",
      severityRank: 5,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    const detail = await session("GET", `/api/v1/hosts/${hostId}`, { role: "viewer" });
    expect(
      (detail.json as unknown as { kernel: { release: string; findings: { fixState: string }[] } }).kernel,
    ).toMatchObject({
      release: "6.8.0-45-generic",
      package: { version: "6.8.0-45.45" },
      findings: [{ fixState: "not-fixed" }],
    });
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
      sync: { state: "unknown" },
    });
    // The running revision against the repository's scans: an earlier scanned commit is older, the last one is current, a
    // commit never scanned is different.
    const scanRow = (id: string, commitSha: string, finishedAt: string) => ({
      id,
      organizationId: ORG,
      repositoryId: "repo_agent_app",
      state: "succeeded" as const,
      trigger: "schedule" as const,
      branch: "main",
      commitSha,
      finishedAt: new Date(finishedAt),
    });
    await t.db
      .insert(schema.scan)
      .values([
        scanRow("scan_old", "0123456789abcdef0123456789abcdef01234567", "2026-10-01T00:00:00Z"),
        scanRow("scan_new", "fedcba9876543210fedcba9876543210fedcba98", "2026-10-29T00:00:00Z"),
      ]);
    const lastScan = (id: string) =>
      t.db
        .update(schema.repository)
        .set({ lastScanId: id })
        .where(eq(schema.repository.id, "repo_agent_app"));
    const syncOf = async () => {
      const list = (await session("GET", "/api/v1/hosts/by-repository/repo_agent_app")).json as unknown as {
        sync: unknown;
      }[];
      return list[0]?.sync;
    };
    await lastScan("scan_new");
    expect(await syncOf()).toMatchObject({
      state: "older",
      latest: { commit: "fedcba9876543210fedcba9876543210fedcba98", branch: "main" },
      runningScannedAt: "2026-10-01T00:00:00.000Z",
    });
    await lastScan("scan_old");
    expect(await syncOf()).toMatchObject({ state: "current" });
    await t.db.delete(schema.scan).where(eq(schema.scan.id, "scan_old"));
    await lastScan("scan_new");
    expect(await syncOf()).toMatchObject({ state: "different" });
    const detailSync = (await session("GET", `/api/v1/hosts/${hostId}`)).json as unknown as {
      containers: { name: string; sync: { state: string } | null }[];
    };
    expect(detailSync.containers.find((c) => c.name === "app")?.sync?.state).toBe("different");
    // Another organisation sees nothing of it.
    await setModule(OTHER, true);
    expect((await session("GET", "/api/v1/hosts/attention", { org: OTHER })).json).toEqual({
      count: 0,
      worst: null,
    });
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
