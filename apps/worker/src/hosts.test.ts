/**
 * Hosts and containers in the worker (ADR 0034) against a throw-away database: matching an image's package list with a stand-in
 * grype (findings replaced, the first sighting kept, nothing while the module is off), and the opt-in registry check against a
 * local HTTPS registry with a throw-away certificate that wants an anonymous token (a newer tag, a moved tag, errors as codes,
 * nothing while the check is off). Skipped without the development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-hosts-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_hosts";
const IMAGE = "a".repeat(64);
const DIGEST_OLD = `sha256:${"1".repeat(64)}`;
const DIGEST_NEW = `sha256:${"2".repeat(64)}`;

const report = (ids: string[]) => ({
  matches: ids.map((id) => ({
    vulnerability: {
      id,
      severity: id.endsWith("1") ? "Critical" : "Medium",
      fix: { versions: ["3.0.15-1"], state: "fixed" },
    },
    artifact: {
      name: "openssl",
      version: "3.0.11-1",
      type: "deb",
      purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
    },
  })),
  descriptor: { version: "0.120.1", db: { status: { built: "2026-10-29T04:00:00Z" } } },
});

describe.skipIf(!adminUrl || !openssl)("hosts and containers in the worker", () => {
  let t: TestDatabase;
  let hosts: typeof import("./hosts.ts");
  let registry: Server;
  let registryPort = 0;
  let registryCa = "";
  const asked: string[] = [];
  let tagsAnswer: unknown = { tags: ["1.27.3", "1.27.4", "1.28.0", "latest", "<script>"] };
  let manifestStatus = 200;

  beforeAll(async () => {
    const grype = join(work, "grype");
    writeFileSync(join(work, "report.json"), JSON.stringify(report(["CVE-2026-0001", "CVE-2026-0002"])));
    writeFileSync(
      join(work, "kernel.json"),
      JSON.stringify({
        matches: [
          {
            vulnerability: {
              id: "CVE-2026-0100",
              severity: "High",
              fix: { versions: [], state: "not-fixed" },
            },
            relatedVulnerabilities: [
              { id: "CVE-2026-0100", cvss: [{ version: "3.1", metrics: { baseScore: 9.8 } }] },
            ],
            artifact: {
              name: "linux-image-6.8.0-45-generic",
              version: "6.8.0-45.45",
              type: "deb",
              purl: "pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45?distro=ubuntu-24.04&upstream=linux",
            },
          },
        ],
        descriptor: { version: "0.120.1", db: { status: { built: "2026-10-29T04:00:00Z" } } },
      }),
    );
    writeFileSync(
      grype,
      `#!/bin/sh\ncase "$1" in purl:*) ;; *) exit 9;; esac\nif grep -q '^pkg:deb/ubuntu/linux-image' "\${1#purl:}"; then cp "${join(work, "kernel.json")}" "$5"; exit 0; fi\ngrep -q '^pkg:deb/debian/openssl@3.0.11-1?distro=debian-12$' "\${1#purl:}" || exit 8\ncp "${join(work, "report.json")}" "$5"\n`,
      { mode: 0o755 },
    );
    const keyFile = join(work, "vault.pem");
    writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    t = await createTestDatabase(adminUrl as string, "worker_hosts");
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: grype,
      GARNETOPS_GRYPE_DB_DIR: work,
      GARNETOPS_WORK_DIR: work,
    });
    delete process.env.GARNETOPS_SCANNER_SOCKET;
    hosts = await import("./hosts.ts");
    vi.spyOn(console, "error").mockImplementation(() => {});

    // A registry that wants an anonymous token from its token service, like Docker Hub.
    const key = join(work, "key.pem");
    const cert = join(work, "cert.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=registry.example.com",
        "-addext",
        "subjectAltName=DNS:registry.example.com,DNS:auth.example.com",
        "-keyout",
        key,
        "-out",
        cert,
      ],
      { stdio: "ignore" },
    );
    registryCa = readFileSync(cert, "utf8");
    registry = createServer({ key: readFileSync(key), cert: registryCa }, (req, res) => {
      asked.push(`${req.method} ${req.headers.host?.split(":")[0]}${req.url}`);
      if (req.url?.startsWith("/token")) {
        return void res.writeHead(200, { "content-type": "application/json" }).end('{"token":"anon-token"}');
      }
      if (req.headers.authorization !== "Bearer anon-token") {
        return void res
          .writeHead(401, {
            "www-authenticate":
              'Bearer realm="https://auth.example.com/token",service="registry.example.com"',
          })
          .end();
      }
      if (req.url?.includes("/manifests/")) {
        if (manifestStatus !== 200) return void res.writeHead(manifestStatus).end();
        return void res.writeHead(200, { "docker-content-digest": DIGEST_NEW }).end();
      }
      if (req.url?.includes("/tags/list")) {
        return void res
          .writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify(tagsAnswer));
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => registry.listen(0, "127.0.0.1", resolve));
    registryPort = (registry.address() as AddressInfo).port;
    hosts.setRegistryTestHooks({
      hooks: {
        lookup: (_host, _options, callback) =>
          (callback as (e: null, a: { address: string; family: number }[]) => void)(null, [
            { address: "127.0.0.1", family: 4 },
          ]),
        ca: registryCa,
        port: registryPort,
      },
      gapMs: 0,
    });

    await t.db.insert(schema.organization).values({ id: ORG, name: "Example" });
    await t.db.insert(schema.hostSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.agentHost).values({
      id: "hst_one",
      organizationId: ORG,
      name: "web-01",
      hostname: "web-01",
      publicKey: "k".repeat(43),
      enrolledAt: new Date(),
    });
    const now = new Date();
    await t.db.insert(schema.containerImage).values({
      organizationId: ORG,
      imageId: IMAGE,
      digests: [`registry.example.com/team/app@${DIGEST_OLD}`],
      packages: [
        {
          purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
          name: "openssl",
          version: "3.0.11-1",
          type: "deb",
        },
      ],
      packagesAt: now,
      firstSeenAt: now,
      lastSeenAt: now,
    });
    await t.db.insert(schema.hostContainer).values({
      hostId: "hst_one",
      containerId: "c".repeat(64),
      organizationId: ORG,
      name: "app",
      imageRef: "registry.example.com/team/app:1.27.3",
      imageId: IMAGE,
      state: "running",
      firstSeenAt: now,
      lastSeenAt: now,
    });
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    hosts?.setRegistryTestHooks(null);
    await new Promise<void>((resolve) => (registry ? registry.close(() => resolve()) : resolve()));
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  const findings = () =>
    t.db.select().from(schema.containerImageFinding).where(eq(schema.containerImageFinding.imageId, IMAGE));

  it("matches an image's packages and keeps the first sighting when it matches again", async () => {
    await hosts.matchImage({ organizationId: ORG, imageId: IMAGE });
    const first = await findings();
    expect(first.map((f) => [f.vulnerabilityId, f.severity]).sort()).toEqual([
      ["CVE-2026-0001", "critical"],
      ["CVE-2026-0002", "medium"],
    ]);
    const [image] = await t.db.select().from(schema.containerImage);
    expect(image?.matchedDbBuilt?.toISOString()).toBe("2026-10-29T04:00:00.000Z");
    expect(image?.matchError).toBeNull();

    // A newer database no longer lists the second one: it goes, the first keeps its first sighting.
    writeFileSync(join(work, "report.json"), JSON.stringify(report(["CVE-2026-0001"])));
    await hosts.matchImage({ organizationId: ORG, imageId: IMAGE });
    const second = await findings();
    expect(second.map((f) => f.vulnerabilityId)).toEqual(["CVE-2026-0001"]);
    expect(second[0]?.firstSeenAt.getTime()).toBe(
      first.find((f) => f.vulnerabilityId === "CVE-2026-0001")?.firstSeenAt.getTime(),
    );
  });

  it("matches the running kernel: affected, no fix yet, the distribution's rating and the highest score side by side", async () => {
    await t.db
      .update(schema.agentHost)
      .set({
        kernelRelease: "6.8.0-45-generic",
        kernelPackage: {
          purl: "pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45?distro=ubuntu-24.04&upstream=linux",
          name: "linux-image-6.8.0-45-generic",
          version: "6.8.0-45.45",
          type: "deb",
          distro: "ubuntu-24.04",
        },
      })
      .where(eq(schema.agentHost.id, "hst_one"));
    await hosts.matchKernel({ hostId: "hst_one" });
    const kernel = await t.db.select().from(schema.hostKernelFinding);
    expect(kernel).toHaveLength(1);
    expect(kernel[0]).toMatchObject({
      vulnerabilityId: "CVE-2026-0100",
      severity: "high",
      fixState: "not-fixed",
      fixedIn: [],
    });
    const [vuln] = await t.db
      .select()
      .from(schema.vulnerability)
      .where(eq(schema.vulnerability.id, "CVE-2026-0100"));
    expect(vuln?.cvssScore).toBe(9.8);
    const [host] = await t.db.select().from(schema.agentHost).where(eq(schema.agentHost.id, "hst_one"));
    expect(host?.kernelMatchedDbBuilt?.toISOString()).toBe("2026-10-29T04:00:00.000Z");
  });

  it("matches nothing while the module is off", async () => {
    await t.db.update(schema.hostSettings).set({ enabled: false });
    writeFileSync(join(work, "report.json"), JSON.stringify(report(["CVE-2026-0001", "CVE-2026-0003"])));
    await hosts.matchImage({ organizationId: ORG, imageId: IMAGE });
    expect((await findings()).map((f) => f.vulnerabilityId)).toEqual(["CVE-2026-0001"]);
    await t.db.update(schema.hostSettings).set({ enabled: true });
  });

  it("asks registries only when the check is on, with an anonymous token, and stores a newer tag and a moved tag", async () => {
    expect(await hosts.checkRegistries(ORG)).toBe(0);
    expect(asked).toEqual([]);
    await t.db.update(schema.hostSettings).set({ registryChecks: true });
    expect(await hosts.checkRegistries(ORG)).toBe(1);
    const [check] = await t.db.select().from(schema.imageUpdateCheck);
    expect(check).toMatchObject({
      ref: "registry.example.com/team/app:1.27.3",
      currentDigest: DIGEST_NEW,
      newerTag: "1.28.0",
      newerKind: "minor",
      error: null,
    });
    // The manifest was asked with HEAD (no pull counted), the token from the token service, only the two registry hosts.
    expect(asked).toContain("HEAD registry.example.com/v2/team/app/manifests/1.27.3");
    expect(
      asked.some((a) =>
        a.startsWith(
          "GET auth.example.com/token?service=registry.example.com&scope=repository%3Ateam%2Fapp%3Apull",
        ),
      ),
    ).toBe(true);
    expect(new Set(asked.map((a) => a.split(" ")[1]?.split("/")[0]))).toEqual(
      new Set(["registry.example.com", "auth.example.com"]),
    );
    // Asked again only a day later.
    asked.length = 0;
    expect(await hosts.checkRegistries(ORG)).toBe(0);
    expect(asked).toEqual([]);
  });

  it("stores errors as codes", async () => {
    manifestStatus = 429;
    await hosts.checkRegistries(ORG, new Date(Date.now() + 25 * 3600_000));
    const [check] = await t.db.select().from(schema.imageUpdateCheck);
    expect(check).toMatchObject({ error: "rateLimited", newerTag: null });
    manifestStatus = 200;
    tagsAnswer = { tags: "not a list" };
    await hosts.checkRegistries(ORG, new Date(Date.now() + 50 * 3600_000));
    const [again] = await t.db.select().from(schema.imageUpdateCheck);
    expect(again?.error).toBe("invalidResponse");
  });
});
