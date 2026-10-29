/**
 * The host agent (ADR 0034) against a fake Docker API on a Unix socket, a stand-in syft and a fake GarnetOps that checks every
 * signature: the proxy forwards reads only, the agent enrols once and keeps its key to itself, reports the running containers with
 * their OCI labels only, and sends package lists only when asked.
 */
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSignedHeader, verifySignature } from "@garnetops/core/agent";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "./client.ts";
import { loadConfig } from "./config.ts";
import { allowed, serveProxy } from "./proxy.ts";
import { reportOnce } from "./report.ts";

const IMAGE = "a".repeat(64);
const IMAGE2 = "b".repeat(64);

describe("the proxy's list of reads", () => {
  it("allows GET and HEAD on the read paths only", () => {
    for (const [method, url] of [
      ["GET", "/_ping"],
      ["HEAD", "/_ping"],
      ["GET", "/version"],
      ["GET", "/info"],
      ["GET", "/containers/json"],
      ["GET", "/v1.47/containers/json?all=0"],
      ["GET", "/images/json"],
      [`GET`, `/images/sha256:${IMAGE}/json`],
      ["GET", "/images/ghcr.io/team/app:1.2/json"],
      ["GET", `/images/get?names=sha256%3A${IMAGE}`],
    ]) {
      expect(allowed(method, url), `${method} ${url}`).toBe(true);
    }
    for (const [method, url] of [
      ["POST", "/containers/create"],
      ["POST", "/images/create?fromImage=x"],
      ["DELETE", "/containers/abc"],
      ["POST", "/containers/abc/start"],
      ["POST", "/containers/abc/exec"],
      ["GET", "/containers/abc/logs"],
      ["GET", "/containers/abc/archive?path=/etc"],
      ["GET", "/secrets"],
      ["GET", "/images/../containers/json"],
      ["PUT", "/containers/json"],
      ["GET", undefined],
    ] as const) {
      expect(allowed(method, url), `${method} ${url}`).toBe(false);
    }
  });
});

describe("the agent's settings", () => {
  it("talks to GarnetOps over https only (http only under the test runner, when asked)", () => {
    expect(() => loadConfig({ GARNETOPS_URL: "http://garnetops.example.com" })).toThrow(/https/);
    expect(() => loadConfig({ GARNETOPS_URL: "https://user:pw@garnetops.example.com" })).toThrow(/plain/);
    expect(loadConfig({ GARNETOPS_URL: "https://garnetops.example.com" }).GARNETOPS_INTERVAL_HOURS).toBe(6);
    expect(
      loadConfig({
        GARNETOPS_URL: "http://127.0.0.1:1",
        NODE_ENV: "test",
        GARNETOPS_ALLOW_HTTP_FOR_TESTS: "1",
      }).GARNETOPS_URL,
    ).toBe("http://127.0.0.1:1");
  });
});

describe("reporting", () => {
  const work = mkdtempSync(join(tmpdir(), "garnetops-agent-test-"));
  const dockerSocket = join(work, "docker.sock");
  const proxySocket = join(work, "proxy", "docker.sock");
  const stateDir = join(work, "state");
  const dockerSaw: string[] = [];
  const serverSaw: { path: string; body: Record<string, unknown>; host: string | null }[] = [];
  let docker: HttpServer;
  let proxy: HttpServer;
  let garnet: HttpServer;
  let baseUrl = "";
  let publicKey = "";
  let need: string[] = [IMAGE];

  beforeAll(async () => {
    docker = createServer((req, res) => {
      dockerSaw.push(`${req.method} ${req.url}`);
      const json = (body: unknown) =>
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
      if (req.url === "/version") return json({ Version: "27.3.1", Os: "linux" });
      if (req.url === "/info")
        return json({
          OperatingSystem: "Ubuntu 24.04.1 LTS",
          OSVersion: "24.04",
          KernelVersion: "6.8.0-45-generic",
          Architecture: "x86_64",
          RegistryConfig: { Mirrors: ["https://mirror.example.lan"] },
          Name: "secret-host-name",
        });
      if (req.url === "/containers/json")
        return json([
          {
            Id: "1".repeat(64),
            Names: ["/app"],
            Image: "ghcr.io/team/app:1.2.3",
            ImageID: `sha256:${IMAGE}`,
            State: "running",
            Created: 1_790_000_000,
          },
          {
            Id: "2".repeat(64),
            Names: ["/db"],
            Image: "postgres:17",
            ImageID: `sha256:${IMAGE2}`,
            State: "running",
          },
        ]);
      if (req.url?.startsWith("/images/") && req.url.endsWith("/json")) {
        const id = req.url.includes(IMAGE) ? IMAGE : IMAGE2;
        return json({
          Id: `sha256:${id}`,
          RepoTags: [id === IMAGE ? "ghcr.io/team/app:1.2.3" : "postgres:17"],
          RepoDigests: [],
          Os: "linux",
          Architecture: "amd64",
          Created: "2026-10-01T10:00:00Z",
          Config: {
            Labels: {
              "org.opencontainers.image.source": "https://git.example.test/team/app",
              "com.example.db-password": "hunter2",
            },
          },
        });
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => docker.listen(dockerSocket, resolve));
    proxy = await serveProxy(dockerSocket, proxySocket);

    const readBody = (req: IncomingMessage) =>
      new Promise<string>((resolve) => {
        let s = "";
        req.on("data", (c) => (s += c));
        req.on("end", () => resolve(s));
      });
    garnet = createServer(async (req, res) => {
      const body = await readBody(req);
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const header = parseSignedHeader(req.headers.authorization);
      if (req.url === "/api/v1/agent/enrol") {
        publicKey = String(parsed.publicKey);
        serverSaw.push({ path: req.url, body: parsed, host: null });
        return void res.writeHead(201, { "content-type": "application/json" }).end('{"hostId":"hst_test1"}');
      }
      const ok =
        header &&
        verifySignature({
          publicKey,
          method: req.method ?? "",
          path: req.url ?? "",
          timestamp: header.timestamp,
          nonce: header.nonce,
          body,
          signature: header.signature,
        });
      if (!ok)
        return void res
          .writeHead(401, { "content-type": "application/json" })
          .end('{"type":"x/invalid-agent-signature"}');
      serverSaw.push({ path: req.url ?? "", body: parsed, host: header?.hostId ?? null });
      if (req.url === "/api/v1/agent/inventory") {
        return void res
          .writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify({ needPackages: need }));
      }
      res.writeHead(202, { "content-type": "application/json" }).end("{}");
    });
    await new Promise<void>((resolve) => garnet.listen(0, "127.0.0.1", resolve));
    baseUrl = `http://127.0.0.1:${(garnet.address() as AddressInfo).port}`;

    mkdirSync(join(work, "proc"));
    writeFileSync(
      join(work, "proc", "version"),
      "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) #45-Ubuntu SMP\n",
    );
    writeFileSync(join(work, "proc", "version_signature"), "Ubuntu 6.8.0-45.45-generic 6.8.12\n");
    // A stand-in syft: checks that it reads Docker through the proxy and writes a recorded SBOM.
    writeFileSync(
      join(work, "syft"),
      `#!/bin/sh\n[ "$DOCKER_HOST" = "unix://${proxySocket}" ] || exit 7\nout="\${4#syft-json=}"\ncat > "$out" <<'JSON'\n{"artifacts":[{"name":"openssl","version":"3.0.11-1","type":"deb","purl":"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12","locations":[{"path":"/var/lib/dpkg/status"}]},{"name":"no-purl","version":"1","type":"binary"}],"distro":{"prettyName":"Debian GNU/Linux 12 (bookworm)"}}\nJSON\n`,
      { mode: 0o755 },
    );
  });

  afterAll(async () => {
    for (const s of [docker, proxy, garnet])
      await new Promise<void>((resolve) => (s ? s.close(() => resolve()) : resolve()));
    rmSync(work, { recursive: true, force: true });
  });

  const deps = (over: Record<string, unknown> = {}) => ({
    server: new Server({ baseUrl }),
    stateDir,
    dockerSocket: proxySocket,
    syftBin: join(work, "syft"),
    procDir: join(work, "proc"),
    enrolmentCode: `goe_${"x".repeat(43)}`,
    hostName: "web-01",
    ...over,
  });

  it("enrols, keeps its private key in a 0600 file, and reports through the proxy", async () => {
    const result = await reportOnce(deps());
    expect(result).toEqual({ containers: 2, packageLists: 1 });
    expect(statSync(join(stateDir, "identity.json")).mode & 0o777).toBe(0o600);
    expect(serverSaw.map((s) => s.path)).toEqual([
      "/api/v1/agent/enrol",
      "/api/v1/agent/inventory",
      "/api/v1/agent/packages",
    ]);
    // The private key never left the host.
    expect(JSON.stringify(serverSaw)).not.toContain("PRIVATE KEY");
    const inventory = serverSaw[1]?.body as {
      containers: unknown[];
      images: { labels: Record<string, string> }[];
    };
    expect(inventory.containers).toHaveLength(2);
    // The host's kernel and distribution, and nothing else of Docker's description of the host.
    expect((inventory as unknown as { kernel: unknown }).kernel).toEqual({
      release: "6.8.0-45-generic",
      procVersion: "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) #45-Ubuntu SMP",
      versionSignature: "Ubuntu 6.8.0-45.45-generic 6.8.12",
      osName: "Ubuntu 24.04.1 LTS",
      osVersion: "24.04",
      architecture: "x86_64",
    });
    expect(JSON.stringify(inventory)).not.toContain("mirror.example.lan");
    expect(JSON.stringify(inventory)).not.toContain("secret-host-name");
    expect(inventory.images[0]?.labels).toEqual({
      "org.opencontainers.image.source": "https://git.example.test/team/app",
    });
    expect(JSON.stringify(inventory)).not.toContain("hunter2");
    const packages = serverSaw[2]?.body as { imageId: string; distro: string; packages: unknown[] };
    expect(packages).toEqual({
      imageId: IMAGE,
      distro: "Debian GNU/Linux 12 (bookworm)",
      packages: [
        {
          name: "openssl",
          version: "3.0.11-1",
          type: "deb",
          purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
        },
      ],
    });
    expect(JSON.stringify(packages)).not.toContain("/var/lib/dpkg");
    // Docker saw reads only.
    expect(dockerSaw.every((line) => line.startsWith("GET "))).toBe(true);
  });

  it("does not enrol again, and sends no package list when none is asked for", async () => {
    serverSaw.length = 0;
    need = [];
    const result = await reportOnce(deps({ enrolmentCode: undefined }));
    expect(result.packageLists).toBe(0);
    expect(serverSaw.map((s) => s.path)).toEqual(["/api/v1/agent/inventory"]);
    expect(serverSaw[0]?.host).toBe("hst_test1");
  });

  it("refuses writes on the proxy before they reach Docker", async () => {
    dockerSaw.length = 0;
    const { request } = await import("node:http");
    const status = await new Promise<number>((resolve) => {
      const req = request({ socketPath: proxySocket, method: "POST", path: "/containers/create" }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.end('{"Image":"alpine"}');
    });
    expect(status).toBe(403);
    expect(dockerSaw).toEqual([]);
  });
});
