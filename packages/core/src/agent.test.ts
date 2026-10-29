import { describe, expect, it } from "vitest";
import {
  enrolmentCodeSchema,
  hashEnrolmentCode,
  inventorySchema,
  kernelPackage,
  newAgentKeyPair,
  newEnrolmentCode,
  newerTag,
  packagesSchema,
  parseImageRef,
  parseSignedHeader,
  parseVersionTag,
  signRequest,
  sourceKey,
  verifySignature,
} from "./agent.ts";

const ID = "a".repeat(64);

describe("enrolment codes", () => {
  it("are 256 random bits with a prefix, and only their hash is stored", () => {
    const code = newEnrolmentCode();
    expect(enrolmentCodeSchema.safeParse(code).success).toBe(true);
    expect(newEnrolmentCode()).not.toBe(code);
    expect(hashEnrolmentCode(code)).toMatch(/^[a-f0-9]{64}$/);
    expect(hashEnrolmentCode(code)).not.toContain(code.slice(4));
  });
});

describe("signed requests", () => {
  const keys = newAgentKeyPair();
  const sign = (body: string, now = 1_790_000_000_000) =>
    signRequest({
      hostId: "hst_abc",
      privateKeyPem: keys.privateKeyPem,
      method: "post",
      path: "/api/v1/agent/inventory",
      body,
      now,
    });

  it("verify with the host's public key, and only for this method, path, time, nonce and body", () => {
    const header = parseSignedHeader(sign('{"a":1}'));
    expect(header).toMatchObject({ hostId: "hst_abc", timestamp: 1_790_000_000_000 });
    const base = {
      publicKey: keys.publicKey,
      method: "POST",
      path: "/api/v1/agent/inventory",
      timestamp: header?.timestamp ?? 0,
      nonce: header?.nonce ?? "",
      body: '{"a":1}',
      signature: header?.signature ?? "",
    };
    expect(verifySignature(base)).toBe(true);
    expect(verifySignature({ ...base, body: '{"a":2}' })).toBe(false);
    expect(verifySignature({ ...base, path: "/api/v1/agent/packages" })).toBe(false);
    expect(verifySignature({ ...base, timestamp: base.timestamp + 1 })).toBe(false);
    expect(verifySignature({ ...base, nonce: "x".repeat(22) })).toBe(false);
    expect(verifySignature({ ...base, publicKey: newAgentKeyPair().publicKey })).toBe(false);
    expect(verifySignature({ ...base, publicKey: "not-a-key" })).toBe(false);
  });

  it("refuses headers that are not exactly ours", () => {
    const good = sign("");
    expect(parseSignedHeader(good)).not.toBeNull();
    expect(parseSignedHeader(`${good} `)).toBeNull();
    expect(parseSignedHeader(good.replace("hst_abc", "usr_abc"))).toBeNull();
    expect(parseSignedHeader("Bearer x")).toBeNull();
    expect(parseSignedHeader(undefined)).toBeNull();
  });

  it("uses a new nonce for every request", () => {
    expect(parseSignedHeader(sign(""))?.nonce).not.toBe(parseSignedHeader(sign(""))?.nonce);
  });
});

describe("what an agent reports", () => {
  it("keeps only five labels, cleans text and cuts it", () => {
    const parsed = inventorySchema.parse({
      hostname: "web-01\u0000\u001b[31m",
      agentVersion: "0.0.12",
      containers: [
        { id: ID, name: "/app", image: "ghcr.io/team/app:1.2.3", imageId: `sha256:${ID}`, state: "running" },
      ],
      images: [
        {
          id: `sha256:${ID}`,
          tags: ["ghcr.io/team/app:1.2.3"],
          labels: {
            "org.opencontainers.image.source": "https://git.example.com/team/app",
            "org.opencontainers.image.revision": "<script>x</script>",
            "com.example.secret": "PASSWORD=hunter2",
            maintainer: "someone",
          },
        },
      ],
    });
    expect(parsed.hostname).toBe("web-01 [31m");
    expect(parsed.containers[0]?.imageId).toBe(ID);
    expect(parsed.images[0]?.labels).toEqual({
      "org.opencontainers.image.source": "https://git.example.com/team/app",
      "org.opencontainers.image.revision": "<script>x</script>",
    });
    expect(JSON.stringify(parsed)).not.toContain("hunter2");
  });

  it("refuses ids that are not Docker ids and package URLs that are not package URLs", () => {
    expect(() =>
      inventorySchema.parse({
        hostname: "h",
        agentVersion: "1",
        containers: [],
        images: [{ id: "../../etc" }],
      }),
    ).toThrow();
    expect(() =>
      packagesSchema.parse({
        imageId: ID,
        packages: [{ name: "a", version: "1", type: "npm", purl: "javascript:x" }],
      }),
    ).toThrow();
    expect(
      packagesSchema.parse({
        imageId: ID,
        distro: "debian 12",
        packages: [
          {
            name: "openssl",
            version: "3.0.11-1",
            type: "deb",
            purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12",
          },
        ],
      }).packages,
    ).toHaveLength(1);
  });
});

describe("linking an image to a repository", () => {
  it("reduces repository URLs and source labels to the same key", () => {
    const key = "git.example.com/team/app";
    for (const value of [
      "https://git.example.com/team/app",
      "https://git.example.com/Team/App.git",
      "https://git.example.com:3000/team/app/",
      "http://git.example.com/team/app",
      "git@git.example.com:team/app.git",
      "ssh://git@git.example.com:2222/team/app.git",
    ]) {
      expect(sourceKey(value), value).toBe(key);
    }
    expect(sourceKey("https://git.example.com/group/sub/app")).toBe("git.example.com/group/sub/app");
  });

  it("is null for anything that is not a repository address", () => {
    for (const value of [
      null,
      "",
      "app",
      "https://example.com",
      "javascript:alert(1)",
      "file:///etc/passwd",
      "https://x/a/<b>",
    ]) {
      expect(sourceKey(value), String(value)).toBeNull();
    }
  });
});

describe("image references", () => {
  it("reads Docker Hub, other registries, tags and digests", () => {
    expect(parseImageRef("nginx")).toEqual({
      registry: "docker.io",
      repository: "library/nginx",
      tag: "latest",
      digest: null,
    });
    expect(parseImageRef("nginx:1.27-alpine")).toMatchObject({
      repository: "library/nginx",
      tag: "1.27-alpine",
    });
    expect(parseImageRef("grafana/grafana:11.2.0")).toMatchObject({
      registry: "docker.io",
      repository: "grafana/grafana",
    });
    expect(parseImageRef(`ghcr.io/team/app:v2@sha256:${ID}`)).toEqual({
      registry: "ghcr.io",
      repository: "team/app",
      tag: "v2",
      digest: `sha256:${ID}`,
    });
    expect(parseImageRef("registry.example.lan:5000/app:1.0")).toMatchObject({
      registry: "registry.example.lan:5000",
      repository: "app",
    });
    expect(parseImageRef(`app@sha256:${ID}`)).toMatchObject({ tag: null });
  });

  it("refuses what is not a reference", () => {
    for (const value of ["", "UPPER/case", "a b", "nginx:", `nginx@sha256:short`, "x".repeat(600)]) {
      expect(parseImageRef(value), value).toBeNull();
    }
  });
});

describe("version tags", () => {
  it("parses the shape of a tag", () => {
    expect(parseVersionTag("1.27.3-alpine")).toEqual({ prefix: "", numbers: [1, 27, 3], suffix: "-alpine" });
    expect(parseVersionTag("v2.1")).toEqual({ prefix: "v", numbers: [2, 1], suffix: "" });
    expect(parseVersionTag("latest")).toBeNull();
    expect(parseVersionTag("1")).toBeNull();
  });

  it("suggests the newest tag of the same shape and says how big the step is", () => {
    const tags = ["1.27.3", "1.27.4", "1.28.0", "2.0.0", "2.0.0-rc1", "1.27.5-alpine", "latest", "v3.0.0"];
    expect(newerTag("1.27.3", tags)).toEqual({ tag: "2.0.0", kind: "major" });
    expect(newerTag("1.27.3", ["1.27.4", "1.27.10"])).toEqual({ tag: "1.27.10", kind: "patch" });
    expect(newerTag("1.27.3", ["1.27.4", "1.28.0"])).toEqual({ tag: "1.28.0", kind: "minor" });
    expect(newerTag("1.27.3-alpine", tags)).toEqual({ tag: "1.27.5-alpine", kind: "patch" });
    expect(newerTag("1.27", ["1.28", "1.27.9"])).toEqual({ tag: "1.28", kind: "minor" });
    expect(newerTag("2.0.0", tags)).toBeNull();
    expect(newerTag("latest", tags)).toBeNull();
  });
});

describe("the host's kernel as a distribution package", () => {
  it("names Ubuntu's kernel from its version signature, with the hardware enablement package where it applies", () => {
    expect(
      kernelPackage({
        release: "6.8.0-45-generic",
        versionSignature: "Ubuntu 6.8.0-45.45-generic 6.8.12",
        osName: "Ubuntu 24.04.1 LTS",
        osVersion: "24.04",
      }),
    ).toEqual({
      ok: true,
      type: "deb",
      name: "linux-image-6.8.0-45-generic",
      version: "6.8.0-45.45",
      distro: "ubuntu-24.04",
      purl: "pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45?distro=ubuntu-24.04&upstream=linux",
    });
    const hwe = kernelPackage({
      release: "6.8.0-45-generic",
      versionSignature: "Ubuntu 6.8.0-45.45~22.04.1-generic 6.8.12",
      osName: "Ubuntu 22.04.5 LTS",
      osVersion: "22.04",
    });
    expect(hwe.ok && hwe.purl).toContain("upstream=linux-hwe-6.8");
    const aws = kernelPackage({
      release: "6.8.0-1015-aws",
      versionSignature: "Ubuntu 6.8.0-1015.16-aws 6.8.12",
      osName: "Ubuntu 24.04.1 LTS",
      osVersion: "24.04",
    });
    expect(aws.ok && aws.purl).toContain("upstream=linux-aws");
    // Without the signature the package version is unknown: said, not guessed.
    expect(
      kernelPackage({ release: "6.8.0-45-generic", osName: "Ubuntu 24.04.1 LTS", osVersion: "24.04" }),
    ).toEqual({
      ok: false,
      reason: "unknownVersion",
    });
  });

  it("names Debian's kernel from /proc/version", () => {
    expect(
      kernelPackage({
        release: "6.1.0-26-amd64",
        procVersion:
          "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)",
        osName: "Debian GNU/Linux 12 (bookworm)",
        osVersion: "12",
      }),
    ).toMatchObject({
      ok: true,
      version: "6.1.112-1",
      purl: "pkg:deb/debian/linux-image-6.1.0-26-amd64@6.1.112-1?distro=debian-12&upstream=linux",
    });
  });

  it("names the kernel of RHEL and its relatives, Oracle's UEK, Amazon Linux and Alpine from uname", () => {
    expect(
      kernelPackage({
        release: "5.14.0-427.13.1.el9_4.x86_64",
        osName: "Red Hat Enterprise Linux 9.4 (Plow)",
        osVersion: "9.4",
      }),
    ).toMatchObject({
      ok: true,
      name: "kernel",
      version: "5.14.0-427.13.1.el9_4",
      purl: "pkg:rpm/redhat/kernel@5.14.0-427.13.1.el9_4?distro=rhel-9&arch=x86_64",
    });
    expect(
      kernelPackage({
        release: "5.14.0-427.13.1.el9_4.x86_64",
        osName: "AlmaLinux 9.4 (Seafoam Ocelot)",
        osVersion: "9.4",
      }),
    ).toMatchObject({
      purl: "pkg:rpm/almalinux/kernel@5.14.0-427.13.1.el9_4?distro=almalinux-9&arch=x86_64",
    });
    expect(
      kernelPackage({
        release: "5.15.0-209.161.7.el9uek.x86_64",
        osName: "Oracle Linux Server 9.4",
        osVersion: "9.4",
      }),
    ).toMatchObject({
      name: "kernel-uek",
    });
    expect(
      kernelPackage({
        release: "6.1.112-122.189.amzn2023.x86_64",
        osName: "Amazon Linux 2023.5.20241001",
        osVersion: "2023",
      }),
    ).toMatchObject({
      purl: "pkg:rpm/amazonlinux/kernel@6.1.112-122.189.amzn2023?distro=amazonlinux-2023&arch=x86_64",
    });
    expect(
      kernelPackage({ release: "6.6.58-0-lts", osName: "Alpine Linux v3.20", osVersion: "3.20.3" }),
    ).toMatchObject({
      purl: "pkg:apk/alpine/linux-lts@6.6.58-r0?distro=alpine-3.20",
    });
  });

  it("says when it cannot name the package", () => {
    expect(
      kernelPackage({
        release: "5.14.21-150500.55.73-default",
        osName: "SUSE Linux Enterprise Server 15 SP5",
        osVersion: "15.5",
      }),
    ).toEqual({
      ok: false,
      reason: "unsupportedDistribution",
    });
    expect(kernelPackage({ release: "6.10.0", osName: "Gentoo Linux", osVersion: "2.15" })).toEqual({
      ok: false,
      reason: "unknownDistribution",
    });
    expect(kernelPackage({ release: "6.10.0", osName: null, osVersion: null })).toEqual({
      ok: false,
      reason: "unknownDistribution",
    });
  });
});
