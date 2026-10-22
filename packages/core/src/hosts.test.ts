import { describe, expect, it } from "vitest";
import {
  buildHostSbom,
  checkHostAddress,
  checkHostName,
  HOST_KEY_ALIAS,
  InventoryParseError,
  knownHostsLine,
  parseAllowedSource,
  parseHostCsv,
  parseInventoryReport,
  parsePort,
  pickHostKey,
  REPORT_HEADER,
  validateHostInput,
} from "./hosts.ts";
import { generateDeployKey } from "./ssh.ts";

describe("checkHostAddress", () => {
  it("accepts host names and public or private addresses, normalised", () => {
    expect(checkHostAddress("web-01.example.com")).toEqual({
      ok: true,
      address: "web-01.example.com",
      kind: "hostname",
    });
    expect(checkHostAddress("  DB01.Example.LAN ")).toEqual({
      ok: true,
      address: "db01.example.lan",
      kind: "hostname",
    });
    expect(checkHostAddress("db01")).toMatchObject({ ok: true, kind: "hostname" });
    expect(checkHostAddress("192.0.2.10")).toEqual({ ok: true, address: "192.0.2.10", kind: "ipv4" });
    expect(checkHostAddress("10.1.2.3")).toMatchObject({ ok: true, kind: "ipv4" });
    expect(checkHostAddress("2001:DB8::1")).toEqual({ ok: true, address: "2001:db8::1", kind: "ipv6" });
  });

  it("refuses anything that could be read as an ssh option or carries more than an address", () => {
    for (const bad of [
      "-oProxyCommand=id",
      "-J jump.example.com",
      "--help",
      "web 01",
      "web\t01",
      "web\n01",
      "user@web.example.com",
      "web.example.com:22",
      "web.example.com/path",
      "[2001:db8::1]",
      "fe80::1%eth0",
      "web_01.example.com",
      "web.example.com.",
      "exa mple",
      "$(id).example.com",
      "`id`",
      "ex;ample",
    ]) {
      expect(checkHostAddress(bad), bad).toMatchObject({ ok: false });
    }
    expect(checkHostAddress("")).toEqual({ ok: false, problem: "empty" });
    expect(checkHostAddress("-x")).toEqual({ ok: false, problem: "option" });
    expect(checkHostAddress(`${"a".repeat(64)}.example.com`)).toMatchObject({ ok: false });
    expect(checkHostAddress(`${"a.".repeat(130)}com`)).toEqual({ ok: false, problem: "tooLong" });
  });

  it("refuses loopback, link-local, metadata and unspecified addresses, and names that resolve to them", () => {
    for (const bad of [
      "127.0.0.1",
      "127.9.9.9",
      "0.0.0.0",
      "169.254.169.254",
      "224.0.0.1",
      "::1",
      "::",
      "fe80::1",
      "::ffff:127.0.0.1",
      "localhost",
      "app.localhost",
    ]) {
      expect(checkHostAddress(bad), bad).toEqual({ ok: false, problem: "reserved" });
    }
    // Resolvers read these as IPv4 addresses (inet_aton), after our checks would have passed them.
    for (const bad of ["127.1", "0x7f.1", "2130706433", "0177.0.0.1", "10.1", "1.2.3"]) {
      expect(checkHostAddress(bad), bad).toMatchObject({ ok: false });
    }
  });
});

describe("parsePort / checkHostName", () => {
  it("accepts 1 to 65535 only", () => {
    expect(parsePort(22)).toBe(22);
    expect(parsePort("2222")).toBe(2222);
    expect(parsePort(" 65535 ")).toBe(65535);
    for (const bad of [0, 65536, -1, 1.5, "0", "22a", "0x16", "", "99999", null, undefined, "22 22"]) {
      expect(parsePort(bad), String(bad)).toBeNull();
    }
  });

  it("accepts printable names up to 120 characters", () => {
    expect(checkHostName(" Mail server (backup) ")).toBe("Mail server (backup)");
    expect(checkHostName("")).toBeNull();
    expect(checkHostName("a".repeat(121))).toBeNull();
    expect(checkHostName("bad\u0000name")).toBeNull();
    expect(checkHostName("bad\nname")).toBeNull();
  });
});

describe("parseAllowedSource", () => {
  it("accepts addresses and ranges, separated by commas or spaces", () => {
    expect(parseAllowedSource("192.0.2.10")).toMatchObject({ ok: true, value: "192.0.2.10" });
    expect(parseAllowedSource("192.0.2.0/24, 2001:DB8::/32 198.51.100.7")).toMatchObject({
      ok: true,
      value: "192.0.2.0/24,2001:db8::/32,198.51.100.7",
    });
    expect(parseAllowedSource("10.0.0.0/8,10.0.0.0/8")).toMatchObject({ ok: true, value: "10.0.0.0/8" });
  });

  it("is required and refuses 'any', wildcards, names and quote characters", () => {
    expect(parseAllowedSource("")).toEqual({ ok: false, problem: "empty" });
    expect(parseAllowedSource(" , ")).toEqual({ ok: false, problem: "empty" });
    expect(parseAllowedSource("0.0.0.0/0")).toEqual({ ok: false, problem: "any" });
    expect(parseAllowedSource("::/0")).toEqual({ ok: false, problem: "any" });
    for (const bad of [
      "*",
      "192.0.2.*",
      "gateway.example.com",
      "192.0.2.0/33",
      "2001:db8::/129",
      "192.0.2.1/24/8",
      '192.0.2.1"',
      "!192.0.2.1",
      "fe80::1%eth0",
      "192.0.2.1/x",
    ]) {
      expect(parseAllowedSource(bad), bad).toEqual({ ok: false, problem: "invalid" });
    }
    expect(parseAllowedSource(Array.from({ length: 9 }, (_, i) => `192.0.2.${i + 1}`).join(","))).toEqual({
      ok: false,
      problem: "tooMany",
    });
  });
});

describe("parseHostCsv", () => {
  it("reads address, name and port without a header", () => {
    const result = parseHostCsv("web-01.example.com,Web 01,22\r\n192.0.2.5,,2222\n\n");
    expect(result).toEqual({
      ok: true,
      rows: [
        { line: 1, address: "web-01.example.com", name: "Web 01", port: "22" },
        { line: 2, address: "192.0.2.5", name: "", port: "2222" },
      ],
    });
  });

  it("finds columns by header, in any order, with semicolons and a byte order mark", () => {
    const result = parseHostCsv('﻿Port;Host;Name\n2222;db.example.com;"Database; main"\n');
    expect(result).toEqual({
      ok: true,
      rows: [{ line: 2, address: "db.example.com", name: "Database; main", port: "2222" }],
    });
  });

  it("handles quotes and escaped quotes", () => {
    const result = parseHostCsv('address,name\n"a.example.com","He said ""hi"""\n');
    expect(result).toMatchObject({ ok: true, rows: [{ address: "a.example.com", name: 'He said "hi"' }] });
  });

  it("refuses empty files, files with too many rows and huge files", () => {
    expect(parseHostCsv("")).toEqual({ ok: false, problem: "empty" });
    expect(parseHostCsv("address,name,port\n")).toEqual({ ok: false, problem: "empty" });
    const many = Array.from({ length: 501 }, (_, i) => `h${i}.example.com`).join("\n");
    expect(parseHostCsv(many)).toEqual({ ok: false, problem: "tooManyRows" });
    expect(parseHostCsv(Array.from({ length: 500 }, (_, i) => `h${i}.example.com`).join("\n"))).toMatchObject(
      { ok: true },
    );
    expect(parseHostCsv("x".repeat(300 * 1024))).toEqual({ ok: false, problem: "tooLarge" });
  });

  it("caps the length of a cell", () => {
    const result = parseHostCsv(`${"a".repeat(5000)}.example.com`);
    expect(result.ok && result.rows[0]?.address.length).toBe(1000);
  });
});

/** An SSH public key blob: the type name, then whatever follows. */
function blob(type: string, ...parts: Buffer[]): string {
  const string = (b: Buffer) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(b.length);
    return Buffer.concat([length, b]);
  };
  return Buffer.concat([string(Buffer.from(type)), ...parts.map(string)]).toString("base64");
}

describe("pickHostKey", () => {
  const ed = generateDeployKey("host").publicKey.split(" ")[1] as string;
  const ecdsa = blob("ecdsa-sha2-nistp256", Buffer.from("nistp256"), Buffer.alloc(65, 4));
  const rsa2048 = blob(
    "ssh-rsa",
    Buffer.from([1, 0, 1]),
    Buffer.concat([Buffer.from([0]), Buffer.alloc(256, 0xff)]),
  );
  const rsa1024 = blob(
    "ssh-rsa",
    Buffer.from([1, 0, 1]),
    Buffer.concat([Buffer.from([0]), Buffer.alloc(128, 0xff)]),
  );

  it("prefers Ed25519, then ECDSA, then RSA, and returns the fingerprint ssh shows", () => {
    const out = [
      `# 192.0.2.1:22 SSH-2.0-OpenSSH_9.6`,
      `192.0.2.1 ssh-rsa ${rsa2048}`,
      `192.0.2.1 ecdsa-sha2-nistp256 ${ecdsa}`,
      `192.0.2.1 ssh-ed25519 ${ed}`,
    ].join("\n");
    const picked = pickHostKey(out);
    expect(picked.key).toMatchObject({ type: "ssh-ed25519", key: ed });
    expect(picked.key?.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(pickHostKey(`h ssh-rsa ${rsa2048}\nh ecdsa-sha2-nistp256 ${ecdsa}`).key?.type).toBe(
      "ecdsa-sha2-nistp256",
    );
    expect(pickHostKey(`h ssh-rsa ${rsa2048}`).key?.type).toBe("ssh-rsa");
  });

  it("drops weak RSA keys and says so", () => {
    expect(pickHostKey(`h ssh-rsa ${rsa1024}`)).toEqual({ key: null, weak: true });
  });

  it("ignores lines that are not exactly a key, and keys filed under the wrong type", () => {
    expect(pickHostKey("").key).toBeNull();
    expect(pickHostKey("# only a comment\nnot a key line\n").key).toBeNull();
    expect(pickHostKey(`h ssh-ed25519 ${ed} trailing words`).key).toBeNull();
    expect(pickHostKey(`h ssh-ed25519 ${ecdsa}`).key).toBeNull();
    expect(pickHostKey(`h ssh-dss ${ed}`).key).toBeNull();
    expect(pickHostKey(`h ssh-ed25519 ${"A".repeat(20000)}`).key).toBeNull();
  });

  it("writes a known_hosts line for one key under the fixed alias", () => {
    expect(knownHostsLine("ssh-ed25519", ed)).toBe(`${HOST_KEY_ALIAS} ssh-ed25519 ${ed}\n`);
  });
});

const T = "\t";
const DEBIAN_REPORT = [
  REPORT_HEADER,
  "@@section os-release",
  'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
  'NAME="Debian GNU/Linux"',
  'VERSION_ID="12"',
  "VERSION_CODENAME=bookworm",
  "ID=debian",
  'HOME_URL="https://www.debian.org/"',
  "@@section kernel",
  "6.1.0-18-amd64",
  "@@section machine",
  "x86_64",
  "@@section dpkg",
  ["libssl3", "3.0.11-1~deb12u2", "amd64", "ii ", "openssl", "3.0.11-1~deb12u2"].join(T),
  ["openssl", "3.0.11-1~deb12u2", "amd64", "ii ", "openssl", "3.0.11-1~deb12u2"].join(T),
  ["bash", "5.2.15-2+b2", "amd64", "ii ", "bash", "5.2.15-2+b2"].join(T),
  ["libc6", "2.36-9+deb12u4", "amd64", "hi ", "glibc", "2.36-9+deb12u4"].join(T),
  ["oldpkg", "1.0-1", "amd64", "rc ", "oldpkg", "1.0-1"].join(T),
  ["tzdata", "2024a-0+deb12u1", "all", "ii ", "", ""].join(T),
  ["bsdutils", "1:2.38.1-5+deb12u1", "amd64", "ii ", "util-linux", "2.38.1-5+deb12u1"].join(T),
  "@@section updates-apt",
  "Listing...",
  "libssl3/stable-security 3.0.11-1~deb12u3 amd64 [upgradable from: 3.0.11-1~deb12u2]",
  "bash/stable 5.2.15-2+b3 amd64 [upgradable from: 5.2.15-2+b2]",
  "@@end",
  "",
].join("\n");

describe("parseInventoryReport: Debian", () => {
  const report = parseInventoryReport(DEBIAN_REPORT);

  it("reads the operating system, kernel and architecture", () => {
    expect(report.os).toEqual({
      id: "debian",
      idLike: [],
      versionId: "12",
      codename: "bookworm",
      name: "Debian GNU/Linux",
      prettyName: "Debian GNU/Linux 12 (bookworm)",
    });
    expect(report.kernel).toBe("6.1.0-18-amd64");
    expect(report.arch).toBe("x86_64");
  });

  it("keeps installed packages (also on hold), drops removed ones, and records the source package", () => {
    expect(report.packages.map((p) => p.name)).toEqual([
      "bash",
      "bsdutils",
      "libc6",
      "libssl3",
      "openssl",
      "tzdata",
    ]);
    const libssl = report.packages.find((p) => p.name === "libssl3");
    expect(libssl).toMatchObject({
      type: "deb",
      version: "3.0.11-1~deb12u2",
      arch: "amd64",
      origin: "openssl",
      originVersion: null,
    });
    // The source name equals the package name: no origin needed.
    expect(report.packages.find((p) => p.name === "openssl")?.origin).toBeNull();
    expect(report.packages.find((p) => p.name === "tzdata")?.origin).toBeNull();
  });

  it("marks pending updates and which come from a security repository", () => {
    const libssl = report.packages.find((p) => p.name === "libssl3");
    expect(libssl).toMatchObject({ upgradableTo: "3.0.11-1~deb12u3", securityUpdate: true });
    expect(report.packages.find((p) => p.name === "bash")).toMatchObject({
      upgradableTo: "5.2.15-2+b3",
      securityUpdate: false,
    });
    expect(report.packages.find((p) => p.name === "openssl")?.upgradableTo).toBeNull();
    expect(report.pendingUpdates).toBe(2);
    expect(report.skipped).toBe(0);
  });
});

describe("parseInventoryReport: RPM", () => {
  const text = [
    REPORT_HEADER,
    "@@section os-release",
    'NAME="Rocky Linux"',
    'ID="rocky"',
    'ID_LIKE="rhel centos fedora"',
    'VERSION_ID="9.3"',
    "@@section kernel",
    "5.14.0-362.8.1.el9_3.x86_64",
    "@@section machine",
    "x86_64",
    "@@section rpm",
    ["openssl-libs", "1", "3.0.7", "24.el9", "x86_64", "openssl-3.0.7-24.el9.src.rpm"].join(T),
    ["bash", "(none)", "5.1.8", "6.el9_1", "x86_64", "bash-5.1.8-6.el9_1.src.rpm"].join(T),
    ["gpg-pubkey", "(none)", "350d275d", "6237e8d3", "(none)", "(none)"].join(T),
    ["kernel-core", "0", "5.14.0", "362.8.1.el9_3", "x86_64", "(none)"].join(T),
    "@@section updates-dnf",
    "Last metadata expiration check: 0:10:00 ago.",
    "",
    "openssl-libs.x86_64                  1:3.0.7-25.el9_3                 baseos",
    "kernel-core.x86_64                   5.14.0-362.13.1.el9_3            baseos",
    "",
    "Obsoleting Packages",
    "foo.x86_64    1.0-1    appstream",
    "@@end",
  ].join("\n");
  const report = parseInventoryReport(text);

  it("builds the version as epoch:version-release and ignores imported keys", () => {
    expect(report.packages.map((p) => [p.name, p.version, p.epoch])).toEqual([
      ["bash", "5.1.8-6.el9_1", 0],
      ["kernel-core", "5.14.0-362.8.1.el9_3", 0],
      ["openssl-libs", "1:3.0.7-24.el9", 1],
    ]);
    expect(report.packages.find((p) => p.name === "openssl-libs")?.origin).toBe(
      "openssl-3.0.7-24.el9.src.rpm",
    );
    expect(report.packages.find((p) => p.name === "kernel-core")?.origin).toBeNull();
    expect(report.os).toMatchObject({ id: "rocky", idLike: ["rhel", "centos", "fedora"], versionId: "9.3" });
  });

  it("reads dnf check-update, stops at obsoleted packages", () => {
    expect(report.pendingUpdates).toBe(2);
    expect(report.packages.find((p) => p.name === "openssl-libs")?.upgradableTo).toBe("1:3.0.7-25.el9_3");
  });
});

describe("parseInventoryReport: Alpine", () => {
  it("reads apk list with origins and apk version updates", () => {
    const report = parseInventoryReport(
      [
        REPORT_HEADER,
        "@@section os-release",
        "ID=alpine",
        "VERSION_ID=3.19.1",
        "@@section machine",
        "x86_64",
        "@@section apk",
        "libcrypto3-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [installed]",
        "busybox-1.36.1-r15 x86_64 {busybox} (GPL-2.0-only) [installed]",
        "py3-foo-bar-1.2.3-r0 noarch {py3-foo-bar} (MIT) [installed]",
        "@@section updates-apk",
        "Installed:                                Available:",
        "libcrypto3-3.1.4-r5                     < 3.1.5-r0",
        "@@end",
      ].join("\n"),
    );
    expect(report.packages).toMatchObject([
      { name: "busybox", version: "1.36.1-r15", arch: "x86_64", origin: null },
      { name: "libcrypto3", version: "3.1.4-r5", origin: "openssl", upgradableTo: "3.1.5-r0" },
      { name: "py3-foo-bar", version: "1.2.3-r0", arch: "noarch" },
    ]);
    expect(report.pendingUpdates).toBe(1);
  });

  it("falls back to apk info -v when apk list printed nothing", () => {
    const report = parseInventoryReport(
      [
        REPORT_HEADER,
        "@@section machine",
        "aarch64",
        "@@section apk",
        "@@section apk-v",
        "musl-1.2.4_git20230717-r4",
        "@@end",
      ].join("\n"),
    );
    expect(report.packages).toMatchObject([
      { name: "musl", version: "1.2.4_git20230717-r4", arch: "aarch64" },
    ]);
  });
});

describe("parseInventoryReport: hostile and broken input", () => {
  const wrap = (body: string[]) => [REPORT_HEADER, ...body, "@@end"].join("\n");

  it("refuses an empty report, a foreign format and a report that was cut off", () => {
    expect(() => parseInventoryReport("")).toThrow(InventoryParseError);
    expect(() => parseInventoryReport("   \n")).toThrow(InventoryParseError);
    expect(() => parseInventoryReport("root:x:0:0:root:/root:/bin/bash\n")).toThrowError(
      expect.objectContaining({ code: "format" }),
    );
    expect(() =>
      parseInventoryReport(`${REPORT_HEADER}\n@@section dpkg\nbash\t1\tamd64\tii \tbash\t1\n`),
    ).toThrowError(expect.objectContaining({ code: "truncated" }));
  });

  it("drops malformed lines and counts them, never throws on them", () => {
    const report = parseInventoryReport(
      wrap([
        "@@section dpkg",
        "no tabs at all",
        ["bash", "5.2", "amd64", "ii ", "bash", "5.2"].join(T),
        ["Bad Name", "1", "amd64", "ii ", "", ""].join(T),
        ["ok", "$(id)", "amd64", "ii ", "", ""].join(T),
        ["ok", "1`id`", "amd64", "ii ", "", ""].join(T),
        ["ok2", "1", "amd64; rm -rf /", "ii ", "", ""].join(T),
        ["a".repeat(500), "1", "amd64", "ii ", "", ""].join(T),
        ["x", "1", "amd64", "ii ", "", "", "extra", "extra", "extra"].join(T),
        "\u0000\u0001binary",
      ]),
    );
    expect(report.packages.map((p) => p.name)).toEqual(["bash"]);
    expect(report.skipped).toBe(8);
  });

  it("ignores unknown and repeated sections and markers inside values", () => {
    const report = parseInventoryReport(
      wrap([
        "@@section kernel",
        "6.1.0-1",
        "@@section kernel",
        "9.9.9-evil",
        "@@section shadow",
        "root:$6$secret::",
        "@@section dpkg",
        ["bash", "1", "amd64", "ii ", "", ""].join(T),
        "@@sectionx dpkg",
        "@@@@end",
      ]),
    );
    expect(report.kernel).toBe("6.1.0-1");
    expect(report.packages).toHaveLength(1);
  });

  it("stops at the first @@end, so nothing after it counts", () => {
    const text = `${wrap(["@@section dpkg", ["bash", "1", "amd64", "ii ", "", ""].join(T)])}\n@@section dpkg\n${["evil", "1", "amd64", "ii ", "", ""].join(T)}\n@@end\n`;
    expect(parseInventoryReport(text).packages.map((p) => p.name)).toEqual(["bash"]);
  });

  it("refuses more packages than the limit and merges duplicates", () => {
    const line = (i: number) => [`pkg${i}`, "1", "amd64", "ii ", "", ""].join(T);
    const many = wrap(["@@section dpkg", ...Array.from({ length: 11 }, (_, i) => line(i))]);
    expect(() => parseInventoryReport(many, 10)).toThrowError(
      expect.objectContaining({ code: "tooManyPackages" }),
    );
    const dup = wrap(["@@section dpkg", line(1), line(1), line(1)]);
    expect(parseInventoryReport(dup, 10).packages).toHaveLength(1);
  });

  it("validates os-release values and strips control characters", () => {
    const report = parseInventoryReport(
      wrap([
        "@@section os-release",
        'ID="Evil; id"',
        "ID_LIKE=ubuntu debian ../x",
        "VERSION_ID=1;2",
        'PRETTY_NAME="A\u001b[31mred\u0007 system"',
        `NAME=${"n".repeat(1000)}`,
        "lowercase=ignored",
        "@@section kernel",
        "5.15; id",
        "@@section machine",
        "x86 64",
      ]),
    );
    expect(report.os.id).toBeNull();
    expect(report.os.idLike).toEqual(["ubuntu", "debian"]);
    expect(report.os.versionId).toBeNull();
    expect(report.os.prettyName).toBe("A[31mred system");
    expect(report.os.name).toBeNull();
    expect(report.kernel).toBeNull();
    expect(report.arch).toBeNull();
  });

  it("handles carriage returns and a large report quickly", () => {
    const rows = Array.from({ length: 15000 }, (_, i) =>
      [`pkg${i}`, `1.0-${i}`, "amd64", "ii ", `src${i % 100}`, "1.0"].join(T),
    );
    const started = performance.now();
    const report = parseInventoryReport(wrap(["@@section dpkg", ...rows]).replaceAll("\n", "\r\n"));
    expect(report.packages).toHaveLength(15000);
    expect(performance.now() - started).toBeLessThan(2000);
  });
});

describe("buildHostSbom", () => {
  const debian = parseInventoryReport(DEBIAN_REPORT);
  const sbom = buildHostSbom({ name: "web-01", os: debian.os, packages: debian.packages }) as {
    artifacts: {
      name: string;
      purl: string;
      type: string;
      metadataType: string;
      metadata: Record<string, unknown>;
    }[];
    distro: Record<string, unknown>;
    source: Record<string, unknown>;
  };

  it("describes the distribution the way syft does", () => {
    expect(sbom.distro).toMatchObject({
      id: "debian",
      versionID: "12",
      name: "Debian GNU/Linux",
      versionCodename: "bookworm",
    });
  });

  it("gives deb packages a purl with distro and upstream (source package)", () => {
    const libssl = sbom.artifacts.find((a) => a.name === "libssl3");
    expect(libssl?.purl).toBe(
      "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
    );
    expect(libssl).toMatchObject({ type: "deb", metadataType: "dpkg-db-entry" });
    expect(libssl?.metadata).toMatchObject({
      package: "libssl3",
      source: "openssl",
      version: "3.0.11-1~deb12u2",
      architecture: "amd64",
    });
    expect(sbom.artifacts.find((a) => a.name === "bash")?.purl).toBe(
      "pkg:deb/debian/bash@5.2.15-2%2Bb2?arch=amd64&distro=debian-12",
    );
  });

  it("keeps the epoch of deb versions encoded, and the source version when it differs", () => {
    const bsdutils = sbom.artifacts.find((a) => a.name === "bsdutils");
    expect(bsdutils?.purl).toContain("bsdutils@1%3A2.38.1-5%2Bdeb12u1");
    expect(bsdutils?.purl).toContain("upstream=util-linux%402.38.1-5%2Bdeb12u1");
  });

  it("builds rpm and apk packages with their own metadata", () => {
    const rpm = parseInventoryReport(
      [
        REPORT_HEADER,
        "@@section os-release",
        "ID=rhel",
        "VERSION_ID=9.2",
        "@@section rpm",
        ["openssl-libs", "1", "3.0.7", "24.el9", "x86_64", "openssl-3.0.7-24.el9.src.rpm"].join(T),
        "@@end",
      ].join("\n"),
    );
    const r = buildHostSbom({ name: "x", os: rpm.os, packages: rpm.packages }) as typeof sbom;
    expect(r.artifacts[0]).toMatchObject({
      name: "openssl-libs",
      version: "1:3.0.7-24.el9",
      type: "rpm",
      purl: "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64&epoch=1&distro=rhel-9.2&upstream=openssl-3.0.7-24.el9.src.rpm",
      metadataType: "rpm-db-entry",
    });
    expect(r.artifacts[0]?.metadata).toMatchObject({
      name: "openssl-libs",
      version: "3.0.7",
      release: "24.el9",
      epoch: 1,
      sourceRpm: "openssl-3.0.7-24.el9.src.rpm",
    });

    const apk = parseInventoryReport(
      [
        REPORT_HEADER,
        "@@section os-release",
        "ID=alpine",
        "VERSION_ID=3.19.1",
        "@@section apk",
        "libcrypto3-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [installed]",
        "@@end",
      ].join("\n"),
    );
    const a = buildHostSbom({ name: "x", os: apk.os, packages: apk.packages }) as typeof sbom;
    expect(a.artifacts[0]?.purl).toBe(
      "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl",
    );
    expect(a.artifacts[0]?.metadata).toMatchObject({ package: "libcrypto3", originPackage: "openssl" });
  });

  it("does not put the server's own name or paths into the SBOM beyond the given name", () => {
    expect(JSON.stringify(sbom)).not.toContain("/home");
    expect(sbom.source).toMatchObject({ name: "web-01", type: "directory" });
  });
});

describe("validateHostInput", () => {
  it("fills in the defaults and normalises the address", () => {
    expect(validateHostInput({ address: " Web-01.Example.COM " })).toEqual({
      ok: true,
      value: { address: "web-01.example.com", name: "web-01.example.com", port: 22, sshUser: "garnetops" },
    });
    expect(
      validateHostInput({ address: "192.0.2.5", name: " Mail ", port: "2222", sshUser: "inventory" }),
    ).toEqual({
      ok: true,
      value: { address: "192.0.2.5", name: "Mail", port: 2222, sshUser: "inventory" },
    });
  });

  it("names every field that is wrong, with a code", () => {
    expect(
      validateHostInput({
        address: "-oProxyCommand=x",
        name: "x".repeat(200),
        port: "70000",
        sshUser: "Root User",
      }),
    ).toEqual({
      ok: false,
      errors: [
        { field: "address", code: "address_option" },
        { field: "name", code: "name_invalid" },
        { field: "port", code: "port_range" },
        { field: "sshUser", code: "user_invalid" },
      ],
    });
    expect(validateHostInput({ address: "127.0.0.1" })).toEqual({
      ok: false,
      errors: [{ field: "address", code: "address_reserved" }],
    });
    expect(validateHostInput({ address: "" })).toEqual({
      ok: false,
      errors: [{ field: "address", code: "address_empty" }],
    });
  });
});
