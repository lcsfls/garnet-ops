import { describe, expect, it } from "vitest";
import { inventorySchema, sshdFactsSchema } from "./agent.ts";
import {
  compareOpenSshVersions,
  isSsholeFinding,
  parseOpenSshVersion,
  SSHD_DEFAULTS,
  type SshdFacts,
  type SshdSettingName,
  type SsholeContext,
  sshdFindings,
  ssholeAffected,
  ssholeSafeReasons,
} from "./sshd.ts";

type Overrides = Partial<Record<SshdSettingName, string | { value: string; match: string[] }>>;

/** A host as the agent reports it; the settings start at OpenSSH's defaults. */
function host(over: Partial<SshdFacts> = {}, settings: Overrides = {}): SshdFacts {
  const all = Object.fromEntries(
    (Object.keys(SSHD_DEFAULTS) as SshdSettingName[]).map((name) => {
      const o = settings[name];
      return [
        name,
        o === undefined
          ? { value: SSHD_DEFAULTS[name], default: true, match: [] }
          : typeof o === "string"
            ? { value: o, default: false, match: [] }
            : { ...o, default: false },
      ];
    }),
  ) as Record<SshdSettingName, { value: string; default: boolean; match: string[] }>;
  return {
    server: "openssh",
    package: { name: "openssh-server", version: "10.0_p1-r9" },
    libc: "musl",
    pamLinked: false,
    config: { read: true, problem: null, files: ["/etc/ssh/sshd_config"], skipped: [], settings: all },
    ...over,
  };
}

const unknownCve: SsholeContext = { cveFinding: false, cveKnown: null };
const rules = (facts: SshdFacts, ctx = unknownCve) =>
  sshdFindings(facts, ctx).map((f) => `${f.rule}:${f.severity}:${f.scope}`);

describe("OpenSSH versions", () => {
  it("reads the upstream part of every distribution's version", () => {
    expect(parseOpenSshVersion("10.0_p1-r9")).toEqual([10, 0, 1]);
    expect(parseOpenSshVersion("1:9.6p1-3ubuntu13.5")).toEqual([9, 6, 1]);
    expect(parseOpenSshVersion("8.7p1-38.el9_4.4")).toEqual([8, 7, 1]);
    expect(parseOpenSshVersion("10.6p2")).toEqual([10, 6, 2]);
    expect(parseOpenSshVersion("10.6")).toEqual([10, 6, 0]);
    expect(parseOpenSshVersion("dropbear-2024.86")).toBeNull();
  });

  it("compares by the upstream version, not as text", () => {
    expect(compareOpenSshVersions("9.9_p2-r0", "10.6p2")).toBe(-1);
    expect(compareOpenSshVersions("10.6_p1-r0", "10.6p2")).toBe(-1);
    expect(compareOpenSshVersions("10.6_p2-r0", "10.6p2")).toBe(0);
    expect(compareOpenSshVersions("1:10.7p1-1", "10.6p2")).toBe(1);
    expect(compareOpenSshVersions("x", "10.6p2")).toBeNull();
  });

  it("knows the sshole finding on any OpenSSH package", () => {
    expect(isSsholeFinding({ vulnerabilityId: "CVE-2026-123158", packageName: "openssh-server" })).toBe(true);
    expect(
      isSsholeFinding({ vulnerabilityId: "cve-2026-123158", packageName: "openssh-client-default" }),
    ).toBe(true);
    expect(isSsholeFinding({ vulnerabilityId: "CVE-2026-123158", packageName: "dropbear" })).toBe(false);
    expect(isSsholeFinding({ vulnerabilityId: "CVE-2026-0001", packageName: "openssh-server" })).toBe(false);
  });
});

describe("SSH hardening rules", () => {
  it("finds nothing on a hardened host", () => {
    const facts = host({ libc: "glibc" }, { passwordAuthentication: "no", permitRootLogin: "no" });
    expect(rules(facts)).toEqual([]);
  });

  it("password authentication is medium, also where keys are switched off", () => {
    const glibc = host({ libc: "glibc", package: { name: "openssh-server", version: "1:10.7p1-1" } });
    expect(rules(glibc)).toEqual(["password-authentication:medium:global"]);
    expect(rules(host({ libc: "glibc" }, { pubkeyAuthentication: "no" }))).toEqual([
      "password-authentication:medium:global",
    ]);
    // Off globally but on for some connections.
    expect(
      rules(host({ libc: "glibc" }, { passwordAuthentication: { value: "no", match: ["yes"] } })),
    ).toEqual(["password-authentication:medium:match"]);
  });

  it("root login with a password is high; key-only root login is not a finding", () => {
    const base = { libc: "glibc" as const };
    expect(rules(host(base, { passwordAuthentication: "no", permitRootLogin: "yes" }))).toEqual([
      "root-login:high:global",
    ]);
    for (const value of ["prohibit-password", "without-password", "forced-commands-only", "no"]) {
      expect(rules(host(base, { passwordAuthentication: "no", permitRootLogin: value }))).toEqual([]);
    }
    expect(
      rules(host(base, { passwordAuthentication: "no", permitRootLogin: { value: "no", match: ["yes"] } })),
    ).toEqual(["root-login:high:match"]);
  });

  it("empty passwords are high", () => {
    expect(
      rules(host({ libc: "glibc" }, { passwordAuthentication: "no", permitEmptyPasswords: "yes" })),
    ).toEqual(["empty-passwords:high:global"]);
  });

  it("sshole is critical on musl without PAM with password logins and an affected OpenSSH", () => {
    // Alpine's defaults: password authentication on (upstream default), no PAM build.
    expect(rules(host())).toEqual(["sshole:critical:global", "password-authentication:medium:global"]);
    expect(sshdFindings(host(), unknownCve)[0]).toMatchObject({ basis: "version" });
    // With the finding from the vulnerability database it is the database's verdict.
    expect(sshdFindings(host(), { cveFinding: true, cveKnown: true })[0]).toMatchObject({
      rule: "sshole",
      basis: "finding",
    });
    // Password logins only in a Match block are enough for those connections.
    expect(rules(host({}, { passwordAuthentication: { value: "no", match: ["yes"] } }))).toEqual([
      "sshole:critical:match",
      "password-authentication:medium:match",
    ]);
  });

  it("sshole does not fire when any condition is missing", () => {
    const off = (facts: SshdFacts, ctx = unknownCve) =>
      !rules(facts, ctx).some((r) => r.startsWith("sshole"));
    expect(off(host({}, { passwordAuthentication: "no" }))).toBe(true);
    expect(off(host({ libc: "glibc" }))).toBe(true);
    expect(off(host({ libc: "unknown" }))).toBe(true);
    // PAM on, from a PAM build with UsePAM yes.
    expect(off(host({ pamLinked: true }, { usePam: "yes" }))).toBe(true);
    // UsePAM yes in a build without PAM changes nothing.
    expect(off(host({ pamLinked: false }, { usePam: "yes" }))).toBe(false);
    // Fixed upstream version.
    expect(off(host({ package: { name: "openssh-server", version: "10.6_p2-r0" } }))).toBe(true);
    // The database knows the CVE and has no finding for this host: the distribution's backport is authoritative.
    expect(
      off(host({ package: { name: "openssh-server", version: "10.0_p1-r10" } }), {
        cveFinding: false,
        cveKnown: true,
      }),
    ).toBe(true);
    // No readable configuration: no claim either way.
    expect(
      rules(host({ config: { read: false, problem: "unreadable", files: [], skipped: [], settings: null } })),
    ).toEqual([]);
    expect(rules(host({ server: "dropbear", config: null }))).toEqual([]);
  });

  it("decides whether OpenSSH is affected by the database first, the version second", () => {
    expect(ssholeAffected(host(), { cveFinding: true, cveKnown: null })).toEqual({
      affected: true,
      basis: "finding",
    });
    expect(ssholeAffected(host(), { cveFinding: false, cveKnown: true })).toEqual({
      affected: false,
      basis: "finding",
    });
    expect(ssholeAffected(host(), { cveFinding: false, cveKnown: false })).toEqual({
      affected: true,
      basis: "version",
    });
    expect(ssholeAffected(host({ package: null }), unknownCve)).toBeNull();
    expect(ssholeAffected(host({ package: { name: "openssh", version: "unknown" } }), unknownCve)).toBeNull();
  });
});

describe("the note on the sshole vulnerability finding", () => {
  it("says why it cannot be used with this configuration, never what cannot be told", () => {
    expect(ssholeSafeReasons(null)).toEqual([]);
    expect(ssholeSafeReasons(host())).toEqual([]);
    expect(ssholeSafeReasons(host({ libc: "glibc" }))).toEqual(["glibc"]);
    expect(ssholeSafeReasons(host({ pamLinked: true }, { usePam: "yes" }))).toEqual(["pam"]);
    expect(ssholeSafeReasons(host({}, { passwordAuthentication: "no" }))).toEqual([
      "password-authentication-off",
    ]);
    expect(ssholeSafeReasons(host({}, { passwordAuthentication: { value: "no", match: ["yes"] } }))).toEqual(
      [],
    );
    expect(ssholeSafeReasons(host({ libc: "glibc" }, { passwordAuthentication: "no" }))).toEqual([
      "glibc",
      "password-authentication-off",
    ]);
    expect(ssholeSafeReasons(host({ server: "none", config: null, package: null }))).toEqual([
      "no-openssh-server",
    ]);
    expect(ssholeSafeReasons(host({ server: "dropbear", config: null }))).toEqual(["dropbear"]);
    // An unreadable sshd_config on musl: nothing can be said.
    expect(
      ssholeSafeReasons(
        host({
          pamLinked: null,
          config: { read: false, problem: "unreadable", files: [], skipped: [], settings: null },
        }),
      ),
    ).toEqual([]);
  });
});

describe("the inventory field sshd", () => {
  const base = { hostname: "alpine-01.example.lan", agentVersion: "dev", containers: [], images: [] };

  it("takes what the agent sends, cleaned and bounded", () => {
    const sent = {
      server: "openssh",
      package: { name: "openssh-server", version: "10.0_p1-r9" },
      libc: "musl",
      pamLinked: null,
      config: {
        read: true,
        files: ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-a.conf"],
        skipped: [{ path: "/etc/ssh/sshd_config.d/x.conf", reason: "something-new" }],
        settings: Object.fromEntries(
          Object.entries(SSHD_DEFAULTS).map(([k, v]) => [
            k,
            { value: k === "permitRootLogin" ? "YES\u0007" : v, default: false, match: [] },
          ]),
        ),
      },
    };
    const parsed = inventorySchema.parse({
      ...base,
      runtime: "systemd",
      serviceManager: "openrc",
      sshd: sent,
    });
    expect(parsed.serviceManager).toBe("openrc");
    expect(parsed.sshd?.config?.settings?.permitRootLogin.value).toBe("yes");
    expect(parsed.sshd?.config?.skipped).toEqual([
      { path: "/etc/ssh/sshd_config.d/x.conf", reason: "unreadable" },
    ]);
    expect(parsed.sshd?.config?.problem).toBeNull();
  });

  it("an older agent sends none, and a broken field never fails the inventory", () => {
    expect(inventorySchema.parse(base).sshd).toBeUndefined();
    expect(inventorySchema.parse(base).serviceManager).toBeUndefined();
    const broken = inventorySchema.parse({ ...base, sshd: { server: "telnet" }, serviceManager: "runit" });
    expect(broken.sshd).toBeUndefined();
    expect(broken.serviceManager).toBeUndefined();
    expect(sshdFactsSchema.safeParse({ server: "none", libc: "glibc" }).data).toEqual({
      server: "none",
      package: null,
      libc: "glibc",
      pamLinked: null,
      config: null,
    });
    // Paths must be absolute; too many files are refused as a whole.
    expect(
      sshdFactsSchema.safeParse({
        server: "openssh",
        libc: "musl",
        config: { read: true, files: ["sshd_config"] },
      }).success,
    ).toBe(false);
  });
});
