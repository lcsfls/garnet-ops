import { describe, expect, it } from "vitest";
import {
  ACTIVE_LIMITS,
  type ActiveSnapshot,
  CAPTURED_HEADERS,
  challengeName,
  countBySeverity,
  daysToExpiry,
  dmarcPolicy,
  EXPOSURE_ERRORS,
  EXPOSURE_PORTS,
  effectiveVerification,
  evaluateActive,
  evaluatePassive,
  expiryLevel,
  expiryWarningDue,
  fileMatchesToken,
  isRiskyService,
  isSameSite,
  mayFollowRedirect,
  newOpenPorts,
  type PassiveSnapshot,
  type PortResult,
  parseHsts,
  plainText,
  portSpec,
  registrableDomain,
  sanitizeBanner,
  spfPolicy,
  spfRecords,
  type TlsSnapshot,
  tlsFindings,
  txtMatchesToken,
  unjudgedRules,
  type VerifiableAsset,
  verifyFileUrl,
  verifyRecordValue,
} from "./exposure.ts";

const TOKEN = "A".repeat(43);
const NOW = new Date("2026-10-22T12:00:00Z");

describe("plain text from remote systems", () => {
  it("strips control and bidirectional characters and collapses blanks", () => {
    expect(plainText("Apache/2.4\u0000\u0007 ‮evil⁩\t  ok")).toBe("Apache/2.4 evil ok");
    expect(plainText("a b\u0085c")).toBe("a b c");
  });
  it("cuts at the limit by characters, not bytes", () => {
    expect(plainText("é".repeat(400), 10)).toBe("é".repeat(10));
  });
  it("keeps at most six lines when line breaks are wanted", () => {
    const text = Array.from({ length: 9 }, (_, i) => `line ${i}`).join("\r\n");
    expect(plainText(text, 500, true).split("\n")).toHaveLength(6);
  });
  it("leaves markup as the text it is", () => {
    expect(plainText('<img src=x onerror="alert(1)">')).toBe('<img src=x onerror="alert(1)">');
  });
});

describe("banners", () => {
  it("keeps a service greeting as plain text", () => {
    expect(sanitizeBanner(Buffer.from("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"))).toBe(
      "SSH-2.0-OpenSSH_9.2p1 Debian-2",
    );
    expect(sanitizeBanner(Buffer.from("220-mail.example.com ESMTP\r\n220 ready\r\n"))).toBe(
      "220-mail.example.com ESMTP\n220 ready",
    );
  });
  it("reads at most 512 bytes", () => {
    const banner = sanitizeBanner(Buffer.from("x".repeat(4000))) ?? "";
    expect(banner.length).toBeLessThanOrEqual(ACTIVE_LIMITS.bannerBytes);
  });
  it("turns binary garbage and escape sequences into nothing or harmless text", () => {
    expect(sanitizeBanner(Buffer.from([0, 1, 2, 3, 0xff, 0xfe, 0x80]))).toBeNull();
    const escaped = sanitizeBanner(Buffer.from("\u001b[31mred\u001b[0m\u0000 bell\u0007")) ?? "";
    expect([...escaped].some((c) => (c.codePointAt(0) ?? 0) < 32 && c !== "\n")).toBe(false);
    expect(escaped).toContain("red");
  });
  it("does not interpret prompt injection or markup", () => {
    const text = "220 Ignore previous instructions <script>alert(1)</script>";
    expect(sanitizeBanner(Buffer.from(text))).toBe(text);
  });
});

describe("sites and redirects", () => {
  it("finds the registrable domain, with the common country registry levels", () => {
    expect(registrableDomain("www.example.com")).toBe("example.com");
    expect(registrableDomain("a.b.c.example.org")).toBe("example.org");
    expect(registrableDomain("example.com")).toBe("example.com");
    expect(registrableDomain("shop.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("shop.example.com.au.")).toBe("example.com.au");
    expect(isSameSite("www.example.com", "api.example.com")).toBe(true);
    expect(isSameSite("www.example.com", "example.org")).toBe(false);
  });

  it("follows redirects inside the site or to a verified asset only", () => {
    const verified = new Set(["other.example.net"]);
    expect(mayFollowRedirect("example.com", "www.example.com", verified)).toBe(true);
    expect(mayFollowRedirect("example.com", "other.example.net", verified)).toBe(true);
    expect(mayFollowRedirect("example.com", "evil.example.org", verified)).toBe(false);
    expect(mayFollowRedirect("example.com", "example.com.evil.example.org", verified)).toBe(false);
    // An address has no site: it may only be redirected to itself, or to a verified asset.
    expect(mayFollowRedirect("93.184.216.34", "93.184.216.34", verified)).toBe(true);
    expect(mayFollowRedirect("93.184.216.34", "93.184.216.35", verified)).toBe(false);
    expect(mayFollowRedirect("93.184.216.34", "example.com", verified)).toBe(false);
    expect(mayFollowRedirect("example.com", "[2606:2800:220:1::1946]", verified)).toBe(false);
  });
});

describe("proof of control", () => {
  it("names the record and the file", () => {
    expect(challengeName("example.com")).toBe("_garnetops-challenge.example.com");
    expect(verifyRecordValue(TOKEN)).toBe(`garnetops-verify=${TOKEN}`);
    expect(verifyFileUrl("example.com")).toBe("https://example.com/.well-known/garnetops-verify.txt");
    expect(verifyFileUrl("2606:2800:220:1::1946", "http")).toBe(
      "http://[2606:2800:220:1::1946]/.well-known/garnetops-verify.txt",
    );
  });

  it("accepts the TXT record, also when the resolver splits it into strings", () => {
    const value = verifyRecordValue(TOKEN);
    expect(txtMatchesToken([[value]], TOKEN)).toBe(true);
    expect(txtMatchesToken([[value.slice(0, 20), value.slice(20)]], TOKEN)).toBe(true);
    expect(txtMatchesToken([["v=spf1 -all"], [` ${value} `]], TOKEN)).toBe(true);
  });

  it("refuses a record that is not exactly the proof", () => {
    const value = verifyRecordValue(TOKEN);
    expect(txtMatchesToken([], TOKEN)).toBe(false);
    expect(txtMatchesToken([[`${value}x`]], TOKEN)).toBe(false);
    expect(txtMatchesToken([[`x${value}`]], TOKEN)).toBe(false);
    expect(txtMatchesToken([[verifyRecordValue("B".repeat(43))]], TOKEN)).toBe(false);
    expect(txtMatchesToken([[TOKEN]], TOKEN)).toBe(false);
    expect(txtMatchesToken([[`garnetops-verify=${TOKEN.toLowerCase()}`]], TOKEN)).toBe(false);
    // A token that is not a token never matches, so an empty value cannot be proven by an empty answer.
    expect(txtMatchesToken([[""], ["garnetops-verify="]], "")).toBe(false);
  });

  it("accepts the file with the bare token or the record form, on a line of its own", () => {
    expect(fileMatchesToken(TOKEN, TOKEN)).toBe(true);
    expect(fileMatchesToken(`${TOKEN}\n`, TOKEN)).toBe(true);
    expect(fileMatchesToken(`# note\r\n${verifyRecordValue(TOKEN)}\r\n`, TOKEN)).toBe(true);
    expect(fileMatchesToken(`prefix ${TOKEN}`, TOKEN)).toBe(false);
    expect(fileMatchesToken(`${TOKEN}x`, TOKEN)).toBe(false);
    expect(fileMatchesToken("", TOKEN)).toBe(false);
    // Too large an answer is no proof, however it ends.
    expect(fileMatchesToken(`${"x".repeat(2000)}\n${TOKEN}`, TOKEN)).toBe(false);
  });

  const asset = (over: Partial<VerifiableAsset> & { id: string; value: string }): VerifiableAsset => ({
    kind: "domain",
    verifyState: "unverified",
    includeSubdomains: false,
    ...over,
  });

  it("covers subdomains only when the verified parent includes them", () => {
    const parent = asset({ id: "p", value: "example.com", verifyState: "verified", includeSubdomains: true });
    const child = asset({ id: "c", value: "www.example.com" });
    const deep = asset({ id: "d", value: "a.b.example.com" });
    const other = asset({ id: "o", value: "example.org" });
    const lookalike = asset({ id: "l", value: "badexample.com" });
    const all = [parent, child, deep, other, lookalike];
    expect(effectiveVerification(parent, all)).toEqual({ verified: true, via: "self", parentId: null });
    expect(effectiveVerification(child, all)).toEqual({ verified: true, via: "parent", parentId: "p" });
    expect(effectiveVerification(deep, all).verified).toBe(true);
    expect(effectiveVerification(other, all).verified).toBe(false);
    expect(effectiveVerification(lookalike, all).verified).toBe(false);
  });

  it("does not cover subdomains by default, nor when the parent lost its proof, nor an address", () => {
    const child = asset({ id: "c", value: "www.example.com" });
    const closed = asset({ id: "p", value: "example.com", verifyState: "verified" });
    expect(effectiveVerification(child, [closed, child]).verified).toBe(false);
    const lost = asset({ id: "p", value: "example.com", verifyState: "lost", includeSubdomains: true });
    expect(effectiveVerification(child, [lost, child]).verified).toBe(false);
    const ip = asset({ id: "i", kind: "ip", value: "93.184.216.34" });
    const open = asset({ id: "p", value: "example.com", verifyState: "verified", includeSubdomains: true });
    expect(effectiveVerification(ip, [open, ip]).verified).toBe(false);
  });
});

describe("DNS policies", () => {
  it("finds SPF records and reads the all mechanism", () => {
    expect(spfRecords([["v=spf1 include:_spf.example.net -all"], ["google-site-verification=abc"]])).toEqual([
      "v=spf1 include:_spf.example.net -all",
    ]);
    expect(spfRecords([["v=spf1"], ["v=spf10 foo"]])).toEqual(["v=spf1"]);
    expect(spfPolicy("v=spf1 mx -all")).toBe("fail");
    expect(spfPolicy("v=spf1 mx ~all")).toBe("softfail");
    expect(spfPolicy("v=spf1 mx ?all")).toBe("neutral");
    expect(spfPolicy("v=spf1 mx +all")).toBe("pass");
    expect(spfPolicy("v=spf1 mx all")).toBe("pass");
    expect(spfPolicy("v=spf1 redirect=_spf.example.net")).toBe("redirect");
    expect(spfPolicy("v=spf1 mx")).toBe("none");
    expect(spfPolicy(undefined)).toBe("none");
  });

  it("reads the DMARC policy and ignores records that are not DMARC", () => {
    expect(dmarcPolicy([["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]])).toBe("reject");
    expect(dmarcPolicy([["v=DMARC1;p=none"]])).toBe("none");
    expect(dmarcPolicy([["v=DMARC1; P=Quarantine ; pct=50"]])).toBe("quarantine");
    expect(dmarcPolicy([["v=DMARC1; rua=mailto:x@example.com"]])).toBeNull();
    expect(dmarcPolicy([["v=DMARC1; p=banana"]])).toBeNull();
    expect(dmarcPolicy([["p=reject"]])).toBeNull();
    expect(dmarcPolicy([["v=DMARC", "1; p=reject"]])).toBe("reject");
    expect(dmarcPolicy([])).toBeNull();
  });
});

describe("security headers", () => {
  it("reads HSTS", () => {
    expect(parseHsts("max-age=31536000; includeSubDomains; preload")).toEqual({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    });
    expect(parseHsts('max-age="600"')).toMatchObject({ maxAge: 600 });
    expect(parseHsts("includeSubDomains")).toBeNull();
    expect(parseHsts("max-age=abc")).toBeNull();
    expect(parseHsts(undefined)).toBeNull();
  });
  it("keeps a fixed list of response headers", () => {
    expect(CAPTURED_HEADERS).toContain("server");
    expect(CAPTURED_HEADERS).not.toContain("set-cookie");
    expect(CAPTURED_HEADERS).not.toContain("authorization");
  });
});

const tls = (over: Partial<TlsSnapshot> = {}): TlsSnapshot => ({
  address: "93.184.216.34",
  port: 443,
  ok: true,
  error: null,
  protocol: "TLSv1.3",
  cipher: "TLS_AES_256_GCM_SHA384",
  trusted: true,
  trustError: null,
  nameMatches: true,
  cert: {
    subject: "example.com",
    issuer: "Example CA",
    sans: ["example.com"],
    validFrom: "2026-09-01T00:00:00Z",
    validTo: "2027-01-01T00:00:00Z",
    fingerprint: "AA:BB",
    keyType: "ec",
    keyBits: 256,
    selfSigned: false,
  },
  chainLength: 2,
  legacy: { tls10: false, tls11: false },
  ...over,
});

const goodHeaders = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=()",
};

function passive(over: Partial<PassiveSnapshot> = {}): PassiveSnapshot {
  return {
    version: 1,
    takenAt: NOW.toISOString(),
    kind: "domain",
    name: "example.com",
    addresses: ["93.184.216.34"],
    nonPublic: [],
    ptr: [],
    dns: {
      a: ["93.184.216.34"],
      aaaa: [],
      cname: [],
      mx: [{ priority: 10, exchange: "mail.example.com" }],
      ns: ["ns1.example.com"],
      caa: [{ critical: false, tag: "issue", value: "ca.example.net" }],
      caaFound: true,
      failed: [],
      spf: { records: 1, policy: "fail", record: "v=spf1 mx -all" },
      dmarc: { found: true, policy: "reject", record: "v=DMARC1; p=reject" },
      dnssec: "unknown",
    },
    tls: [tls()],
    http: {
      address: "93.184.216.34",
      url: "https://example.com/",
      finalUrl: "https://example.com/",
      status: 200,
      redirects: [],
      headers: goodHeaders,
      error: null,
    },
    plain: {
      address: "93.184.216.34",
      status: 301,
      location: "https://example.com/",
      redirectsToHttps: true,
      error: null,
    },
    geo: [],
    resolves: true,
    httpsOpen: true,
    ...over,
  };
}

const rules = (snapshot: PassiveSnapshot) =>
  evaluatePassive(snapshot, NOW)
    .map((f) => f.rule)
    .sort();

describe("TLS rules", () => {
  it("count the days to expiry and map them to warning levels", () => {
    expect(daysToExpiry("2026-11-01T12:00:00Z", NOW)).toBe(10);
    expect(daysToExpiry("2026-10-22T11:00:00Z", NOW)).toBe(-1);
    expect(expiryLevel(45)).toBeNull();
    expect(expiryLevel(31)).toBeNull();
    expect(expiryLevel(30)).toBe(30);
    expect(expiryLevel(15)).toBe(30);
    expect(expiryLevel(14)).toBe(14);
    expect(expiryLevel(8)).toBe(14);
    expect(expiryLevel(7)).toBe(7);
    expect(expiryLevel(0)).toBe(7);
    expect(expiryLevel(-1)).toBe(0);
  });

  it("warn once per step and again when a more urgent step is reached", () => {
    expect(expiryWarningDue(null, null)).toBe(false);
    expect(expiryWarningDue(30, null)).toBe(true);
    expect(expiryWarningDue(30, 30)).toBe(false);
    expect(expiryWarningDue(14, 30)).toBe(true);
    expect(expiryWarningDue(7, 14)).toBe(true);
    expect(expiryWarningDue(0, 7)).toBe(true);
    expect(expiryWarningDue(14, 7)).toBe(false);
    // A renewed certificate resets the announcement: the level is null, then 30 again is news.
    expect(expiryWarningDue(null, 7)).toBe(false);
    expect(expiryWarningDue(30, null)).toBe(true);
  });

  it("call an expired certificate high, and an expiring one by the days left", () => {
    const expired = tls({
      cert: { ...(tls().cert as object), validTo: "2026-10-01T00:00:00Z" } as never,
      trusted: false,
    });
    expect(tlsFindings(expired, NOW, "passive")).toEqual([
      expect.objectContaining({
        rule: "tlsExpired",
        severity: "high",
        subject: "443",
        params: expect.objectContaining({ days: 22 }),
      }),
    ]);
    const soon = (validTo: string) =>
      tlsFindings(tls({ cert: { ...(tls().cert as object), validTo } as never }), NOW, "passive");
    expect(soon("2026-10-28T12:00:00Z")[0]).toMatchObject({ rule: "tlsExpiring", severity: "high" });
    expect(soon("2026-11-04T12:00:00Z")[0]).toMatchObject({ rule: "tlsExpiring", severity: "medium" });
    expect(soon("2026-11-15T12:00:00Z")[0]).toMatchObject({ rule: "tlsExpiring", severity: "low" });
    expect(soon("2026-12-15T12:00:00Z")).toEqual([]);
  });

  it("report an untrusted chain, a wrong name, a weak key and old protocol versions", () => {
    expect(
      tlsFindings(tls({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT" }), NOW, "passive"),
    ).toEqual([expect.objectContaining({ rule: "tlsUntrusted", severity: "medium" })]);
    expect(tlsFindings(tls({ trusted: false, nameMatches: false }), NOW, "passive")[0]).toMatchObject({
      rule: "tlsNameMismatch",
    });
    const weak = tls({ cert: { ...(tls().cert as object), keyType: "rsa", keyBits: 1024 } as never });
    expect(tlsFindings(weak, NOW, "passive")[0]).toMatchObject({
      rule: "tlsWeakKey",
      params: { bits: 1024 },
    });
    const ok = tls({ cert: { ...(tls().cert as object), keyType: "rsa", keyBits: 2048 } as never });
    expect(tlsFindings(ok, NOW, "passive")).toEqual([]);
    const legacy = tlsFindings(tls({ legacy: { tls10: true, tls11: true } }), NOW, "passive");
    expect(legacy).toEqual([
      expect.objectContaining({
        rule: "tlsLegacyProtocol",
        severity: "medium",
        params: expect.objectContaining({ versions: "TLS 1.0, TLS 1.1" }),
      }),
    ]);
    expect(
      tlsFindings(tls({ legacy: { tls10: false, tls11: true } }), NOW, "passive")[0]?.params.versions,
    ).toBe("TLS 1.1");
    expect(tlsFindings(tls({ legacy: null }), NOW, "passive")).toEqual([]);
  });

  it("use the port as subject so a second TLS port is its own finding", () => {
    const f = tlsFindings(tls({ port: 8443, trusted: false }), NOW, "active");
    expect(f[0]).toMatchObject({ subject: "8443", stage: "active" });
  });
});

describe("passive rules", () => {
  it("find nothing wrong with a well configured site", () => {
    expect(rules(passive())).toEqual([]);
  });

  it("list every missing security header on its own", () => {
    const bare = passive({
      http: { ...(passive().http as object), headers: { server: "nginx" } } as never,
    });
    expect(rules(bare)).toEqual([
      "httpCspMissing",
      "httpFramingMissing",
      "httpHstsMissing",
      "httpNosniffMissing",
      "httpPermissionsPolicyMissing",
      "httpReferrerPolicyMissing",
    ]);
  });

  it("take frame-ancestors or X-Frame-Options as framing protection, and HSTS under 180 days as weak", () => {
    const xfo = passive({
      http: {
        ...(passive().http as object),
        headers: {
          ...goodHeaders,
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
        },
      } as never,
    });
    expect(rules(xfo)).toEqual([]);
    const weak = passive({
      http: {
        ...(passive().http as object),
        headers: { ...goodHeaders, "strict-transport-security": "max-age=600" },
      } as never,
    });
    expect(rules(weak)).toEqual(["httpHstsWeak"]);
  });

  it("do not ask for HSTS on a page that was only served over plain HTTP", () => {
    const http = passive({
      httpsOpen: false,
      tls: [],
      http: {
        ...(passive().http as object),
        url: "http://example.com/",
        finalUrl: "http://example.com/",
        headers: goodHeaders,
      } as never,
      plain: { address: "93.184.216.34", status: 200, location: null, redirectsToHttps: false, error: null },
    });
    expect(rules(http)).toEqual(["httpNoHttps"]);
  });

  it("call out a banner with a version number, and show the banner", () => {
    const banner = passive({
      http: {
        ...(passive().http as object),
        headers: { ...goodHeaders, server: "nginx/1.22.1", "x-powered-by": "PHP/8.2.7" },
      } as never,
    });
    const found = evaluatePassive(banner, NOW).filter((f) => f.rule === "httpBannerVersion");
    expect(found.map((f) => f.params.banner)).toEqual(["nginx/1.22.1", "PHP/8.2.7"]);
    const plain = passive({
      http: { ...(passive().http as object), headers: { ...goodHeaders, server: "nginx" } } as never,
    });
    expect(rules(plain)).toEqual([]);
    const apache = passive({
      http: {
        ...(passive().http as object),
        headers: { ...goodHeaders, server: "Apache/2.4.57 (Debian)" },
      } as never,
    });
    expect(rules(apache)).toEqual(["httpBannerVersion"]);
  });

  it("flag plain HTTP that does not redirect while HTTPS is open", () => {
    const open = passive({
      plain: { address: "93.184.216.34", status: 200, location: null, redirectsToHttps: false, error: null },
    });
    expect(evaluatePassive(open, NOW).map((f) => f.rule)).toEqual(["httpNoRedirectToHttps"]);
  });

  it("find missing mail authentication, weaker with no mail server", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    const noMail = passive({
      dns: {
        ...dns,
        mx: [],
        spf: { records: 0, policy: "none", record: null },
        dmarc: { found: false, policy: null, record: null },
        caaFound: false,
      },
    });
    const found = evaluatePassive(noMail, NOW);
    expect(found.map((f) => [f.rule, f.severity])).toEqual(
      expect.arrayContaining([
        ["dnsNoSpf", "low"],
        ["dnsNoDmarc", "low"],
        ["dnsNoCaa", "low"],
      ]),
    );
    const mail = passive({
      dns: {
        ...dns,
        spf: { records: 0, policy: "none", record: null },
        dmarc: { found: false, policy: null, record: null },
      },
    });
    const severities = Object.fromEntries(evaluatePassive(mail, NOW).map((f) => [f.rule, f.severity]));
    expect(severities).toMatchObject({ dnsNoSpf: "medium", dnsNoDmarc: "medium" });
  });

  it("find a permissive SPF record, several SPF records and DMARC p=none", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    expect(
      rules(passive({ dns: { ...dns, spf: { records: 1, policy: "pass", record: "v=spf1 +all" } } })),
    ).toEqual(["dnsSpfPermissive"]);
    expect(
      rules(passive({ dns: { ...dns, spf: { records: 1, policy: "neutral", record: "v=spf1 ?all" } } })),
    ).toEqual(["dnsSpfPermissive"]);
    expect(
      rules(passive({ dns: { ...dns, spf: { records: 1, policy: "softfail", record: "v=spf1 ~all" } } })),
    ).toEqual([]);
    expect(
      rules(passive({ dns: { ...dns, spf: { records: 2, policy: "fail", record: "v=spf1 -all" } } })),
    ).toEqual(["dnsSpfMultiple"]);
    expect(
      rules(passive({ dns: { ...dns, dmarc: { found: true, policy: "none", record: "v=DMARC1; p=none" } } })),
    ).toEqual(["dnsDmarcNone"]);
    expect(
      rules(
        passive({
          dns: { ...dns, dmarc: { found: true, policy: "quarantine", record: "v=DMARC1; p=quarantine" } },
        }),
      ),
    ).toEqual([]);
  });

  it("stay silent about records whose lookup failed instead of guessing", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    const blind = passive({
      dns: {
        ...dns,
        failed: ["txt", "dmarc", "caa"],
        caaFound: false,
        spf: { records: 0, policy: "none", record: null },
        dmarc: { found: false, policy: null, record: null },
      },
    });
    expect(rules(blind)).toEqual([]);
  });

  it("find a dangling CNAME and an address that is not public", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    const dangling = passive({
      resolves: false,
      addresses: [],
      tls: [],
      http: null,
      plain: null,
      dns: { ...dns, a: [], cname: ["gone.example.net"] },
    });
    expect(rules(dangling)).toContain("dnsDanglingCname");
    const internal = passive({ nonPublic: ["10.0.0.5"], addresses: [], tls: [], http: null, plain: null });
    expect(
      evaluatePassive(internal, NOW).find((f) => f.rule === "dnsNonPublicAddress")?.params.addresses,
    ).toBe("10.0.0.5");
  });

  it("take the worst certificate when several addresses answer", () => {
    const bad = tls({
      address: "93.184.216.35",
      trusted: false,
      trustError: "CERT_HAS_EXPIRED",
      cert: { ...(tls().cert as object), validTo: "2026-10-01T00:00:00Z" } as never,
    });
    const found = evaluatePassive(passive({ tls: [tls(), bad] }), NOW);
    expect(found.filter((f) => f.rule === "tlsExpired")).toHaveLength(1);
  });

  it("never produces a finding outside the four severities", () => {
    const all = evaluatePassive(
      passive({
        dns: null,
        http: { ...(passive().http as object), headers: {} } as never,
        nonPublic: ["10.0.0.1"],
      }),
      NOW,
    );
    expect(all.every((f) => ["critical", "high", "medium", "low"].includes(f.severity))).toBe(true);
    expect(countBySeverity(all).low).toBeGreaterThan(0);
  });
});

describe("rules a snapshot could not judge", () => {
  it("is empty for a complete snapshot", () => {
    expect(unjudgedRules(passive())).toEqual([]);
  });
  it("leaves the DNS rules of failed lookups alone", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    const out = unjudgedRules(passive({ dns: { ...dns, failed: ["txt", "caa"] } }));
    expect(out).toEqual(expect.arrayContaining(["dnsNoSpf", "dnsSpfPermissive", "dnsNoCaa"]));
    expect(out).not.toContain("dnsNoDmarc");
  });
  it("leaves TLS and header rules alone when the servers did not answer in time", () => {
    const silent = passive({
      tls: [tls({ ok: false, error: "timeout", cert: null })],
      http: { ...(passive().http as object), status: null, error: "timeout" } as never,
    });
    expect(unjudgedRules(silent)).toEqual(expect.arrayContaining(["tlsExpired", "httpCspMissing"]));
  });
  it("judges a closed port: nothing listening is an answer", () => {
    const closed = passive({
      httpsOpen: false,
      tls: [tls({ ok: false, error: "refused", cert: null })],
      http: null,
    });
    expect(unjudgedRules(closed)).toEqual([]);
  });
  it("judges nothing when the name could not be looked up", () => {
    const dns = passive().dns as NonNullable<PassiveSnapshot["dns"]>;
    const blind = passive({
      addresses: [],
      tls: [],
      http: null,
      plain: null,
      resolves: false,
      dns: { ...dns, failed: ["a", "aaaa"] },
    });
    expect(unjudgedRules(blind)).toEqual(
      expect.arrayContaining(["tlsExpired", "httpCspMissing", "dnsDanglingCname"]),
    );
  });
});

describe("the port list of stage 2", () => {
  it("is the documented list and nothing else", () => {
    expect(EXPOSURE_PORTS.map((p) => p.port)).toEqual([
      21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306,
      3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017,
    ]);
    expect(new Set(EXPOSURE_PORTS.map((p) => p.port)).size).toBe(EXPOSURE_PORTS.length);
  });

  it("reads a banner only where the service speaks first, and starts TLS only on TLS ports", () => {
    expect(EXPOSURE_PORTS.filter((p) => p.banner).map((p) => p.port)).toEqual([21, 22, 25, 110, 143, 587]);
    expect(EXPOSURE_PORTS.filter((p) => p.tls).map((p) => p.port)).toEqual([443, 465, 993, 995, 2376, 8443]);
    // A port is never both: a service that starts with TLS does not greet first.
    expect(EXPOSURE_PORTS.filter((p) => p.banner && p.tls)).toEqual([]);
  });

  it("assigns the documented severity to the risky services", () => {
    const sev = (port: number) => portSpec(port)?.severity ?? null;
    expect(sev(2375)).toBe("critical");
    for (const port of [23, 445, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]) {
      expect(sev(port), String(port)).toBe("high");
    }
    expect(sev(21)).toBe("medium");
    expect(sev(2376)).toBe("medium");
    expect(sev(110)).toBe("low");
    expect(sev(22)).toBeNull();
    expect(sev(443)).toBeNull();
    expect(isRiskyService("high")).toBe(true);
    expect(isRiskyService("critical")).toBe(true);
    expect(isRiskyService("medium")).toBe(false);
    expect(isRiskyService(null)).toBe(false);
  });
});

describe("active rules", () => {
  const open = (port: number, address = "93.184.216.34"): PortResult => {
    const spec = portSpec(port) as NonNullable<ReturnType<typeof portSpec>>;
    return {
      address,
      port,
      service: spec.service,
      category: spec.category,
      severity: spec.severity,
      banner: null,
      tls: null,
    };
  };
  const snapshot = (ports: PortResult[]): ActiveSnapshot => ({
    version: 1,
    takenAt: NOW.toISOString(),
    addresses: ["93.184.216.34"],
    open: ports,
    checked: 30,
    closed: 30 - ports.length,
    noAnswer: 0,
    stopped: null,
  });

  it("reports unusual open ports once per port, with the addresses", () => {
    const found = evaluateActive(
      snapshot([open(22), open(3389), open(3389, "93.184.216.35"), open(2375), open(80)]),
      NOW,
    );
    expect(found.map((f) => [f.rule, f.subject, f.severity]).sort()).toEqual([
      ["portExposed", "2375", "critical"],
      ["portExposed", "3389", "high"],
    ]);
    expect(found.find((f) => f.subject === "3389")?.params.addresses).toBe("93.184.216.34, 93.184.216.35");
  });

  it("applies the TLS rules to other TLS ports and leaves 443 to stage 1", () => {
    const expired = tls({
      port: 8443,
      cert: { ...(tls().cert as object), validTo: "2026-10-01T00:00:00Z" } as never,
      trusted: false,
    });
    const found = evaluateActive(
      snapshot([
        { ...open(8443), tls: expired },
        { ...open(443), tls: expired },
      ]),
      NOW,
    );
    expect(found.map((f) => [f.rule, f.subject])).toEqual([["tlsExpired", "8443"]]);
  });

  it("finds ports that are new since the last run", () => {
    const before = [{ address: "93.184.216.34", port: 22 }];
    const now = [
      { address: "93.184.216.34", port: 22 },
      { address: "93.184.216.34", port: 3306 },
      { address: "93.184.216.35", port: 22 },
    ];
    expect(newOpenPorts(now, before)).toEqual([
      { address: "93.184.216.34", port: 3306 },
      { address: "93.184.216.35", port: 22 },
    ]);
    expect(newOpenPorts([], before)).toEqual([]);
  });
});

describe("limits and codes", () => {
  it("fix the active limits the documentation promises", () => {
    expect(ACTIVE_LIMITS).toMatchObject({
      concurrency: 4,
      gapMs: 200,
      connectTimeoutMs: 3000,
      bannerReadMs: 2000,
      bannerBytes: 512,
      minIntervalHours: 24,
    });
  });
  it("has a distinct code for every error", () => {
    expect(new Set(EXPOSURE_ERRORS).size).toBe(EXPOSURE_ERRORS.length);
  });
});
