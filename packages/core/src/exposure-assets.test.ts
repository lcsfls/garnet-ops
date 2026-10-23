import { describe, expect, it } from "vitest";
import { isVerifyToken } from "./exposure.ts";
import { addressAllowed, checkAsset, isExternalAddress, newVerifyToken } from "./exposure-assets.ts";

describe("checkAsset: host names", () => {
  it("accepts public host names and normalises them", () => {
    expect(checkAsset("Example.COM")).toEqual({ ok: true, kind: "domain", value: "example.com" });
    expect(checkAsset(" www.example.com. ")).toEqual({ ok: true, kind: "domain", value: "www.example.com" });
    expect(checkAsset("a-b.c1.example.org")).toEqual({
      ok: true,
      kind: "domain",
      value: "a-b.c1.example.org",
    });
    expect(checkAsset("xn--bcher-kva.example")).toMatchObject({ ok: false });
    expect(checkAsset("xn--bcher-kva.example.com")).toMatchObject({ ok: true });
  });

  it("converts internationalised names to their ASCII form", () => {
    expect(checkAsset("bücher.example.com")).toEqual({
      ok: true,
      kind: "domain",
      value: "xn--bcher-kva.example.com",
    });
  });

  it("refuses names that are not RFC 1123 host names", () => {
    expect(checkAsset("")).toEqual({ ok: false, problem: "empty" });
    expect(checkAsset("   ")).toEqual({ ok: false, problem: "empty" });
    expect(checkAsset("-bad.example.com")).toEqual({ ok: false, problem: "label" });
    expect(checkAsset("bad-.example.com")).toEqual({ ok: false, problem: "label" });
    expect(checkAsset("under_score.example.com")).toEqual({ ok: false, problem: "label" });
    expect(checkAsset("a..example.com")).toEqual({ ok: false, problem: "label" });
    expect(checkAsset(`${"a".repeat(64)}.example.com`)).toEqual({ ok: false, problem: "label" });
    expect(checkAsset(`${"a.".repeat(130)}com`)).toEqual({ ok: false, problem: "tooLong" });
    expect(checkAsset("intranet")).toEqual({ ok: false, problem: "singleLabel" });
    expect(checkAsset("example.c")).toEqual({ ok: false, problem: "label" });
  });

  it("refuses URLs, paths, ports, users, wildcards and anything with blanks", () => {
    for (const bad of [
      "https://example.com",
      "example.com/path",
      "example.com:8443",
      "user@example.com",
      "exa mple.com",
      "example.com?x=1",
    ]) {
      expect(checkAsset(bad).ok, bad).toBe(false);
    }
    expect(checkAsset("*.example.com")).toEqual({ ok: false, problem: "wildcard" });
  });

  it("refuses names that cannot be public, and numeric tricks that resolvers read as addresses", () => {
    for (const bad of [
      "host.local",
      "host.localhost",
      "host.internal",
      "nas.lan",
      "router.home.arpa",
      "1.0.0.127.in-addr.arpa",
      "site.test",
      "site.invalid",
      "site.example",
      "hidden.onion",
    ]) {
      expect(checkAsset(bad), bad).toEqual({ ok: false, problem: "reservedName" });
    }
    for (const bad of ["127.1", "0x7f.1", "0x7f.0x1", "10.1", "example.123"]) {
      expect(checkAsset(bad), bad).toMatchObject({ ok: false });
    }
  });
});

describe("checkAsset: addresses", () => {
  it("accepts public IPv4 and IPv6 addresses and writes IPv6 in canonical form", () => {
    // 8.8.8.8 and 1.1.1.1 style public addresses are ordinary unicast space; the documentation ranges are not.
    expect(checkAsset("93.184.216.34")).toEqual({ ok: true, kind: "ip", value: "93.184.216.34" });
    expect(checkAsset("[2606:2800:220:1:248:1893:25c8:1946]")).toEqual({
      ok: true,
      kind: "ip",
      value: "2606:2800:220:1:248:1893:25c8:1946",
    });
    expect(checkAsset("2606:2800:0220:0001:0248:1893:25C8:1946")).toMatchObject({
      ok: true,
      value: "2606:2800:220:1:248:1893:25c8:1946",
    });
  });

  it("refuses private, loopback, link-local, shared, documentation and reserved addresses", () => {
    for (const bad of [
      "10.0.0.1",
      "172.16.5.4",
      "192.168.1.10",
      "127.0.0.1",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
      "192.0.2.10",
      "198.51.100.10",
      "203.0.113.10",
      "198.18.0.1",
      "::1",
      "::",
      "fe80::1",
      "fc00::1",
      "fd12:3456::1",
      "2001:db8::1",
      "::ffff:93.184.216.34",
      "64:ff9b::7f00:1",
      "64:ff9b::5db8:d822",
      "2002:5db8:d822::1",
    ]) {
      expect(checkAsset(bad), bad).toEqual({ ok: false, problem: "notPublic" });
    }
  });

  it("lets tests use documentation and loopback ranges, and only through the explicit hook", () => {
    expect(checkAsset("192.0.2.10", { allowTestRanges: true })).toEqual({
      ok: true,
      kind: "ip",
      value: "192.0.2.10",
    });
    expect(checkAsset("127.0.0.1", { allowTestRanges: true })).toMatchObject({ ok: true });
    // Link-local and metadata addresses stay refused even in tests.
    expect(checkAsset("169.254.169.254", { allowTestRanges: true })).toEqual({
      ok: false,
      problem: "notPublic",
    });
  });
});

describe("address policy for connections", () => {
  it("allows public unicast addresses only", () => {
    expect(isExternalAddress("93.184.216.34")).toBe(true);
    expect(isExternalAddress("2606:2800:220:1:248:1893:25c8:1946")).toBe(true);
    for (const bad of [
      "127.0.0.1",
      "10.1.2.3",
      "192.0.2.1",
      "169.254.169.254",
      "::1",
      "2001:db8::5",
      "fe80::1",
    ]) {
      expect(isExternalAddress(bad), bad).toBe(false);
    }
  });

  it("opens loopback and documentation ranges for tests only", () => {
    expect(addressAllowed("127.0.0.1")).toBe(false);
    expect(addressAllowed("127.0.0.1", true)).toBe(true);
    expect(addressAllowed("192.0.2.4", true)).toBe(true);
    expect(addressAllowed("169.254.169.254", true)).toBe(false);
    expect(addressAllowed("0.0.0.0", true)).toBe(false);
    // Private networks stay refused under the test policy, so tests can prove the refusal.
    for (const bad of ["10.0.0.5", "192.168.1.1", "172.16.0.9", "100.64.0.1", "fc00::1"]) {
      expect(addressAllowed(bad, true), bad).toBe(false);
    }
  });
});

describe("verification tokens", () => {
  it("are 256 random bits, unique and url safe", () => {
    const a = newVerifyToken();
    const b = newVerifyToken();
    expect(a).not.toEqual(b);
    expect(isVerifyToken(a)).toBe(true);
    expect(Buffer.from(a, "base64url")).toHaveLength(32);
  });
});
