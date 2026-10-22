import { describe, expect, it } from "vitest";
import {
  aiBaseUrlProblem,
  classifyAddress,
  decideEndpoint,
  endpointHost,
  inNetwork,
  isOverlayAddress,
  normalizeBaseUrl,
} from "./ai-endpoint.ts";

describe("address classes", () => {
  it("treats private network addresses as the customer's network", () => {
    for (const a of [
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.254",
      "192.168.1.10",
      "100.64.0.5",
      "100.127.255.1",
      "fd12:3456::1",
      "fc00::1",
      "::ffff:192.168.1.10",
      "::ffff:c0a8:10a",
    ]) {
      expect(classifyAddress(a), a).toBe("private");
    }
  });

  it("refuses loopback, link-local, metadata, unspecified, multicast and reserved addresses in every notation", () => {
    for (const a of [
      "127.0.0.1",
      "127.1.2.3",
      "0.0.0.0",
      "169.254.169.254",
      "224.0.0.1",
      "255.255.255.255",
      "240.0.0.1",
      "100.100.100.200",
      "::1",
      "::",
      "0:0:0:0:0:0:0:1",
      "fe80::1",
      "febf::1",
      "fec0::1",
      "ff02::1",
      "fd00:ec2::254",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "0:0:0:0:0:ffff:7f00:1",
      "::ffff:169.254.169.254",
      "::ffff:a9fe:a9fe",
      "64:ff9b::7f00:1",
      "2002:7f00:1::1",
      "::7f00:1",
      "not an address",
      "",
    ]) {
      expect(classifyAddress(a), a).toBe("forbidden");
    }
  });

  it("calls everything else public", () => {
    for (const a of [
      "8.8.8.8",
      "100.63.255.255",
      "100.128.0.1",
      "172.15.0.1",
      "172.32.0.1",
      "192.0.2.1",
      "2001:db8::1",
      "2606:4700::1",
      "::ffff:8.8.8.8",
    ]) {
      expect(classifyAddress(a), a).toBe("public");
    }
  });

  it("allows loopback only when a test says so", () => {
    expect(classifyAddress("127.0.0.1", true)).toBe("private");
    expect(classifyAddress("::1", true)).toBe("private");
    expect(classifyAddress("169.254.169.254", true)).toBe("forbidden");
  });
});

describe("the decision for an endpoint", () => {
  it("accepts private addresses over https", () => {
    expect(decideEndpoint("https:", ["192.168.1.5"], false)).toEqual({
      ok: true,
      scope: "private",
      error: null,
    });
    expect(decideEndpoint("https:", ["10.0.0.1", "fd00::1"], false)).toEqual({
      ok: true,
      scope: "private",
      error: null,
    });
  });
  it("refuses plain http to other private addresses", () => {
    for (const a of ["192.168.1.5", "10.0.0.1", "172.16.0.9", "fd00::1", "::ffff:192.168.1.5"]) {
      expect(decideEndpoint("http:", [a], false), a).toEqual({
        ok: false,
        scope: "private",
        error: "insecure-private",
      });
    }
    // one LAN address among several is enough
    expect(decideEndpoint("http:", ["100.64.0.20", "192.168.1.5"], false).error).toBe("insecure-private");
  });
  it("accepts plain http inside the VPN overlay range", () => {
    const ok = { ok: true, scope: "private", error: null };
    expect(decideEndpoint("http:", ["100.64.0.20"], false)).toEqual(ok);
    expect(decideEndpoint("http:", ["100.127.255.254", "100.100.1.1"], false)).toEqual(ok);
    expect(decideEndpoint("http:", ["::ffff:100.64.0.20"], false)).toEqual(ok);
    expect(decideEndpoint("http:", ["::ffff:6440:14"], false)).toEqual(ok);
  });
  it("accepts plain http inside a network of the machine that connects", () => {
    const localNetworks = ["172.18.0.5/16", "fd12:3456::2/64", "10.20.30.40/32"];
    const ok = { ok: true, scope: "private", error: null };
    expect(decideEndpoint("http:", ["172.18.0.2"], false, { localNetworks })).toEqual(ok);
    expect(decideEndpoint("http:", ["::ffff:172.18.255.254"], false, { localNetworks })).toEqual(ok);
    expect(decideEndpoint("http:", ["fd12:3456::7"], false, { localNetworks })).toEqual(ok);
    expect(decideEndpoint("http:", ["10.20.30.40"], false, { localNetworks })).toEqual(ok);
    // every address has to be inside, not just one
    expect(decideEndpoint("http:", ["172.18.0.2", "172.19.0.2"], false, { localNetworks }).error).toBe(
      "insecure-private",
    );
    expect(decideEndpoint("http:", ["10.20.30.41"], false, { localNetworks }).error).toBe("insecure-private");
    expect(decideEndpoint("http:", ["192.168.1.5"], false, { localNetworks }).error).toBe("insecure-private");
    expect(decideEndpoint("http:", ["192.168.1.5"], false, { localNetworks: [] }).error).toBe(
      "insecure-private",
    );
  });
  it("never lets a local network override the forbidden and public rules", () => {
    const localNetworks = ["169.254.0.0/16", "8.8.8.0/24", "127.0.0.0/8"];
    expect(decideEndpoint("http:", ["169.254.169.254"], false, { localNetworks }).error).toBe(
      "address-refused",
    );
    expect(decideEndpoint("http:", ["127.0.0.1"], false, { localNetworks }).error).toBe("address-refused");
    expect(decideEndpoint("http:", ["8.8.8.8"], true, { localNetworks }).error).toBe("insecure-external");
  });
  it("treats loopback as the same host only when a test allows it", () => {
    expect(decideEndpoint("http:", ["127.0.0.1"], false, { allowLoopback: true }).ok).toBe(true);
    expect(decideEndpoint("http:", ["192.168.1.5"], false, { allowLoopback: true }).error).toBe(
      "insecure-private",
    );
  });
  it("refuses when any answer is forbidden, even if others are fine", () => {
    expect(decideEndpoint("https:", ["192.168.1.5", "127.0.0.1"], true).error).toBe("address-refused");
    expect(decideEndpoint("http:", ["169.254.169.254"], true).error).toBe("address-refused");
  });
  it("needs https and an acknowledgement for a public address", () => {
    expect(decideEndpoint("http:", ["8.8.8.8"], true)).toMatchObject({
      ok: false,
      scope: "external",
      error: "insecure-external",
    });
    expect(decideEndpoint("https:", ["8.8.8.8"], false)).toMatchObject({
      ok: false,
      scope: "external",
      error: "external-not-acknowledged",
    });
    expect(decideEndpoint("https:", ["8.8.8.8"], true)).toEqual({ ok: true, scope: "external", error: null });
  });
  it("treats a mixed answer as external", () => {
    expect(decideEndpoint("https:", ["192.168.1.5", "8.8.8.8"], false).error).toBe(
      "external-not-acknowledged",
    );
  });
  it("refuses a name that does not resolve", () => {
    expect(decideEndpoint("https:", [], true).error).toBe("unresolvable");
  });
});

describe("inNetwork", () => {
  it("matches IPv4 addresses by prefix", () => {
    expect(inNetwork("192.0.2.77", "192.0.2.0/24")).toBe(true);
    expect(inNetwork("192.0.3.1", "192.0.2.0/24")).toBe(false);
    expect(inNetwork("172.31.255.255", "172.16.0.0/12")).toBe(true);
    expect(inNetwork("172.32.0.0", "172.16.0.0/12")).toBe(false);
    expect(inNetwork("100.64.0.1", "100.64.0.0/10")).toBe(true);
    expect(inNetwork("100.128.0.1", "100.64.0.0/10")).toBe(false);
    // host bits in the network part are ignored, as interfaces report them
    expect(inNetwork("172.18.0.9", "172.18.0.5/16")).toBe(true);
  });
  it("handles the extreme prefix lengths", () => {
    expect(inNetwork("203.0.113.9", "0.0.0.0/0")).toBe(true);
    expect(inNetwork("::ffff:203.0.113.9", "0.0.0.0/0")).toBe(true);
    expect(inNetwork("203.0.113.9", "203.0.113.9/32")).toBe(true);
    expect(inNetwork("203.0.113.10", "203.0.113.9/32")).toBe(false);
    expect(inNetwork("2001:db8::1", "::/0")).toBe(true);
    expect(inNetwork("2001:db8::1", "2001:db8::1/128")).toBe(true);
    expect(inNetwork("2001:db8::2", "2001:db8::1/128")).toBe(false);
  });
  it("matches IPv6 addresses by prefix in any notation", () => {
    expect(inNetwork("2001:db8:0:1::5", "2001:db8:0:1::/64")).toBe(true);
    expect(inNetwork("2001:0db8:0000:0001:ffff:ffff:ffff:ffff", "2001:db8:0:1::/64")).toBe(true);
    expect(inNetwork("2001:db8:0:2::5", "2001:db8:0:1::/64")).toBe(false);
    expect(inNetwork("fd12:3456::1", "fc00::/7")).toBe(true);
    expect(inNetwork("fe80::1", "fc00::/7")).toBe(false);
    expect(inNetwork("2001:db8::1", "2001:db8::/33")).toBe(true);
    expect(inNetwork("2001:db8:8000::1", "2001:db8::/33")).toBe(false);
  });
  it("matches an IPv4 network against the IPv4-mapped form, in both notations", () => {
    expect(inNetwork("::ffff:192.0.2.7", "192.0.2.0/24")).toBe(true);
    expect(inNetwork("::ffff:c000:207", "192.0.2.0/24")).toBe(true);
    expect(inNetwork("::ffff:192.0.3.7", "192.0.2.0/24")).toBe(false);
    // only the mapped prefix counts, not other addresses that embed an IPv4 address
    expect(inNetwork("64:ff9b::192.0.2.7", "192.0.2.0/24")).toBe(false);
    expect(inNetwork("::192.0.2.7", "192.0.2.0/24")).toBe(false);
  });
  it("never matches an IPv4 address against an IPv6 network", () => {
    expect(inNetwork("192.0.2.7", "::/0")).toBe(false);
    expect(inNetwork("192.0.2.7", "::ffff:192.0.2.0/120")).toBe(false);
  });
  it("is false for anything that does not parse", () => {
    for (const cidr of [
      "192.0.2.0",
      "192.0.2.0/33",
      "192.0.2.0/-1",
      "192.0.2.0/x",
      "/24",
      "foo/24",
      "::/129",
      "",
    ]) {
      expect(inNetwork("192.0.2.1", cidr), cidr).toBe(false);
    }
    expect(inNetwork("not an address", "192.0.2.0/24")).toBe(false);
    expect(inNetwork("", "192.0.2.0/24")).toBe(false);
    expect(inNetwork("192.0.2.1.5", "192.0.2.0/24")).toBe(false);
  });
});

describe("isOverlayAddress", () => {
  it("is the 100.64.0.0/10 range, also mapped", () => {
    for (const a of ["100.64.0.0", "100.100.1.1", "100.127.255.255", "::ffff:100.64.0.20"]) {
      expect(isOverlayAddress(a), a).toBe(true);
    }
    for (const a of ["100.63.255.255", "100.128.0.0", "10.0.0.1", "192.168.1.1", "8.8.8.8", "fd00::1", "x"]) {
      expect(isOverlayAddress(a), a).toBe(false);
    }
  });
});

describe("base URLs", () => {
  it("accepts typical local model servers", () => {
    for (const u of [
      "http://llm.example.lan:8000/v1",
      "http://192.168.1.20:11434/v1",
      "https://llm.example.com/v1",
      "https://llm.example.com",
      "http://[fd00::5]:1234/v1",
      "https://8.8.8.8/v1",
    ]) {
      expect(aiBaseUrlProblem(u), u).toBeNull();
    }
  });
  it("refuses what cannot be right", () => {
    for (const u of [
      "ftp://llm.example.lan/v1",
      "not a url",
      "http://user:pw@llm.example.lan/v1",
      "http://llm.example.lan/v1?key=1",
      "http://llm.example.lan/v1#x",
      "http://localhost:11434/v1",
      "http://ollama.localhost/v1",
      "http://127.0.0.1:8000/v1",
      "http://[::1]:8000/v1",
      "http://[::ffff:7f00:1]/v1",
      "http://169.254.169.254/latest",
      "http://0.0.0.0/v1",
      "http://8.8.8.8/v1",
      "http://llm.example.lan/v 1",
    ]) {
      expect(aiBaseUrlProblem(u), u).not.toBeNull();
    }
  });
  it("stores the URL without a trailing slash and names the host with its port", () => {
    expect(normalizeBaseUrl("http://LLM.example.lan:8000/v1/")).toBe("http://llm.example.lan:8000/v1");
    expect(normalizeBaseUrl("https://llm.example.com/")).toBe("https://llm.example.com");
    expect(endpointHost("http://LLM.example.lan:8000/v1")).toBe("llm.example.lan:8000");
    // Dot segments are resolved by the URL parser before anything is stored.
    expect(normalizeBaseUrl("http://llm.example.lan/v1/../v2")).toBe("http://llm.example.lan/v2");
  });
});
