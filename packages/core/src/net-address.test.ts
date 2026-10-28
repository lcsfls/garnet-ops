import { describe, expect, it } from "vitest";
import { checkHostAddress } from "./net-address.ts";

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
