import { describe, expect, it } from "vitest";
import { compareDebVersions, debUpstream, parseDebVersion } from "./deb-version.ts";

const sign = (n: number) => Math.sign(n);

describe("Debian versions, compared as dpkg does", () => {
  // Each pair: [older, newer]. Checked against `dpkg --compare-versions a lt b`.
  const ordered: [string, string][] = [
    ["1.0", "1.1"],
    ["1.0", "1.0-1"],
    ["1.0-1", "1.0-2"],
    ["1.0-1", "1.0-1+b1"],
    ["1.0~rc1", "1.0"],
    ["1.0~rc1-1", "1.0-1"],
    ["1.0~~", "1.0~"],
    ["1.0~", "1.0"],
    ["1.0", "1.0a"],
    ["1.0", "1.0."],
    ["1.0a", "1.0."],
    ["1.0", "1.0+"],
    ["2.4-1", "2.30-1"],
    ["1.09", "1.10"],
    ["9.9", "1:0.1"],
    ["1:1.0", "2:0.1"],
    ["3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"],
    ["3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.10"],
    ["2.9.14+dfsg-1.3ubuntu3", "2.9.14+dfsg-1.3ubuntu3.1"],
    // Ubuntu Pro (ESM) builds: "+esm" after the release sorts above it, "~esm" below the next regular update.
    ["1.2.3-1ubuntu0.1", "1.2.3-1ubuntu0.1+esm1"],
    ["1.2.3-1ubuntu0.1+esm1", "1.2.3-1ubuntu0.1+esm2"],
    ["1.2.3-1ubuntu0.2~esm1", "1.2.3-1ubuntu0.2"],
    ["6.1.112-1", "6.1.115-1"],
    ["6.1.76-1~bpo11+1", "6.1.76-1"],
    ["8.2.26-1~deb12u1", "8.2.26-1"],
    ["8.3.6-0ubuntu0.24.04.2", "8.3.6-0ubuntu0.24.04.3"],
    ["8.3.13-1+ubuntu24.04.1+deb.sury.org+1", "8.3.14-1+ubuntu24.04.1+deb.sury.org+1"],
    ["0.0.0-0", "0:0.0.1"],
  ];
  it.each(ordered)("%s < %s", (older, newer) => {
    expect(sign(compareDebVersions(older, newer))).toBe(-1);
    expect(sign(compareDebVersions(newer, older))).toBe(1);
  });

  it("treats equal versions as equal, also with a zero epoch and leading zeros", () => {
    expect(compareDebVersions("1.0-1", "1.0-1")).toBe(0);
    expect(compareDebVersions("0:1.0-1", "1.0-1")).toBe(0);
    expect(compareDebVersions("1.001", "1.1")).toBe(0);
  });

  it("splits epoch, upstream and revision at the first colon and the last hyphen", () => {
    expect(parseDebVersion("1:2.3-4-5")).toEqual({ epoch: 1, upstream: "2.3-4", revision: "5" });
    expect(parseDebVersion("2.3")).toEqual({ epoch: 0, upstream: "2.3", revision: "" });
    expect(parseDebVersion("")).toBeNull();
    expect(parseDebVersion("x:1.0")).toBeNull();
    expect(parseDebVersion("abc")).toBeNull();
    expect(debUpstream("1:8.3.14-1+ubuntu24.04.1+deb.sury.org+1")).toBe("8.3.14");
  });

  it("puts text that is not a version below every version", () => {
    expect(sign(compareDebVersions("not a version", "0.1"))).toBe(-1);
    expect(sign(compareDebVersions("0.1", ""))).toBe(1);
    expect(compareDebVersions("", "x")).toBe(0);
  });
});
