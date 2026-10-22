import { describe, expect, test } from "vitest";
import {
  compareVersions,
  ecosystemOfPackageType,
  majorOf,
  parseVersion,
  schemeOfPackageType,
  selectTarget,
} from "./versions.ts";

const semver = (a: string, b: string) => compareVersions("semver", a, b);
const pep = (a: string, b: string) => compareVersions("pep440", a, b);

describe("package types", () => {
  test("maps the scanner's types to editable ecosystems", () => {
    expect(ecosystemOfPackageType("npm")).toBe("npm");
    expect(ecosystemOfPackageType("python")).toBe("pypi");
    expect(ecosystemOfPackageType("go-module")).toBe("go");
    expect(ecosystemOfPackageType("rust-crate")).toBe("cargo");
    expect(ecosystemOfPackageType("php-composer")).toBe("composer");
    expect(ecosystemOfPackageType("java-archive")).toBeNull();
    expect(ecosystemOfPackageType("deb")).toBeNull();
    expect(schemeOfPackageType("python")).toBe("pep440");
    expect(schemeOfPackageType("npm")).toBe("semver");
    expect(schemeOfPackageType("gem")).toBe("generic");
  });
});

describe("semver-like order (npm, Cargo, Composer, Go)", () => {
  test("compares numerically, not as text", () => {
    expect(semver("1.10.0", "1.9.0")).toBe(1);
    expect(semver("2.0.0", "10.0.0")).toBe(-1);
    expect(semver("4.17.21", "4.17.21")).toBe(0);
    expect(semver("1.2", "1.2.0")).toBe(0);
    expect(semver("1.2.3.4", "1.2.3")).toBe(1);
  });
  test("a pre-release is older than its release, identifiers follow semver", () => {
    expect(semver("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(semver("1.0.0-alpha", "1.0.0-alpha.1")).toBe(-1);
    expect(semver("1.0.0-alpha.2", "1.0.0-alpha.10")).toBe(-1);
    expect(semver("1.0.0-alpha.1", "1.0.0-beta")).toBe(-1);
    expect(semver("1.0.0-1", "1.0.0-alpha")).toBe(-1);
  });
  test("accepts a leading v and ignores build metadata", () => {
    expect(semver("v1.2.3", "1.2.3")).toBe(0);
    expect(semver("1.2.3+build.5", "1.2.3+other")).toBe(0);
  });
  test("go pseudo-versions order before the release they lead to", () => {
    expect(semver("v0.0.0-20210101000000-abcdefabcdef", "v1.0.0")).toBe(-1);
  });
  test("what is not a version is unknown, never guessed", () => {
    for (const bad of [
      "",
      "latest",
      "1.x",
      "^1.2.3",
      "1.2.3.4.5.6.7",
      "1..2",
      "a.b.c",
      "1.2.3-",
      "x".repeat(200),
    ]) {
      expect(parseVersion("semver", bad), bad).toBeNull();
    }
    expect(semver("latest", "1.0.0")).toBeNull();
  });
  test("huge numbers are refused instead of losing precision", () => {
    expect(parseVersion("semver", `${"9".repeat(30)}.0.0`)).toBeNull();
  });
});

describe("PEP 440 order (Python)", () => {
  test("dev < alpha < beta < rc < release < post", () => {
    const order = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1"];
    for (let i = 0; i < order.length - 1; i++) {
      expect(pep(order[i] as string, order[i + 1] as string), `${order[i]} < ${order[i + 1]}`).toBe(-1);
    }
  });
  test("spellings are equivalent", () => {
    expect(pep("1.0-alpha1", "1.0a1")).toBe(0);
    expect(pep("1.0.RC1", "1.0rc1")).toBe(0);
    expect(pep("1.0c1", "1.0rc1")).toBe(0);
    expect(pep("1.0-1", "1.0.post1")).toBe(0);
    expect(pep("1.0.0", "1.0")).toBe(0);
    expect(pep("v2.0", "2.0")).toBe(0);
  });
  test("epoch wins, local versions are ignored", () => {
    expect(pep("1!1.0", "2023.1")).toBe(1);
    expect(pep("1.0+ubuntu1", "1.0")).toBe(0);
  });
  test("numbers compare numerically", () => {
    expect(pep("2.10", "2.9")).toBe(1);
    expect(pep("1.0.post2", "1.0.post10")).toBe(-1);
  });
  test("a dev release of a post release", () => {
    expect(pep("1.0.post1.dev1", "1.0.post1")).toBe(-1);
    expect(pep("1.0.post1.dev1", "1.0")).toBe(1);
  });
  test("not a version", () => {
    for (const bad of ["", "abc", "1.0.*", "==1.0", ">=1.0"])
      expect(parseVersion("pep440", bad), bad).toBeNull();
  });
});

describe("selectTarget", () => {
  const pick = (
    scheme: "semver" | "pep440" | "generic",
    installed: string,
    vulnerabilities: { id: string; fixedIn: string[] }[],
  ) => selectTarget({ scheme, installed, vulnerabilities });

  test("npm: the lowest fixed version", () => {
    expect(pick("semver", "4.17.20", [{ id: "CVE-1", fixedIn: ["4.17.21"] }])).toEqual({
      version: "4.17.21",
      majorUpgrade: false,
      fixes: ["CVE-1"],
      unresolved: [],
    });
  });
  test("takes the highest of the per-vulnerability fixes so that all are fixed", () => {
    const result = pick("semver", "4.17.10", [
      { id: "A", fixedIn: ["4.17.12"] },
      { id: "B", fixedIn: ["4.17.21"] },
      { id: "C", fixedIn: ["4.17.15"] },
    ]);
    expect(result?.version).toBe("4.17.21");
    expect(result?.fixes).toEqual(["A", "B", "C"]);
    expect(result?.majorUpgrade).toBe(false);
  });
  test("prefers the release line of the installed version", () => {
    const result = pick("semver", "1.2.0", [{ id: "A", fixedIn: ["2.0.3", "1.2.5", "3.1.0"] }]);
    expect(result?.version).toBe("1.2.5");
    expect(result?.majorUpgrade).toBe(false);
  });
  test("marks a major upgrade when nothing in the same major fixes it", () => {
    const result = pick("semver", "1.2.0", [{ id: "A", fixedIn: ["2.0.3", "3.1.0"] }]);
    expect(result?.version).toBe("2.0.3");
    expect(result?.majorUpgrade).toBe(true);
  });
  test("one vulnerability that needs a major upgrade makes the whole proposal one", () => {
    const result = pick("semver", "1.2.0", [
      { id: "A", fixedIn: ["1.2.5"] },
      { id: "B", fixedIn: ["2.0.1"] },
    ]);
    expect(result).toMatchObject({ version: "2.0.1", majorUpgrade: true, fixes: ["A", "B"] });
  });
  test("fix versions at or below the installed one are ignored; vulnerabilities without a usable fix are listed", () => {
    const result = pick("semver", "2.0.0", [
      { id: "A", fixedIn: ["1.9.9", "2.0.0"] },
      { id: "B", fixedIn: ["2.0.1"] },
      { id: "C", fixedIn: ["not-a-version"] },
      { id: "D", fixedIn: [] },
    ]);
    expect(result).toMatchObject({ version: "2.0.1", fixes: ["B"], unresolved: ["A", "C", "D"] });
  });
  test("never proposes a pre-release, unless the installed version is one", () => {
    expect(pick("semver", "1.0.0", [{ id: "A", fixedIn: ["1.1.0-rc.1"] }])).toBeNull();
    expect(pick("semver", "1.0.0", [{ id: "A", fixedIn: ["1.1.0-rc.1", "1.1.0"] }])?.version).toBe("1.1.0");
    expect(pick("semver", "1.0.0-beta.1", [{ id: "A", fixedIn: ["1.0.0-beta.3"] }])?.version).toBe(
      "1.0.0-beta.3",
    );
  });
  test("Go: a leading v is removed (the writer adds it back)", () => {
    expect(pick("semver", "v1.4.0", [{ id: "A", fixedIn: ["v1.4.2"] }])?.version).toBe("1.4.2");
  });
  test("Cargo and Composer use the same order", () => {
    expect(pick("semver", "0.9.3", [{ id: "A", fixedIn: ["0.9.5", "0.10.1"] }])?.version).toBe("0.9.5");
    expect(pick("semver", "2.5.0.1", [{ id: "A", fixedIn: ["2.5.1"] }])?.version).toBe("2.5.1");
  });
  test("PyPI: PEP 440 order, post releases and pre-releases", () => {
    expect(pick("pep440", "2.25.0", [{ id: "A", fixedIn: ["2.31.0", "2.32.0rc1"] }])?.version).toBe("2.31.0");
    expect(pick("pep440", "1.0", [{ id: "A", fixedIn: ["1.0.post1"] }])?.version).toBe("1.0.post1");
    expect(pick("pep440", "1.26.5", [{ id: "A", fixedIn: ["1.26.18", "2.0.7"] }])).toMatchObject({
      version: "1.26.18",
      majorUpgrade: false,
    });
  });
  test("an installed version that does not parse gives no proposal", () => {
    expect(pick("semver", "weird", [{ id: "A", fixedIn: ["1.0.0"] }])).toBeNull();
  });
  test("majorOf", () => {
    expect(majorOf("semver", "v3.2.1")).toBe(3);
    expect(majorOf("semver", "nope")).toBeNull();
  });
});
