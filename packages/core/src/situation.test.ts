import { describe, expect, it } from "vitest";
import { FIX_SIDE, fixKnown, fixPathOf, isBaseImagePackage, worstStatus } from "./situation.ts";

describe("what fixes a finding (ADR 0052)", () => {
  it("is nobody's action yet while no fixed version is known", () => {
    for (const kind of ["repository", "container", "host"] as const) {
      expect(fixPathOf({ kind, packageType: "deb", fixedIn: [] })).toBe("vendor");
      expect(fixPathOf({ kind, packageType: "npm", fixedIn: null, builtByRepository: true })).toBe("vendor");
    }
    expect(fixKnown([""])).toBe(false);
    expect(fixKnown(["1.2.3"])).toBe(true);
  });

  it("is a server action for a host's packages and for an image nobody here builds", () => {
    expect(fixPathOf({ kind: "host", packageType: "deb", fixedIn: ["1.2"] })).toBe("server-package");
    expect(fixPathOf({ kind: "host", packageType: "linux-kernel", fixedIn: ["6.1"] })).toBe("server-package");
    // A third-party image: its language packages are not ours to raise either.
    expect(fixPathOf({ kind: "container", packageType: "deb", fixedIn: ["1.2"] })).toBe("server-image");
    expect(
      fixPathOf({ kind: "container", packageType: "npm", fixedIn: ["1.2"], builtByRepository: false }),
    ).toBe("server-image");
  });

  it("is a commit for a repository's dependencies and for images a repository builds", () => {
    expect(fixPathOf({ kind: "repository", packageType: "python", fixedIn: ["5.2"] })).toBe(
      "repository-dependency",
    );
    expect(
      fixPathOf({ kind: "container", packageType: "python", fixedIn: ["5.2"], builtByRepository: true }),
    ).toBe("repository-dependency");
    // The distribution's packages and loose binaries come with the base image.
    for (const packageType of ["deb", "apk", "rpm", "binary"]) {
      expect(fixPathOf({ kind: "container", packageType, fixedIn: ["1"], builtByRepository: true })).toBe(
        "repository-base-image",
      );
    }
    expect(isBaseImagePackage("go-module")).toBe(false);
  });

  it("names the side of each path, and the worst state of a system", () => {
    expect(FIX_SIDE["server-image"]).toBe("server");
    expect(FIX_SIDE["repository-base-image"]).toBe("repository");
    expect(FIX_SIDE.vendor).toBe("none");
    expect(worstStatus(["not-reachable", "affected"])).toBe("affected");
    expect(worstStatus(["not-reachable", "not-reachable"])).toBe("not-reachable");
    expect(worstStatus([])).toBe("not-checked");
  });
});
