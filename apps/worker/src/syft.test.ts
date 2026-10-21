import { describe, expect, it } from "vitest";
import { parseSbom } from "./syft.ts";

describe("parseSbom", () => {
  it("lists every package, merges duplicates and skips malformed entries", () => {
    const inventory = parseSbom({
      descriptor: { version: "1.55.0" },
      artifacts: [
        {
          name: "lodash",
          version: "4.17.15",
          type: "npm",
          purl: "pkg:npm/lodash@4.17.15",
          locations: [{ path: "/a/package-lock.json" }],
        },
        {
          name: "lodash",
          version: "4.17.15",
          type: "npm",
          locations: [{ path: "/b/package-lock.json" }],
          licenses: [{ value: "MIT" }],
        },
        { name: "minimist", version: "1.2.0", type: "npm" },
        { version: "1.0.0" },
        "not an object",
      ],
    });
    expect(inventory.total).toBe(2);
    expect(inventory.syftVersion).toBe("1.55.0");
    expect(inventory.packages[0]).toEqual({
      name: "lodash",
      version: "4.17.15",
      type: "npm",
      purl: "pkg:npm/lodash@4.17.15",
      locations: ["/a/package-lock.json", "/b/package-lock.json"],
      licenses: ["MIT"],
    });
    expect(inventory.packages[1]?.name).toBe("minimist");
  });

  it("refuses a document that is not an SBOM", () => {
    expect(() => parseSbom({ matches: [] })).toThrow();
  });
});
