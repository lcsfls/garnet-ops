import { describe, expect, it } from "vitest";
import { imagePresence, presenceCaveatOf, presenceName } from "./image-presence.ts";

describe("a repository's package in a running image (ADR 0054)", () => {
  it("has no answer without the module, without an image, or while the image is not read", () => {
    expect(imagePresence({ hostsOn: false, images: 2, read: 2, found: true })).toEqual({
      state: null,
      reason: "module-off",
    });
    expect(imagePresence({ hostsOn: true, images: 0, read: 0, found: false })).toEqual({
      state: null,
      reason: "no-image",
    });
    // Not read is not "not there".
    expect(imagePresence({ hostsOn: true, images: 1, read: 0, found: false })).toEqual({
      state: null,
      reason: "not-read",
    });
  });

  it("says in the image when one read image names the package, and not in it when none does", () => {
    expect(imagePresence({ hostsOn: true, images: 2, read: 1, found: true }).state).toBe("in-image");
    expect(imagePresence({ hostsOn: true, images: 2, read: 1, found: false }).state).toBe("not-in-image");
  });

  it("names what a missing package cannot rule out", () => {
    expect(presenceCaveatOf("npm")).toBe("bundled");
    expect(presenceCaveatOf("rust-crate")).toBe("compiled");
    for (const type of ["go-module", "deb", "python", "java-archive"])
      expect(presenceCaveatOf(type)).toBeNull();
    expect(presenceName("Django")).toBe("django");
  });
});
