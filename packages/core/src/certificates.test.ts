import { describe, expect, it } from "vitest";
import { certificateFingerprint, certificateName, normalizeFingerprint } from "./certificates.ts";

describe("certificate fingerprints", () => {
  it("writes SHA-256 as upper-case hex pairs separated by colons", () => {
    const f = certificateFingerprint(Buffer.from("example"));
    expect(f).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(normalizeFingerprint(f.toLowerCase())).toBe(f);
    expect(normalizeFingerprint("AA:BB")).toBeNull();
    expect(normalizeFingerprint(f.replace(/:/g, ""))).toBeNull();
  });

  it("shows a certificate name on one line without control characters", () => {
    expect(certificateName("CN=a\u0007b\nO=Example")).toBe("CN=ab, O=Example");
    expect(certificateName(undefined)).toBe("");
    expect(certificateName("x".repeat(400))).toHaveLength(300);
  });
});
