import { describe, expect, it } from "vitest";
import { parseScanError, SCAN_ERRORS, type ScanErrorCode, scanErrorMessage } from "./scan-errors.ts";

describe("scan errors", () => {
  it("round-trips every message through its code", () => {
    for (const code of Object.keys(SCAN_ERRORS) as ScanErrorCode[]) {
      const text = scanErrorMessage(code, { limit: 500 });
      expect(parseScanError(text)?.code).toBe(code);
    }
  });

  it("fills and reads back parameters", () => {
    const text = scanErrorMessage("repositoryTooLarge", { limit: 750 });
    expect(text).toBe("The repository is larger than the 750 MB limit.");
    expect(parseScanError(text)).toEqual({ code: "repositoryTooLarge", params: { limit: "750" } });
  });

  it("returns null for texts it does not know", () => {
    expect(parseScanError("Something new from a later version.")).toBeNull();
    expect(parseScanError("")).toBeNull();
  });
});
