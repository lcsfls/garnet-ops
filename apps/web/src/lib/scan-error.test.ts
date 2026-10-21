import { SCAN_ERRORS } from "@garnetops/core";
import { resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";

describe("scan error messages", () => {
  it("has a translation for every code, and English matches what the worker stores", () => {
    for (const [code, text] of Object.entries(SCAN_ERRORS)) {
      expect(resources.en.translation.scanError).toHaveProperty(code, text);
      expect(resources.de.translation.scanError).toHaveProperty(code);
    }
    expect(Object.keys(resources.en.translation.scanError).sort()).toEqual(Object.keys(SCAN_ERRORS).sort());
  });
});
