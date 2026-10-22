import { HOST_ERRORS } from "@garnetops/core";
import { resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";

describe("host error messages", () => {
  it("has a translation for every code, and English matches what the worker stores", () => {
    for (const [code, text] of Object.entries(HOST_ERRORS)) {
      expect(resources.en.translation.hostError).toHaveProperty(code, text);
      expect(resources.de.translation.hostError).toHaveProperty(code);
    }
    expect(Object.keys(resources.en.translation.hostError).sort()).toEqual(Object.keys(HOST_ERRORS).sort());
  });
});
