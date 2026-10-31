import { describe, expect, it } from "vitest";
import { isVulnDbBuildKey, VULNDB_BUILD_HOSTS, VULNDB_BUILD_KEYS } from "./vulndb-build.ts";

describe("keys of the own vulnerability database build", () => {
  it.each([
    `ghp_${"A1b2".repeat(9)}`,
    `github_pat_${"a".repeat(22)}`,
    `github_pat_11ABCDEFG0123456789_${"x".repeat(59)}`,
  ])("accepts the GitHub token %s", (token) => {
    expect(VULNDB_BUILD_KEYS.githubToken.test(token)).toBe(true);
  });

  it.each([
    "",
    "ghp_",
    `ghp_${"a".repeat(35)}`,
    `ghp_${"a".repeat(37)}`,
    `ghp_${"a".repeat(35)}-`,
    `gho_${"a".repeat(36)}`,
    `github_pat_${"a".repeat(21)}`,
    `github_pat_${"a".repeat(256)}`,
    `github_pat_${"a".repeat(30)}\n`,
    ` ghp_${"a".repeat(36)}`,
    `ghp_${"a".repeat(36)} x`,
    `Bearer ghp_${"a".repeat(36)}`,
  ])("refuses the GitHub token %j", (token) => {
    expect(VULNDB_BUILD_KEYS.githubToken.test(token)).toBe(false);
  });

  it.each(["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"])(
    "accepts the NVD key %s",
    (key) => {
      expect(VULNDB_BUILD_KEYS.nvdApiKey.test(key)).toBe(true);
    },
  );

  it.each([
    "",
    "aaaaaaaabbbbccccddddeeeeeeeeeeee",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeea",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeg",
    "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n",
  ])("refuses the NVD key %j", (key) => {
    expect(VULNDB_BUILD_KEYS.nvdApiKey.test(key)).toBe(false);
  });

  it("ignores surrounding whitespace only in the helper", () => {
    expect(isVulnDbBuildKey("nvdApiKey", "  aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")).toBe(true);
    expect(isVulnDbBuildKey("githubToken", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")).toBe(false);
  });

  it("names the one host each key is sent to", () => {
    expect(VULNDB_BUILD_HOSTS).toEqual({
      githubToken: "api.github.com",
      nvdApiKey: "services.nvd.nist.gov",
    });
  });
});
