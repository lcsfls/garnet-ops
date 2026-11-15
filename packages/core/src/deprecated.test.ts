import { describe, expect, it } from "vitest";
import {
  cleanMessage,
  cleanRegistryUrl,
  deprecationEcosystemOf,
  excludedEntryProblem,
  isExcluded,
  parseCrates,
  parseNpm,
  parsePypi,
  registryPath,
} from "./deprecated.ts";

describe("which registry and which names", () => {
  it("maps grype's package types", () => {
    expect(deprecationEcosystemOf("npm")).toBe("npm");
    expect(deprecationEcosystemOf("python")).toBe("pypi");
    expect(deprecationEcosystemOf("rust-crate")).toBe("crates");
    expect(deprecationEcosystemOf("go-module")).toBeNull();
  });

  it("accepts an https registry address and nothing else", () => {
    expect(cleanRegistryUrl("https://npm.example.lan:8443/repository/npm/")).toEqual({
      url: "https://npm.example.lan:8443/repository/npm",
    });
    expect(cleanRegistryUrl("http://npm.example.lan")).toEqual({ problem: "https" });
    expect(cleanRegistryUrl("https://user:pw@npm.example.lan")).toEqual({ problem: "parts" });
    expect(cleanRegistryUrl("https://npm.example.lan/?token=x")).toEqual({ problem: "parts" });
    expect(cleanRegistryUrl("not a url")).toEqual({ problem: "parts" });
  });

  it("keeps excluded scopes and patterns inside", () => {
    expect(isExcluded("@acme/ui", ["@acme"])).toBe(true);
    expect(isExcluded("@acmecorp/ui", ["@acme"])).toBe(false);
    expect(isExcluded("acme-billing", ["acme-*"])).toBe(true);
    expect(isExcluded("ACME-Billing", ["acme-*"])).toBe(true);
    expect(isExcluded("lodash", ["acme-*", "@acme"])).toBe(false);
    expect(excludedEntryProblem("@acme")).toBeNull();
    expect(excludedEntryProblem("acme-*")).toBeNull();
    expect(excludedEntryProblem("*")).toBe("everything");
    expect(excludedEntryProblem("@*")).toBe("everything");
    expect(excludedEntryProblem("a b")).toBe("characters");
  });

  it("builds request paths from checked names only", () => {
    expect(registryPath("npm", "@scope/pkg", "1.0.0")).toBe("/@scope%2fpkg");
    expect(registryPath("npm", "lodash", "4.17.15")).toBe("/lodash");
    expect(registryPath("pypi", "Django_REST.framework", "3.1")).toBe("/pypi/django-rest-framework/3.1/json");
    expect(registryPath("crates", "a", "1")).toBe("/1/a");
    expect(registryPath("crates", "ab", "1")).toBe("/2/ab");
    expect(registryPath("crates", "Abc", "1")).toBe("/3/a/abc");
    expect(registryPath("crates", "serde_json", "1")).toBe("/se/rd/serde_json");
    for (const bad of ["../etc", "a/b/c", "x?y", "%2e%2e", ""]) {
      expect(() => registryPath("npm", bad, "1"), bad).toThrow();
    }
    expect(() => registryPath("pypi", "requests", "1.0/../x")).toThrow();
  });
});

describe("what the registries answer", () => {
  it("npm: deprecated with the maintainers' message, current, or unknown", () => {
    const doc = JSON.stringify({
      versions: {
        "2.7.1": { deprecated: "Rimraf versions prior to v4 are no longer supported" },
        "4.0.0": { deprecated: "" },
        "5.0.0": {},
      },
    });
    expect(Object.fromEntries(parseNpm(doc, ["2.7.1", "4.0.0", "5.0.0", "9.9.9"]))).toEqual({
      "2.7.1": { state: "deprecated", message: "Rimraf versions prior to v4 are no longer supported" },
      "4.0.0": { state: "current", message: null },
      "5.0.0": { state: "current", message: null },
      "9.9.9": { state: "unknown", message: null },
    });
    expect(parseNpm("not json", ["1"]).get("1")).toEqual({ state: "unknown", message: null });
  });

  it("PyPI: yanked only when every file is", () => {
    expect(
      parsePypi(
        JSON.stringify({ urls: [{ yanked: true, yanked_reason: "Broken wheel" }, { yanked: true }] }),
      ),
    ).toEqual({
      state: "yanked",
      message: "Broken wheel",
    });
    expect(parsePypi(JSON.stringify({ urls: [{ yanked: true }, { yanked: false }] })).state).toBe("current");
    expect(parsePypi("{}").state).toBe("unknown");
  });

  it("crates.io: the sparse index's yanked flag per version", () => {
    const index = [
      '{"name":"x","vers":"0.1.0","yanked":true}',
      '{"name":"x","vers":"0.2.0","yanked":false}',
      "garbage",
    ].join("\n");
    expect(Object.fromEntries(parseCrates(index, ["0.1.0", "0.2.0", "0.3.0"]))).toEqual({
      "0.1.0": { state: "yanked", message: null },
      "0.2.0": { state: "current", message: null },
      "0.3.0": { state: "unknown", message: null },
    });
  });

  it("cleans registry text before it is kept", () => {
    expect(cleanMessage("use x‮\u0007 instead")).toBe("use x   instead");
    expect(cleanMessage("a".repeat(400))?.length).toBe(300);
    expect(cleanMessage(42)).toBeNull();
    expect(cleanMessage("   ")).toBeNull();
  });
});
