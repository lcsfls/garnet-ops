import { describe, expect, it } from "vitest";
import {
  AUDIT_FILTERS,
  auditSearch,
  findingSearch,
  repositorySearch,
  SETTINGS_SECTIONS,
  settingsSearch,
  toQuery,
} from "./search.ts";

describe("search params", () => {
  it("accepts numbers where the URL decoder produced them", () => {
    expect(findingSearch.parse({ kev: 1, q: 2099, pageSize: "50" })).toMatchObject({
      kev: "1",
      q: "2099",
      pageSize: 50,
    });
  });

  it("keeps the AI panel flag and the AI settings section in the address, and drops anything else", () => {
    expect(findingSearch.parse({ id: "fnd_1", ai: 1 })).toMatchObject({ id: "fnd_1", ai: "1" });
    expect(findingSearch.parse({ ai: "yes" })).toMatchObject({ ai: undefined });
    expect(settingsSearch.parse({ section: "ai" })).toEqual({ section: "ai" });
    expect(settingsSearch.parse({ section: "nope" })).toEqual({ section: undefined });
    // The flag is for the page only: the list request leaves it out.
    expect(toQuery({ q: "x", ai: "1", id: "fnd_1" }, ["id", "ai"])).toBe("?q=x");
  });

  it("drops invalid values instead of failing the page", () => {
    const parsed = findingSearch.parse({
      state: "nope",
      kev: "yes",
      pageSize: 7,
      severity: "critical,bogus",
    });
    expect(parsed).toMatchObject({
      state: undefined,
      kev: undefined,
      pageSize: undefined,
      severity: "critical",
    });
    expect(repositorySearch.parse({ status: "weird", add: "1" })).toMatchObject({
      status: undefined,
      add: "1",
    });
  });

  it("builds API queries without empty or UI-only values", () => {
    expect(toQuery({ severity: "critical", q: undefined, id: "fnd_1", kev: "1" }, ["id"])).toBe(
      "?severity=critical&kev=1",
    );
    expect(toQuery({})).toBe("");
  });

  it("accepts one grade or 'none' in the repository list", () => {
    expect(repositorySearch.parse({ grade: "F", sort: "grade" })).toMatchObject({
      grade: "F",
      sort: "grade",
    });
    expect(repositorySearch.parse({ grade: "none", sort: "grade", dir: "asc" })).toMatchObject({
      grade: "none",
      sort: "grade",
      dir: "asc",
    });
    expect(repositorySearch.parse({ grade: "G" })).toMatchObject({ grade: undefined });
    expect(repositorySearch.parse({ grade: "f" })).toMatchObject({ grade: undefined });
  });

  it("offers no settings section and no audit group of a removed module", () => {
    const removed = ["proxmox", "unifi", "exposure", "xdr", "attacks", "host"];
    for (const name of removed) {
      expect(SETTINGS_SECTIONS).not.toContain(name);
      expect(AUDIT_FILTERS).not.toContain(name);
      expect(settingsSearch.parse({ section: name })).toEqual({ section: undefined });
      expect(auditSearch.parse({ group: name })).toMatchObject({ group: undefined });
    }
    expect(auditSearch.parse({ group: "fix_pr" })).toMatchObject({ group: "fix_pr" });
  });
});
