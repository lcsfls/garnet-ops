import { describe, expect, it } from "vitest";
import { findingSearch, repositorySearch, toQuery } from "./search.ts";

describe("search params", () => {
  it("accepts numbers where the URL decoder produced them", () => {
    expect(findingSearch.parse({ kev: 1, q: 2099, pageSize: "50" })).toMatchObject({
      kev: "1",
      q: "2099",
      pageSize: 50,
    });
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
});
