import { GRADE_OF_RULE, GRADE_RULES } from "@garnetops/core/grades";
import { describe, expect, it } from "vitest";
import { gradeFindingFilter } from "./grade-badge.ts";

describe("the findings behind a grade", () => {
  it("links every deciding rule to the findings it counts, and A to nothing", () => {
    expect(gradeFindingFilter("known-exploited-with-fix")).toEqual({ kev: "1", fixable: "1" });
    expect(gradeFindingFilter("critical-with-fix")).toEqual({ severity: "critical", fixable: "1" });
    expect(gradeFindingFilter("high-with-fix")).toEqual({ severity: "high", fixable: "1" });
    expect(gradeFindingFilter("medium-with-fix")).toEqual({ severity: "medium", fixable: "1" });
    // Without a fix: a worse rule would have decided if a fix existed, so severity alone is exact.
    expect(gradeFindingFilter("critical-without-fix")).toEqual({ severity: "critical" });
    expect(gradeFindingFilter("high-without-fix")).toEqual({ severity: "high" });
    // B is about every open finding of the repository.
    expect(gradeFindingFilter("other-open")).toEqual({});
    expect(gradeFindingFilter("none")).toBeNull();
  });

  it("has an answer for every rule", () => {
    for (const rule of GRADE_RULES) {
      expect(gradeFindingFilter(rule) === null, rule).toBe(GRADE_OF_RULE[rule] === "A");
    }
  });
});
