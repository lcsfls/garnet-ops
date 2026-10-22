import { describe, expect, test } from "vitest";
import {
  emptyGradeCounts,
  findingGradeRank,
  GRADE_OF_RULE,
  GRADE_RANK,
  GRADE_RULES,
  GRADES,
  type Grade,
  type GradeCounts,
  type GradeFinding,
  gradeCountsOf,
  gradeOf,
  parseGradeFilter,
} from "./grades.ts";

const counts = (patch: Partial<GradeCounts>): GradeCounts => ({ ...emptyGradeCounts(), ...patch });
const finding = (patch: Partial<GradeFinding>): GradeFinding => ({
  severity: "medium",
  hasFix: false,
  knownExploited: false,
  ...patch,
});
const gradeOfFindings = (findings: GradeFinding[]) => gradeOf(gradeCountsOf(findings));

describe("gradeOf: one rule at a time", () => {
  test("no open findings is A", () => {
    expect(gradeOf(emptyGradeCounts())).toEqual({ grade: "A", rule: "none", count: 0 });
  });

  test("only low findings is B, with or without a fix", () => {
    expect(gradeOf(counts({ otherOpen: 3 }))).toEqual({ grade: "B", rule: "other-open", count: 3 });
    expect(gradeOfFindings([finding({ severity: "low", hasFix: true })]).grade).toBe("B");
    expect(gradeOfFindings([finding({ severity: "low", hasFix: false })]).grade).toBe("B");
  });

  test("negligible and unknown severity are B, even with a fix", () => {
    for (const severity of ["negligible", "unknown"]) {
      expect(gradeOfFindings([finding({ severity, hasFix: true })]).grade).toBe("B");
      expect(gradeOfFindings([finding({ severity, hasFix: false })]).grade).toBe("B");
    }
  });

  test("a medium without a fix is B", () => {
    expect(gradeOfFindings([finding({ severity: "medium" })])).toEqual({
      grade: "B",
      rule: "other-open",
      count: 1,
    });
  });

  test("a medium with a fix is C", () => {
    expect(gradeOfFindings([finding({ severity: "medium", hasFix: true })])).toEqual({
      grade: "C",
      rule: "medium-with-fix",
      count: 1,
    });
  });

  test("a high without a fix is C", () => {
    expect(gradeOfFindings([finding({ severity: "high" })])).toEqual({
      grade: "C",
      rule: "high-without-fix",
      count: 1,
    });
  });

  test("a high with a fix is D", () => {
    expect(gradeOfFindings([finding({ severity: "high", hasFix: true })])).toEqual({
      grade: "D",
      rule: "high-with-fix",
      count: 1,
    });
  });

  test("a critical without a fix is D", () => {
    expect(gradeOfFindings([finding({ severity: "critical" })])).toEqual({
      grade: "D",
      rule: "critical-without-fix",
      count: 1,
    });
  });

  test("a critical with a fix is E", () => {
    expect(gradeOfFindings([finding({ severity: "critical", hasFix: true })])).toEqual({
      grade: "E",
      rule: "critical-with-fix",
      count: 1,
    });
  });

  test("a known exploited vulnerability with a fix is F, whatever its severity", () => {
    for (const severity of ["critical", "high", "medium", "low", "negligible", "unknown"]) {
      expect(gradeOfFindings([finding({ severity, hasFix: true, knownExploited: true })])).toEqual({
        grade: "F",
        rule: "known-exploited-with-fix",
        count: 1,
      });
    }
  });
});

describe("gradeOf: boundaries", () => {
  test("a known exploited vulnerability without a fix is graded by its severity only", () => {
    const grade = (severity: string) =>
      gradeOfFindings([finding({ severity, hasFix: false, knownExploited: true })]).grade;
    expect(grade("critical")).toBe("D");
    expect(grade("high")).toBe("C");
    expect(grade("medium")).toBe("B");
    expect(grade("low")).toBe("B");
  });

  test("the worst matching rule wins over any number of milder findings", () => {
    const many = (n: number, patch: Partial<GradeFinding>) => Array.from({ length: n }, () => finding(patch));
    // 50 highs with a fix are still D when a single critical with a fix is there.
    expect(
      gradeOfFindings([
        ...many(50, { severity: "high", hasFix: true }),
        finding({ severity: "critical", hasFix: true }),
      ]).grade,
    ).toBe("E");
    // A single KEV with a fix beats everything.
    expect(
      gradeOfFindings([
        ...many(5, { severity: "critical", hasFix: true }),
        finding({ severity: "low", hasFix: true, knownExploited: true }),
      ]).grade,
    ).toBe("F");
    // A single medium with a fix lifts a repository full of lows to C.
    expect(
      gradeOfFindings([
        ...many(100, { severity: "low", hasFix: true }),
        finding({ severity: "medium", hasFix: true }),
      ]).grade,
    ).toBe("C");
  });

  test("a critical without a fix still lifts a repository to D, but a high with a fix is not worse", () => {
    expect(gradeOfFindings([finding({ severity: "critical" }), finding({ severity: "medium" })]).grade).toBe(
      "D",
    );
    expect(
      gradeOfFindings([finding({ severity: "critical" }), finding({ severity: "high", hasFix: true })]).grade,
    ).toBe("D");
  });

  test("with two rules at the same grade, the one with a fix is the reason", () => {
    expect(
      gradeOfFindings([
        finding({ severity: "critical" }),
        finding({ severity: "critical" }),
        finding({ severity: "high", hasFix: true }),
      ]),
    ).toEqual({ grade: "D", rule: "high-with-fix", count: 1 });
    expect(
      gradeOfFindings([finding({ severity: "high" }), finding({ severity: "medium", hasFix: true })]),
    ).toEqual({ grade: "C", rule: "medium-with-fix", count: 1 });
  });

  test("the count is the number of findings of the deciding rule", () => {
    expect(
      gradeOfFindings([
        finding({ severity: "high", hasFix: true }),
        finding({ severity: "high", hasFix: true }),
        finding({ severity: "medium", hasFix: true }),
      ]),
    ).toEqual({ grade: "D", rule: "high-with-fix", count: 2 });
    // B counts every open finding, as all of them are what makes it B.
    expect(
      gradeOfFindings([
        finding({ severity: "medium" }),
        finding({ severity: "low", hasFix: true }),
        finding({ severity: "unknown" }),
      ]),
    ).toEqual({ grade: "B", rule: "other-open", count: 3 });
  });

  test("clearing the findings of one rule after the other lowers the grade step by step", () => {
    let c = counts({ kevWithFix: 1, criticalWithFix: 1, highWithFix: 1, mediumWithFix: 1, otherOpen: 1 });
    expect(gradeOf(c).grade).toBe("F");
    c = { ...c, kevWithFix: 0 };
    expect(gradeOf(c).grade).toBe("E");
    c = { ...c, criticalWithFix: 0 };
    expect(gradeOf(c).grade).toBe("D");
    c = { ...c, highWithFix: 0 };
    expect(gradeOf(c).grade).toBe("C");
    c = { ...c, mediumWithFix: 0 };
    expect(gradeOf(c).grade).toBe("B");
    c = { ...c, otherOpen: 0 };
    expect(gradeOf(c).grade).toBe("A");
  });
});

describe("tables stay in step with each other", () => {
  test("every rule has a grade and every grade has a rank, A is the lowest", () => {
    expect(Object.keys(GRADE_OF_RULE).sort()).toEqual([...GRADE_RULES].sort());
    expect(GRADES.map((g) => GRADE_RANK[g])).toEqual([0, 1, 2, 3, 4, 5]);
  });

  test("every grade is reachable", () => {
    const reached = new Set<Grade>(GRADE_RULES.map((r) => GRADE_OF_RULE[r]));
    expect([...reached].sort()).toEqual([...GRADES]);
  });

  test("a single finding's rank is the rank of the repository that has only it", () => {
    expect(findingGradeRank(finding({ severity: "low" }))).toBe(1);
    expect(findingGradeRank(finding({ severity: "critical", hasFix: true }))).toBe(4);
    expect(findingGradeRank(finding({ severity: "low", hasFix: true, knownExploited: true }))).toBe(5);
  });

  test("the worst finding decides, whatever the order (exhaustive over all finding kinds)", () => {
    const severities = ["critical", "high", "medium", "low", "negligible", "unknown"];
    const kinds: GradeFinding[] = [];
    for (const severity of severities)
      for (const hasFix of [true, false])
        for (const knownExploited of [true, false]) kinds.push({ severity, hasFix, knownExploited });
    // Every pair of kinds: the grade of the pair is the worse of the two single grades.
    for (const a of kinds) {
      for (const b of kinds) {
        expect(GRADE_RANK[gradeOfFindings([a, b]).grade]).toBe(
          Math.max(findingGradeRank(a), findingGradeRank(b)),
        );
        expect(gradeOfFindings([a, b]).grade).toBe(gradeOfFindings([b, a]).grade);
      }
    }
  });
});

describe("parseGradeFilter", () => {
  test("accepts letters and none, once each", () => {
    expect(parseGradeFilter("F,E,none")).toEqual(["F", "E", "none"]);
    expect(parseGradeFilter("A,A")).toEqual(["A"]);
  });

  test("refuses anything else instead of showing everything", () => {
    expect(parseGradeFilter("")).toBeNull();
    expect(parseGradeFilter("G")).toBeNull();
    expect(parseGradeFilter("a")).toBeNull();
    expect(parseGradeFilter("F,;drop")).toBeNull();
  });
});
