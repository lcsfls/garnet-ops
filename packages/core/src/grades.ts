/**
 * Grades A to F for repositories and servers (ADR 0018). Pure and shared by the API (reason
 * texts, filters) and the web app.
 *
 * A grade is display only. It never changes a gate result, a notification or anything else
 * (AGENTS.md rule 2). Changing a rule here changes what users see on upgrade, so a test pins
 * every boundary.
 *
 * Rules (the worst matching rule wins; only open findings count, accepted risks are excluded
 * while the acceptance is valid; "with a fix" means a fixed version is known):
 *
 * - F: a known exploited vulnerability (CISA KEV) with a fix
 * - E: a critical with a fix
 * - D: a high with a fix, or a critical without a fix
 * - C: a medium with a fix, or a high without a fix
 * - B: any other open finding (low severity, or without a fix and not covered above)
 * - A: no open findings
 *
 * A repository or server that was never scanned has no grade at all (`null`), not A.
 */
export const GRADES = ["A", "B", "C", "D", "E", "F"] as const;
export type Grade = (typeof GRADES)[number];

/** 0 for A up to 5 for F. Sorting "worst first" is sorting by this, descending. */
export const GRADE_RANK: Readonly<Record<Grade, number>> = Object.freeze({
  A: 0,
  B: 1,
  C: 2,
  D: 3,
  E: 4,
  F: 5,
});

/** What a grade filter may name besides the letters: nothing was scanned yet. */
export const GRADE_FILTER_VALUES = [...GRADES, "none"] as const;
export type GradeFilterValue = (typeof GRADE_FILTER_VALUES)[number];

/** The rank the database sorts by for something that was never scanned: below A. */
export const NOT_SCANNED_RANK = -1;

/**
 * Open findings, split by what decides the grade. The buckets overlap on purpose: a KEV with
 * a fix is counted in `kevWithFix` and in its severity bucket too. `gradeOf` checks the rules
 * from the worst down, so the overlap never matters.
 */
export interface GradeCounts {
  /** Listed in CISA KEV, whatever its severity, and a fixed version is known. */
  kevWithFix: number;
  criticalWithFix: number;
  criticalWithoutFix: number;
  highWithFix: number;
  highWithoutFix: number;
  mediumWithFix: number;
  mediumWithoutFix: number;
  /** Everything else: low, negligible and unknown severity, with or without a fix. */
  otherOpen: number;
}

export const emptyGradeCounts = (): GradeCounts => ({
  kevWithFix: 0,
  criticalWithFix: 0,
  criticalWithoutFix: 0,
  highWithFix: 0,
  highWithoutFix: 0,
  mediumWithFix: 0,
  mediumWithoutFix: 0,
  otherOpen: 0,
});

/** The rule that decided a grade, from the worst to the mildest. */
export const GRADE_RULES = [
  "known-exploited-with-fix",
  "critical-with-fix",
  "high-with-fix",
  "critical-without-fix",
  "medium-with-fix",
  "high-without-fix",
  "other-open",
  "none",
] as const;
export type GradeRule = (typeof GRADE_RULES)[number];

/** The grade each rule gives. */
export const GRADE_OF_RULE: Readonly<Record<GradeRule, Grade>> = Object.freeze({
  "known-exploited-with-fix": "F",
  "critical-with-fix": "E",
  "high-with-fix": "D",
  "critical-without-fix": "D",
  "medium-with-fix": "C",
  "high-without-fix": "C",
  "other-open": "B",
  none: "A",
});

export interface GradeResult {
  grade: Grade;
  /** The rule that decided. With two rules at the same grade, the one with a fix comes first. */
  rule: GradeRule;
  /** How many open findings match the deciding rule. 0 for A. */
  count: number;
}

/** The grade of one repository or server from the counts of its open findings. */
export function gradeOf(counts: GradeCounts): GradeResult {
  const decided = (rule: GradeRule, count: number): GradeResult => ({
    grade: GRADE_OF_RULE[rule],
    rule,
    count,
  });
  if (counts.kevWithFix > 0) return decided("known-exploited-with-fix", counts.kevWithFix);
  if (counts.criticalWithFix > 0) return decided("critical-with-fix", counts.criticalWithFix);
  if (counts.highWithFix > 0) return decided("high-with-fix", counts.highWithFix);
  if (counts.criticalWithoutFix > 0) return decided("critical-without-fix", counts.criticalWithoutFix);
  if (counts.mediumWithFix > 0) return decided("medium-with-fix", counts.mediumWithFix);
  if (counts.highWithoutFix > 0) return decided("high-without-fix", counts.highWithoutFix);
  const others = counts.mediumWithoutFix + counts.otherOpen;
  if (others > 0) return decided("other-open", others);
  return decided("none", 0);
}

/** A finding as far as the grade is concerned. */
export interface GradeFinding {
  severity: string;
  /** At least one fixed version is known. */
  hasFix: boolean;
  /** Listed in CISA KEV. */
  knownExploited: boolean;
}

/**
 * Counts open findings into the buckets `gradeOf` reads. The database does the same in SQL
 * (apps/api/src/lib/grades.ts); tests check that both agree.
 */
export function gradeCountsOf(findings: readonly GradeFinding[]): GradeCounts {
  const counts = emptyGradeCounts();
  for (const f of findings) {
    if (f.knownExploited && f.hasFix) counts.kevWithFix++;
    if (f.severity === "critical") f.hasFix ? counts.criticalWithFix++ : counts.criticalWithoutFix++;
    else if (f.severity === "high") f.hasFix ? counts.highWithFix++ : counts.highWithoutFix++;
    else if (f.severity === "medium") f.hasFix ? counts.mediumWithFix++ : counts.mediumWithoutFix++;
    else counts.otherOpen++;
  }
  return counts;
}

/** The rank (0 to 5) of a finding on its own: the grade a repository with only this finding has. */
export function findingGradeRank(finding: GradeFinding): number {
  return GRADE_RANK[gradeOf(gradeCountsOf([finding])).grade];
}

/**
 * Parses a comma-separated grade filter such as "F,E,none". Returns null for anything
 * unknown, so the caller can refuse the request instead of silently showing everything.
 */
export function parseGradeFilter(value: string): GradeFilterValue[] | null {
  const parts = value.split(",").filter(Boolean);
  if (parts.length === 0) return null;
  const out: GradeFilterValue[] = [];
  for (const part of parts) {
    if (!(GRADE_FILTER_VALUES as readonly string[]).includes(part)) return null;
    if (!out.includes(part as GradeFilterValue)) out.push(part as GradeFilterValue);
  }
  return out;
}
