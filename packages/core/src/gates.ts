/**
 * Quality gate rules (ADR 0008). Pure evaluation, shared by the worker (after each scan)
 * and the API (rule descriptions, defaults).
 *
 * Defaults never block: a rule only fails a pipeline after an admin set it to "block".
 * Changing a default here would change gate behaviour on upgrade (AGENTS.md rule 2), so
 * a test pins them.
 */
export const GATE_RULES = ["critical-fixable", "known-exploited", "high-fixable", "license-denied"] as const;
export type GateRule = (typeof GATE_RULES)[number];

export const GATE_MODES = ["off", "report", "block"] as const;
export type GateMode = (typeof GATE_MODES)[number];

export const GATE_DEFAULTS: Readonly<Record<GateRule, GateMode>> = Object.freeze({
  "critical-fixable": "report",
  "known-exploited": "report",
  "high-fixable": "report",
  "license-denied": "off",
});

export type GateResult = "passed" | "notes" | "blocked";

export interface GateFinding {
  severity: string;
  cvssScore: number | null;
  knownExploited: boolean;
  /** A fixed version is known. */
  fixable: boolean;
}

export interface GatePackage {
  /** Licence expressions as syft reports them, e.g. "MIT" or "(MIT OR Apache-2.0)". */
  licenses: string[] | null;
}

export type GateMatches = Partial<Record<GateRule, { count: number; mode: GateMode }>>;

const SPDX_OPERATORS = new Set(["AND", "OR", "WITH"]);

/**
 * True if every way to use the package hits a denied licence. "A OR B" offers a choice,
 * so it is denied only when both A and B are; "A AND B" is denied when either is.
 */
export function licenseDenied(expression: string, denied: ReadonlySet<string>): boolean {
  if (denied.size === 0) return false;
  const alternatives = expression
    .replace(/[()]/g, " ")
    .split(/\s+OR\s+/i)
    .map((alt) =>
      alt
        .split(/\s+/)
        .filter((token) => token && !SPDX_OPERATORS.has(token.toUpperCase()))
        .map((token) => token.toLowerCase()),
    )
    .filter((ids) => ids.length > 0);
  if (alternatives.length === 0) return false;
  return alternatives.every((ids) => ids.some((id) => denied.has(id)));
}

const RULE_MATCHES: Record<Exclude<GateRule, "license-denied">, (f: GateFinding) => boolean> = {
  "critical-fixable": (f) => f.fixable && (f.severity === "critical" || (f.cvssScore ?? 0) >= 9),
  "known-exploited": (f) => f.knownExploited,
  "high-fixable": (f) => f.fixable && f.severity === "high",
};

/**
 * Evaluates the open findings (accepted risks excluded by the caller) and the package
 * inventory of one scan. Rules without a stored mode use their default.
 */
export function evaluateGate(input: {
  findings: GateFinding[];
  packages: GatePackage[];
  modes: Partial<Record<GateRule, GateMode>>;
  deniedLicenses: string[];
}): { result: GateResult; matches: GateMatches } {
  const matches: GateMatches = {};
  const denied = new Set(input.deniedLicenses.map((l) => l.trim().toLowerCase()).filter(Boolean));
  for (const rule of GATE_RULES) {
    const mode = input.modes[rule] ?? GATE_DEFAULTS[rule];
    if (mode === "off") continue;
    const count =
      rule === "license-denied"
        ? input.packages.filter((p) => (p.licenses ?? []).some((l) => licenseDenied(l, denied))).length
        : input.findings.filter(RULE_MATCHES[rule]).length;
    if (count > 0) matches[rule] = { count, mode };
  }
  const hits = Object.values(matches);
  const result: GateResult = hits.some((m) => m.mode === "block")
    ? "blocked"
    : hits.length > 0
      ? "notes"
      : "passed";
  return { result, matches };
}

/**
 * A ref a gate check may ask for: a branch, tag or forge ref such as "refs/pull/12/head".
 * Plain characters only, nothing git could read as an option or a range.
 */
export function isSafeGitRef(ref: string): boolean {
  return (
    /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(ref) &&
    !ref.includes("..") &&
    !ref.includes("//") &&
    !ref.endsWith("/") &&
    !ref.endsWith(".lock") &&
    !ref.endsWith(".")
  );
}

/** A full commit id (SHA-1 or SHA-256). */
export function isCommitSha(sha: string): boolean {
  return /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(sha);
}
