import { describe, expect, test } from "vitest";
import {
  evaluateGate,
  GATE_DEFAULTS,
  type GateFinding,
  isCommitSha,
  isSafeGitRef,
  licenseDenied,
} from "./gates.ts";

const finding = (patch: Partial<GateFinding>): GateFinding => ({
  severity: "medium",
  cvssScore: null,
  knownExploited: false,
  fixable: false,
  ...patch,
});

describe("gate defaults", () => {
  test("no rule blocks unless an admin says so (AGENTS.md rule 2)", () => {
    expect(GATE_DEFAULTS).toEqual({
      "critical-fixable": "report",
      "known-exploited": "report",
      "high-fixable": "report",
      "license-denied": "off",
    });
    const { result } = evaluateGate({
      findings: [finding({ severity: "critical", fixable: true, knownExploited: true })],
      packages: [{ licenses: ["AGPL-3.0-only"] }],
      modes: {},
      deniedLicenses: ["AGPL-3.0-only"],
    });
    expect(result).toBe("notes");
  });
});

describe("evaluateGate", () => {
  test("passes when nothing matches", () => {
    expect(evaluateGate({ findings: [finding({})], packages: [], modes: {}, deniedLicenses: [] })).toEqual({
      result: "passed",
      matches: {},
    });
  });

  test("counts per rule and blocks only through a rule set to block", () => {
    const findings = [
      finding({ severity: "critical", fixable: true }),
      finding({ severity: "high", cvssScore: 9.1, fixable: true }),
      finding({ severity: "critical", fixable: false, knownExploited: true }),
      finding({ severity: "high", fixable: true }),
    ];
    const out = evaluateGate({
      findings,
      packages: [],
      modes: { "critical-fixable": "block", "high-fixable": "off" },
      deniedLicenses: [],
    });
    expect(out.result).toBe("blocked");
    expect(out.matches).toEqual({
      "critical-fixable": { count: 2, mode: "block" },
      "known-exploited": { count: 1, mode: "report" },
    });
  });

  test("licence rule counts packages with a denied licence once it is switched on", () => {
    const out = evaluateGate({
      findings: [],
      packages: [
        { licenses: ["AGPL-3.0-only"] },
        { licenses: ["(MIT OR AGPL-3.0-only)"] },
        { licenses: null },
      ],
      modes: { "license-denied": "block" },
      deniedLicenses: [" agpl-3.0-only "],
    });
    expect(out).toEqual({ result: "blocked", matches: { "license-denied": { count: 1, mode: "block" } } });
  });
});

describe("licenseDenied", () => {
  const denied = new Set(["agpl-3.0-only", "sspl-1.0"]);
  test.each([
    ["AGPL-3.0-only", true],
    ["MIT", false],
    ["MIT OR AGPL-3.0-only", false],
    ["(AGPL-3.0-only OR SSPL-1.0)", true],
    ["MIT AND AGPL-3.0-only", true],
    ["GPL-2.0-only WITH Classpath-exception-2.0", false],
    ["", false],
  ])("%s -> %s", (expression, expected) => {
    expect(licenseDenied(expression, denied)).toBe(expected);
  });
  test("an empty deny list denies nothing", () => {
    expect(licenseDenied("AGPL-3.0-only", new Set())).toBe(false);
  });
});

describe("isSafeGitRef", () => {
  test.each(["main", "release/1.2", "refs/pull/12/head", "refs/heads/feature-x", "v1.0.0"])(
    "accepts %s",
    (ref) => {
      expect(isSafeGitRef(ref)).toBe(true);
    },
  );
  test.each([
    "-upload-pack=evil",
    "--help",
    "main..evil",
    "a//b",
    "branch/",
    "x.lock",
    "a b",
    "a;b",
    "$(id)",
    "@{-1}",
    "",
  ])("refuses %s", (ref) => {
    expect(isSafeGitRef(ref)).toBe(false);
  });
});

describe("isCommitSha", () => {
  test("full SHA-1 and SHA-256 ids only", () => {
    expect(isCommitSha("a".repeat(40))).toBe(true);
    expect(isCommitSha("A".repeat(64))).toBe(true);
    expect(isCommitSha("abc123")).toBe(false);
    expect(isCommitSha(`${"a".repeat(39)}g`)).toBe(false);
  });
});
