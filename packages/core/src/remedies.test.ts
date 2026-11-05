import { describe, expect, test } from "vitest";
import { groupRemedies, headlineFacts, type RemedyFinding, summarizeRemedies } from "./remedies.ts";

const RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, negligible: 1, unknown: 0 };

let n = 0;
function finding(patch: Partial<RemedyFinding> & { vulnerabilityId: string }): RemedyFinding {
  n++;
  const severity = patch.severity ?? "high";
  return {
    id: `fnd_${n}`,
    repositoryId: "repo_a",
    repositoryName: "api",
    severity,
    severityRank: RANK[severity] ?? 0,
    packageType: "npm",
    packageName: "lodash",
    packageVersion: "4.17.15",
    fixedIn: [],
    knownExploited: false,
    ...patch,
  };
}

describe("groupRemedies", () => {
  test("one group per package and installed version; the target is the highest fixed version needed", () => {
    const [remedy, ...rest] = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.19"] }),
      finding({ vulnerabilityId: "CVE-2", fixedIn: ["4.17.21"] }),
      finding({ vulnerabilityId: "CVE-3", fixedIn: ["4.17.23"], severity: "critical" }),
      finding({ vulnerabilityId: "CVE-4", fixedIn: ["4.18.0"], severity: "medium" }),
    ]);
    expect(rest).toEqual([]);
    expect(remedy).toMatchObject({
      packageName: "lodash",
      ecosystem: "npm",
      fromVersion: "4.17.15",
      toVersion: "4.18.0",
      complete: true,
      laterVersion: null,
      remainingVulnerabilityIds: [],
      findings: 4,
    });
    expect(remedy?.closes).toMatchObject({
      total: 4,
      bySeverity: { critical: 1, high: 2, medium: 1 },
      vulnerabilityIds: ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
      worstRank: 5,
    });
    // The keys come in severity order, worst first.
    expect(Object.keys(remedy?.closes.bySeverity ?? {})).toEqual(["critical", "high", "medium"]);
  });

  test("takes the lowest fix per vulnerability in the installed major release, never a pre-release", () => {
    const [remedy] = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.21", "5.0.1"] }),
      finding({ vulnerabilityId: "CVE-2", fixedIn: ["4.17.19", "4.17.22-rc.1"] }),
    ]);
    expect(remedy).toMatchObject({ toVersion: "4.17.21", complete: true });
  });

  test("prefers the current major release when it closes everything, even if a later one is listed too", () => {
    const [remedy] = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.21"] }),
      finding({ vulnerabilityId: "CVE-2", fixedIn: ["5.0.1", "4.17.23"] }),
    ]);
    expect(remedy).toMatchObject({ toVersion: "4.17.23", complete: true, laterVersion: null });
  });

  test("mixed major releases: no single fix; says what the current major closes and what would close the rest", () => {
    const [remedy] = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.21"] }),
      finding({ vulnerabilityId: "CVE-2", fixedIn: ["5.0.1"], severity: "critical" }),
    ]);
    expect(remedy).toMatchObject({
      toVersion: "4.17.21",
      complete: false,
      laterVersion: "5.0.1",
      remainingVulnerabilityIds: ["CVE-2"],
      findings: 2,
    });
    expect(remedy?.closes).toMatchObject({ total: 1, bySeverity: { high: 1 }, worstRank: 4 });
  });

  test("nothing in the current major release: no target, nothing closed", () => {
    const [remedy] = groupRemedies([finding({ vulnerabilityId: "CVE-1", fixedIn: ["5.0.1"] })]);
    expect(remedy).toMatchObject({ toVersion: null, complete: false, laterVersion: "5.0.1" });
    expect(remedy?.closes.total).toBe(0);
  });

  test("a fixed version below the installed one, a pre-release or text that is no version is never a target", () => {
    const [remedy] = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.10", "4.18.0-beta.1", "see advisory"] }),
    ]);
    expect(remedy).toMatchObject({ toVersion: null, complete: false, laterVersion: null });
  });

  test("counts across repositories; the same version elsewhere is the same remedy, another version is another", () => {
    const remedies = groupRemedies([
      finding({
        vulnerabilityId: "CVE-1",
        fixedIn: ["1.2.6"],
        packageName: "minimist",
        packageVersion: "1.2.0",
      }),
      finding({
        vulnerabilityId: "CVE-1",
        fixedIn: ["1.2.6"],
        packageName: "minimist",
        packageVersion: "1.2.0",
        repositoryId: "repo_b",
        repositoryName: "billing",
      }),
      finding({
        vulnerabilityId: "CVE-1",
        fixedIn: ["1.2.6"],
        packageName: "minimist",
        packageVersion: "1.2.5",
      }),
    ]);
    expect(remedies).toHaveLength(2);
    const [same] = remedies.filter((r) => r.fromVersion === "1.2.0");
    expect(same?.repositories).toEqual([
      { id: "repo_a", name: "api" },
      { id: "repo_b", name: "billing" },
    ]);
    expect(same?.closes.total).toBe(2);
  });

  test("findings without a fixed version form no group", () => {
    expect(groupRemedies([finding({ vulnerabilityId: "CVE-1", fixedIn: [] })])).toEqual([]);
  });

  test("known exploited first, then the worst severity closed, then the number of findings closed", () => {
    const order = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", packageName: "many-highs", fixedIn: ["4.17.16"] }),
      finding({ vulnerabilityId: "CVE-2", packageName: "many-highs", fixedIn: ["4.17.16"] }),
      finding({ vulnerabilityId: "CVE-3", packageName: "many-highs", fixedIn: ["4.17.16"] }),
      finding({
        vulnerabilityId: "CVE-4",
        packageName: "one-critical",
        fixedIn: ["4.17.16"],
        severity: "critical",
      }),
      finding({
        vulnerabilityId: "CVE-5",
        packageName: "exploited-medium",
        fixedIn: ["4.17.16"],
        severity: "medium",
      }),
      finding({
        vulnerabilityId: "CVE-6",
        packageName: "exploited-medium",
        fixedIn: ["4.17.16"],
        severity: "medium",
        knownExploited: true,
      }),
      finding({ vulnerabilityId: "CVE-7", packageName: "one-high", fixedIn: ["4.17.16"] }),
    ]).map((r) => r.packageName);
    expect(order).toEqual(["exploited-medium", "one-critical", "many-highs", "one-high"]);
  });

  test("the summary counts the upgrades that close something, against every open finding", () => {
    const remedies = groupRemedies([
      finding({ vulnerabilityId: "CVE-1", fixedIn: ["4.17.21"] }),
      finding({ vulnerabilityId: "CVE-2", packageName: "other", fixedIn: ["9.0.0"] }),
    ]);
    expect(summarizeRemedies(remedies, 5)).toEqual({ upgrades: 1, closes: 1, open: 5 });
  });
});

describe("headlineFacts", () => {
  test("two criticals from one package in two repositories, one upgrade fixes both, none exploited", () => {
    const findings = [
      finding({
        vulnerabilityId: "CVE-1",
        severity: "critical",
        packageName: "minimist",
        packageVersion: "1.2.0",
        fixedIn: ["1.2.6"],
      }),
      finding({
        vulnerabilityId: "CVE-1",
        severity: "critical",
        packageName: "minimist",
        packageVersion: "1.2.0",
        fixedIn: ["1.2.6"],
        repositoryId: "repo_b",
        repositoryName: "billing",
      }),
      finding({ vulnerabilityId: "CVE-9", severity: "high", fixedIn: [] }),
    ];
    expect(headlineFacts(findings, groupRemedies(findings))).toEqual({
      level: "critical",
      count: 2,
      repositories: 2,
      package: { name: "minimist", version: "1.2.0" },
      packages: 1,
      oneUpgrade: {
        remedyKey: "npm\u001fminimist\u001f1.2.0",
        packageName: "minimist",
        fromVersion: "1.2.0",
        toVersion: "1.2.6",
      },
      fixable: 2,
      upgrades: 1,
      knownExploited: 0,
    });
  });

  test("several packages: no one upgrade; counts what upgrades fix and what is known exploited", () => {
    const findings = [
      finding({ vulnerabilityId: "CVE-1", severity: "critical", packageName: "a", fixedIn: ["4.17.16"] }),
      finding({ vulnerabilityId: "CVE-2", severity: "critical", packageName: "b", knownExploited: true }),
      finding({ vulnerabilityId: "CVE-3", severity: "critical", packageName: "c", fixedIn: ["4.17.16"] }),
    ];
    expect(headlineFacts(findings, groupRemedies(findings))).toMatchObject({
      level: "critical",
      count: 3,
      repositories: 1,
      package: null,
      packages: 3,
      oneUpgrade: null,
      fixable: 2,
      upgrades: 2,
      knownExploited: 1,
    });
  });

  test("an upgrade that fixes only part of a package's findings is not the one upgrade", () => {
    const findings = [
      finding({ vulnerabilityId: "CVE-1", severity: "critical", fixedIn: ["4.17.21"] }),
      finding({ vulnerabilityId: "CVE-2", severity: "critical", fixedIn: ["5.0.1"] }),
    ];
    expect(headlineFacts(findings, groupRemedies(findings))).toMatchObject({
      package: { name: "lodash", version: "4.17.15" },
      oneUpgrade: null,
      fixable: 1,
      upgrades: 1,
    });
  });

  test("high when no critical is open, none when neither is", () => {
    const highs = [finding({ vulnerabilityId: "CVE-1", severity: "high" })];
    expect(headlineFacts(highs, [])).toMatchObject({ level: "high", count: 1, fixable: 0, oneUpgrade: null });
    const mediums = [finding({ vulnerabilityId: "CVE-1", severity: "medium" })];
    expect(headlineFacts(mediums, [])).toMatchObject({ level: "none", count: 0 });
    expect(headlineFacts([], [])).toMatchObject({ level: "none", count: 0 });
  });
});
