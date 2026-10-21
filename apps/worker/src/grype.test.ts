import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

vi.mock("./env.ts", () => ({ env: {} }));
const { addAdvisoryDates, parseDbDate, parseReport } = await import("./grype.ts");

const sample = {
  matches: [
    {
      vulnerability: {
        id: "GHSA-35jh-r3h4-6jhm",
        namespace: "github:language:javascript",
        severity: "High",
        description: "Command Injection in lodash",
        urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "javascript:alert(1)"],
        cvss: [{ version: "3.1", vector: "CVSS:3.1/AV:N", metrics: { baseScore: 7.2 } }],
        epss: [{ epss: 0.21 }],
        fix: { versions: ["4.17.21"], state: "fixed" },
      },
      relatedVulnerabilities: [{ id: "CVE-2021-23337" }],
      artifact: {
        name: "lodash",
        version: "4.17.20",
        type: "npm",
        purl: "pkg:npm/lodash@4.17.20",
        locations: [{ path: "/package-lock.json" }],
      },
    },
    {
      vulnerability: { id: "GHSA-35jh-r3h4-6jhm", severity: "High" },
      artifact: {
        name: "lodash",
        version: "4.17.20",
        type: "npm",
        locations: [{ path: "/web/package-lock.json" }],
      },
    },
    {
      vulnerability: { id: "CVE-2099-0001", severity: "Something odd", knownExploited: [{}] },
      artifact: { name: "openssl", version: "3.0.0", type: "deb" },
    },
  ],
  descriptor: { version: "0.120.1", db: { status: { built: "2026-10-19T06:39:15Z" } } },
};

describe("parseReport", () => {
  const parsed = parseReport(sample, "repo_1");

  it("deduplicates by repository, vulnerability and package and merges locations", () => {
    expect(parsed.findings.size).toBe(2);
    const lodash = parsed.findings.get("repo_1|GHSA-35jh-r3h4-6jhm|npm|lodash");
    expect(lodash?.locations).toEqual(["/package-lock.json", "/web/package-lock.json"]);
    expect(lodash?.fixedIn).toEqual(["4.17.21"]);
    expect(lodash?.severityRank).toBe(4);
  });

  it("keeps only http(s) URLs", () => {
    expect(parsed.vulnerabilities.get("GHSA-35jh-r3h4-6jhm")?.urls).toEqual([
      "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    ]);
  });

  it("maps unknown severities to unknown and flags known exploited", () => {
    const odd = parsed.vulnerabilities.get("CVE-2099-0001");
    expect(odd?.severity).toBe("unknown");
    expect(odd?.knownExploited).toBe(true);
  });

  it("reads aliases, scores, versions and counts packages", () => {
    const v = parsed.vulnerabilities.get("GHSA-35jh-r3h4-6jhm");
    expect(v?.aliases).toEqual(["CVE-2021-23337"]);
    expect(v?.cvssScore).toBe(7.2);
    expect(v?.epss).toBe(0.21);
    expect(parsed.grypeVersion).toBe("0.120.1");
    expect(parsed.dbBuiltAt?.toISOString()).toBe("2026-10-19T06:39:15.000Z");
  });

  it("rejects reports without matches", () => {
    expect(() => parseReport({ nope: true }, "repo_1")).toThrow();
  });
});

describe("parseReport on recorded grype output", () => {
  // grype 0.120.1 against test/fixtures/npm-vulnerable (see test/fixtures/README.md).
  const recorded = JSON.parse(
    readFileSync(new URL("../test/fixtures/grype-npm-vulnerable.json", import.meta.url), "utf8"),
  );

  it("reads every match of a real report", () => {
    const parsed = parseReport(recorded, "repo_1");
    expect(parsed.findings.size).toBe(8);
    expect(parsed.grypeVersion).toBe("0.120.1");
    expect(parsed.dbBuiltAt?.toISOString()).toBe("2026-10-19T06:39:15.000Z");
  });

  it("normalises severities and keeps fixed versions", () => {
    const parsed = parseReport(recorded, "repo_1");
    const minimist = parsed.findings.get("repo_1|GHSA-xvch-5gv4-984h|npm|minimist");
    expect(minimist).toMatchObject({
      severity: "critical",
      severityRank: 5,
      packageVersion: "1.2.0",
      fixedIn: ["1.2.6"],
    });
    const severities = new Set([...parsed.findings.values()].map((f) => f.severity));
    expect([...severities].sort()).toEqual(["critical", "high", "medium"]);
  });

  it("links GitHub advisories to their CVE aliases and keeps only http(s) references", () => {
    const parsed = parseReport(recorded, "repo_1");
    const lodash = parsed.vulnerabilities.get("GHSA-35jh-r3h4-6jhm");
    expect(lodash?.aliases).toContain("CVE-2021-23337");
    for (const v of parsed.vulnerabilities.values()) {
      for (const url of v.urls) expect(url).toMatch(/^https?:\/\//);
    }
  });
});

describe("advisory dates", () => {
  it("reads grype's datetime text as an instant", () => {
    expect(parseDbDate("2021-02-15 13:15:12.56+00:00")?.toISOString()).toBe("2021-02-15T13:15:12.560Z");
    expect(parseDbDate("2025-02-10 17:48:07+00:00")?.toISOString()).toBe("2025-02-10T17:48:07.000Z");
    expect(parseDbDate(null)).toBeNull();
    expect(parseDbDate("not a date")).toBeNull();
  });

  it("leaves the dates empty when the database is missing, without failing", () => {
    const report = parseReport(sample, "repo_1");
    addAdvisoryDates(report.vulnerabilities, "/does/not/exist");
    expect(report.vulnerabilities.get("GHSA-35jh-r3h4-6jhm")?.publishedAt).toBeNull();
  });

  const dbDir = fileURLToPath(new URL("../../../.tools/grype-db/", import.meta.url));
  it.skipIf(!existsSync(`${dbDir}6/vulnerability.db`))("takes the dates from the local database", () => {
    const report = parseReport(sample, "repo_1");
    addAdvisoryDates(report.vulnerabilities, dbDir);
    const v = report.vulnerabilities.get("GHSA-35jh-r3h4-6jhm");
    expect(v?.publishedAt?.toISOString().slice(0, 10)).toBe("2021-02-15");
    expect(v?.modifiedAt).toBeInstanceOf(Date);
  });
});
