/**
 * The report documents and the report mail with the real words of packages/i18n (ADR 0047): what the PDF says, that the mail
 * stays a short summary with counts and links (no names of repositories, findings or packages, ADR 0010), and that hostile
 * names cannot break the PDF or a mail header. Both languages are checked for every key the documents use.
 */
import { inflateSync } from "node:zlib";
import { toPdfDocument } from "@garnetops/core/pdf";
import {
  format,
  hostReportDocument,
  organizationReportDocument,
  type ReportMessages,
  reportMail,
  repositoryReportDocument,
} from "@garnetops/core/report-documents";
import {
  emptyCounts,
  type HostReport,
  hostNextSteps,
  type OrganizationReport,
  organizationNextSteps,
  type RepositoryReport,
  repositoryNextSteps,
  type WebsiteOverviewRow,
} from "@garnetops/core/reports";
import { resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";

const en = resources.en.translation as unknown as ReportMessages;
const de = resources.de.translation as unknown as ReportMessages;

const row = (value: string, patch: Partial<WebsiteOverviewRow> = {}): WebsiteOverviewRow => ({
  id: value,
  value,
  kind: "domain",
  verifyState: "verified",
  verified: true,
  availability: { enabled: false, state: null, since: null },
  certificateExpires: null,
  certificateDays: null,
  open: emptyCounts(),
  worst: null,
  worstRule: null,
  software: { outdated: [], endOfLife: [] },
  lastCheckedAt: null,
  checkError: null,
  ...patch,
});

function organizationReport(patch: Partial<OrganizationReport> = {}): OrganizationReport {
  const base: Omit<OrganizationReport, "nextSteps"> = {
    kind: "organization",
    generatedAt: "2026-11-02T07:00:00.000Z",
    organization: "Example (Ltd)",
    period: { from: "2026-10-26", to: "2026-11-01", days: 7, timeZone: "Europe/Berlin" },
    findings: {
      open: { critical: 2, high: 3, medium: 0, low: 1 },
      opened: { critical: 1, high: 0, medium: 0, low: 0 },
      fixed: { critical: 0, high: 4, medium: 0, low: 0 },
      fixableCritical: 2,
      knownExploited: 0,
    },
    repositories: {
      total: 3,
      scanned: 2,
      failedScans: 0,
      neverScanned: [{ id: "r3", name: "handbook-site" }],
      neverScannedCount: 1,
    },
    gates: { passed: 5, notes: 1, blocked: 2 },
    earlyWarnings: { repositories: 0, runtime: null },
    accepted: { total: 1, expired: 0, endingSoon: 0 },
    top: {
      repositories: [
        { id: "r1", name: "payroll-service", open: { critical: 2, high: 3, medium: 0, low: 1 } },
      ],
      hosts: null,
    },
    hosts: null,
    websites: [
      row("down.example.com", {
        availability: { enabled: true, state: "down", since: null },
        worst: "high",
        certificateDays: 5,
        software: { outdated: ["nginx 1.24.0"], endOfLife: [] },
        lastCheckedAt: "2026-11-01T22:00:00.000Z",
      }),
    ],
    vulnDb: { builtAt: "2026-11-01T03:00:00.000Z", freshness: "current" },
    ...patch,
  };
  return { ...base, nextSteps: organizationNextSteps(base) };
}

describe("organisation report document and mail", () => {
  const ctx = { language: "en", timeZone: "Europe/Berlin" };

  it("writes a PDF with the period, the counts and the website table", () => {
    const pdf = toPdfDocument(organizationReportDocument(organizationReport(), en, ctx));
    expect(pageText(toPdfDocument(organizationReportDocument(organizationReport(), de, ctx)))).toContain(
      "Sicherheitsbericht: Example",
    );
    expect(pdf.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
    const text = pageText(pdf);
    expect(text).toContain("Security report: Example \\(Ltd\\)");
    expect(text).toContain("Oct 26, 2026 to Nov 1, 2026 \\(7 days\\)");
    expect(text).toContain("down.example.com");
    expect(text).toContain("6 open: 2 critical, 3 high, 0 medium, 1 low");
  });

  it("keeps the mail short: counts and links, no names of repositories", () => {
    const mail = reportMail(organizationReport(), "weekly", en, ctx, {
      origin: "https://garnetops.example.com",
      attached: true,
    });
    expect(mail.subject).toBe("Weekly security report: Example (Ltd), Oct 26, 2026 to Nov 1, 2026");
    expect(mail.text).toContain("Open findings: 6 open: 2 critical, 3 high, 0 medium, 1 low");
    expect(mail.text).toContain("Websites down: 1.");
    expect(mail.text).toContain("https://garnetops.example.com/account?section=notifications");
    expect(mail.text).not.toContain("payroll-service");
    expect(mail.text).not.toContain("handbook-site");
    expect(mail.text.split("\n").length).toBeLessThan(25);
  });

  it("a monthly subject names the month; a daily one the day", () => {
    const monthly = organizationReport({
      period: { from: "2026-10-01", to: "2026-10-31", days: 31, timeZone: "UTC" },
    });
    expect(reportMail(monthly, "monthly", en, ctx, { origin: "", attached: false }).subject).toContain(
      "October 2026",
    );
    const daily = organizationReport({
      period: { from: "2026-11-01", to: "2026-11-01", days: 1, timeZone: "UTC" },
    });
    expect(reportMail(daily, "daily", en, ctx, { origin: "", attached: false }).subject).toContain(
      "Nov 1, 2026",
    );
  });

  it("removes line breaks from a hostile organisation name in the subject", () => {
    const report = organizationReport({ organization: "Evil\r\nBcc: someone@example.com" });
    expect(reportMail(report, "daily", en, ctx, { origin: "", attached: false }).subject).not.toMatch(
      /[\r\n]/,
    );
  });
});

describe("message format", () => {
  it("fills plurals per language, and never parses inserted values", () => {
    const text = "{count, plural, =0 {none} one {# host has} other {# hosts have}} {name}";
    expect(format(text, { count: 1, name: "a" }, "en")).toBe("1 host has a");
    expect(format(text, { count: 3, name: "{count}" }, "en")).toBe("3 hosts have {count}");
    expect(format(text, { count: 0, name: "" }, "de")).toBe("none ");
    expect(format("{missing}", {}, "en")).toBe("{missing}");
  });

  it("every report text of English and German is a valid message", () => {
    for (const language of ["en", "de"] as const) {
      const texts = resources[language].translation.reports;
      const walk = (value: unknown): void => {
        if (typeof value === "string") {
          expect(format(value, { count: 2, days: 2, failed: 2, open: 2 }, language)).not.toMatch(/plural/);
        } else for (const inner of Object.values(value as object)) walk(inner);
      };
      walk(texts);
    }
  });
});

describe("repository and host documents", () => {
  const ctx = { language: "de", timeZone: "Europe/Berlin" };

  it("a repository report names grade, gate, scan, database and the worst findings", () => {
    const base: Omit<RepositoryReport, "nextSteps"> = {
      kind: "repository",
      generatedAt: "2026-11-02T07:00:00.000Z",
      repository: {
        id: "r",
        name: "web",
        url: "https://git.example.lan/web.git",
        branch: null,
        inactive: false,
      },
      lastScan: { state: "failed", at: "2026-11-02T03:00:00.000Z" },
      lastSuccessfulScan: { at: "2026-11-01T03:00:00.000Z", commit: "a".repeat(40), packages: 412 },
      vulnDb: { builtAt: "2026-10-20T03:00:00.000Z", freshness: "outdated" },
      open: { critical: 1, high: 0, medium: 2, low: 0 },
      fixable: { critical: 1, high: 0, medium: 0, low: 0 },
      knownExploited: 1,
      accepted: { total: 2, expired: 1 },
      grade: { grade: "E", stale: true },
      gate: { result: "blocked", at: "2026-11-02T03:01:00.000Z" },
      earlyWarnings: { open: 0, worst: null },
      top: [
        {
          severity: "critical",
          vulnerabilityId: "CVE-2099-0001",
          packageName: "left-pad(",
          packageVersion: "1.0.0",
          fixedIn: ["1.0.1"],
          knownExploited: true,
        },
      ],
    };
    const report = { ...base, nextSteps: repositoryNextSteps(base) };
    expect(report.nextSteps.map((s) => s.code)).toEqual([
      "scanFailed",
      "knownExploited",
      "fixCritical",
      "gateBlocked",
      "acceptedExpired",
      "vulnDbStale",
    ]);
    const text = pageText(toPdfDocument(repositoryReportDocument(report, de, ctx)));
    expect(text).toContain("Bericht: web");
    expect(text).toContain("E \\(der letzte Scan ist fehlgeschlagen\\)");
    expect(text).toContain("CVE-2099-0001");
    expect(text).toContain("left-pad\\(");
    expect(text).toContain("Standard-Branch");
  });

  it("a host report counts kernel, host packages and images apart", () => {
    const base: Omit<HostReport, "nextSteps"> = {
      kind: "host",
      generatedAt: "2026-11-02T07:00:00.000Z",
      host: {
        id: "h",
        name: "build-01",
        hostname: "build-01.example.lan",
        os: "Debian 12",
        runtime: "systemd",
        agentVersion: "0.0.18",
      },
      lastReportAt: "2026-10-30T07:00:00.000Z",
      reporting: false,
      kernel: {
        release: "6.1.0-1-amd64",
        checked: true,
        matchedAt: null,
        open: { critical: 0, high: 2, medium: 0, low: 0 },
      },
      packages: {
        count: 900,
        matchedAt: null,
        open: { critical: 0, high: 0, medium: 3, low: 0 },
        fixable: 3,
      },
      images: { containers: 0, images: 0, withSerious: 0, notMatched: 0, updates: 0, open: emptyCounts() },
      open: { critical: 0, high: 2, medium: 3, low: 0 },
      vulnDb: { builtAt: null, freshness: "unknown" },
      earlyWarnings: { open: 0, worst: null },
      top: [],
    };
    const report = { ...base, nextSteps: hostNextSteps(base) };
    expect(report.nextSteps.map((s) => s.code)).toEqual([
      "hostNotReporting",
      "kernelUpdate",
      "packagesUpdate",
    ]);
    const text = pageText(toPdfDocument(hostReportDocument(report, en, { language: "en", timeZone: "UTC" })));
    expect(text).toContain("6.1.0-1-amd64: 2 open");
    expect(text).toContain("900 packages, 3 open vulnerabilities");
    expect(text).toContain("No open findings.");
  });
});

/** The text operators of every page, inflated. */
function pageText(pdf: Buffer): string {
  const raw = pdf.toString("latin1");
  const out: string[] = [];
  const re = />>\nstream\n/g;
  let match: RegExpExecArray | null = re.exec(raw);
  while (match) {
    const start = match.index + match[0].length;
    const end = raw.indexOf("\nendstream", start);
    out.push(inflateSync(pdf.subarray(start, end)).toString("latin1"));
    match = re.exec(raw);
  }
  return out.join("\n");
}
