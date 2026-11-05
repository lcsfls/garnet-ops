import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { toPdfDocument, wrap } from "./pdf.ts";
import {
  addDays,
  compareWebsites,
  daysIn,
  dueReportMail,
  emptyCounts,
  localParts,
  mailPeriod,
  type OrganizationReport,
  organizationNextSteps,
  rangePeriod,
  reportFileName,
  repositoryNextSteps,
  type WebsiteOverviewRow,
} from "./reports.ts";

const at = (iso: string) => new Date(iso);

describe("calendar days (ADR 0005)", () => {
  it("adds days on the calendar, across month and year ends", () => {
    expect(addDays("2026-10-31", 1)).toBe("2026-11-01");
    expect(addDays("2026-03-01", -1)).toBe("2026-02-28");
    expect(addDays("2028-03-01", -1)).toBe("2028-02-29");
    expect(addDays("2026-12-31", 1)).toBe("2027-01-01");
    expect(daysIn("2026-10-01", "2026-10-31")).toBe(31);
  });

  it("names the local date and time of an instant in the zone, not the machine's", () => {
    // 23:30 UTC on 24 October is already 01:30 on the 25th in Berlin (summer time, UTC+2).
    expect(localParts(at("2026-10-24T23:30:00Z"), "Europe/Berlin")).toEqual({
      date: "2026-10-25",
      time: "01:30",
    });
    expect(localParts(at("2026-10-24T23:30:00Z"), "UTC")).toEqual({ date: "2026-10-24", time: "23:30" });
    expect(localParts(at("2026-10-24T23:30:00Z"), "America/New_York").date).toBe("2026-10-24");
  });

  it("the last 7 and 30 days end today in the reader's zone", () => {
    expect(rangePeriod(7, "Europe/Berlin", at("2026-11-01T23:30:00Z"))).toEqual({
      from: "2026-10-27",
      to: "2026-11-02",
      days: 7,
      timeZone: "Europe/Berlin",
    });
    expect(rangePeriod(30, "UTC", at("2026-11-01T23:30:00Z"))).toMatchObject({
      from: "2026-10-03",
      to: "2026-11-01",
    });
  });

  it("a period across the autumn change is still 7 calendar days", () => {
    // Berlin 2026-10-25 has 25 hours; the period counts days, not 24-hour blocks.
    const p = rangePeriod(7, "Europe/Berlin", at("2026-10-28T10:00:00Z"));
    expect(p).toMatchObject({ from: "2026-10-22", to: "2026-10-28", days: 7 });
  });
});

describe("report mail periods", () => {
  const BERLIN = "Europe/Berlin";

  it("daily: the day before, from 07:00 local", () => {
    // 05:59 UTC is 06:59 in Berlin (winter time): today's mail is not due yet, yesterday's is.
    expect(mailPeriod("daily", BERLIN, at("2026-11-03T05:59:00Z"))).toEqual({
      period: { from: "2026-11-01", to: "2026-11-01", days: 1, timeZone: BERLIN },
      sendDate: "2026-11-02",
    });
    expect(mailPeriod("daily", BERLIN, at("2026-11-03T06:00:00Z")).period.from).toBe("2026-11-02");
  });

  it("weekly: Monday to Sunday, sent on Monday", () => {
    // Monday 2 November 2026, 08:00 Berlin.
    expect(mailPeriod("weekly", BERLIN, at("2026-11-02T07:00:00Z"))).toEqual({
      period: { from: "2026-10-26", to: "2026-11-01", days: 7, timeZone: BERLIN },
      sendDate: "2026-11-02",
    });
    // Monday 06:30 Berlin: still the week before last.
    expect(mailPeriod("weekly", BERLIN, at("2026-11-02T05:30:00Z")).period.from).toBe("2026-10-19");
    // Sunday evening: the week that ends today is not complete.
    expect(mailPeriod("weekly", BERLIN, at("2026-11-08T20:00:00Z")).period.from).toBe("2026-10-26");
  });

  it("weekly over the autumn change: the week with 25 hours on Sunday is one period", () => {
    // Week of 19 to 25 October 2026; the clocks go back on Sunday the 25th.
    const { period, sendDate } = mailPeriod("weekly", BERLIN, at("2026-10-26T06:00:00Z"));
    expect(period).toMatchObject({ from: "2026-10-19", to: "2026-10-25", days: 7 });
    expect(sendDate).toBe("2026-10-26");
    // 06:00 UTC on 26 October is 07:00 in Berlin (UTC+1 again).
    expect(localParts(at("2026-10-26T06:00:00Z"), BERLIN).time).toBe("07:00");
  });

  it("weekly over the spring change", () => {
    // 29 March 2026 has 23 hours in Berlin; Monday 30 March 07:00 local is 05:00 UTC.
    expect(mailPeriod("weekly", BERLIN, at("2026-03-30T04:59:00Z")).period.from).toBe("2026-03-16");
    expect(mailPeriod("weekly", BERLIN, at("2026-03-30T05:00:00Z")).period).toMatchObject({
      from: "2026-03-23",
      to: "2026-03-29",
      days: 7,
    });
  });

  it("monthly: the month before, sent on the 1st, across year ends and leap years", () => {
    expect(mailPeriod("monthly", BERLIN, at("2026-11-01T07:00:00Z")).period).toMatchObject({
      from: "2026-10-01",
      to: "2026-10-31",
      days: 31,
    });
    expect(mailPeriod("monthly", BERLIN, at("2027-01-01T06:00:00Z")).period).toMatchObject({
      from: "2026-12-01",
      to: "2026-12-31",
    });
    expect(mailPeriod("monthly", "UTC", at("2028-03-15T12:00:00Z")).period).toMatchObject({
      from: "2028-02-01",
      to: "2028-02-29",
      days: 29,
    });
    // On the 1st before 07:00 the month before last is the latest due one.
    expect(mailPeriod("monthly", BERLIN, at("2026-11-01T05:00:00Z")).period.from).toBe("2026-09-01");
  });

  it("a zone whose midnight is skipped (America/Santiago, 6 September 2026)", () => {
    // Clocks jump from 00:00 to 01:00 on Sunday 6 September; the day still counts once.
    const sunday = mailPeriod("daily", "America/Santiago", at("2026-09-07T12:00:00Z"));
    expect(sunday.period).toMatchObject({ from: "2026-09-06", to: "2026-09-06", days: 1 });
    expect(localParts(at("2026-09-06T04:30:00Z"), "America/Santiago").date).toBe("2026-09-06");
  });

  it("is due only after the send time and only for a frequency chosen before it", () => {
    const since = at("2026-10-01T10:00:00Z");
    expect(
      dueReportMail({ frequency: "weekly", timeZone: BERLIN, now: at("2026-11-02T06:30:00Z"), since }),
    ).toEqual({
      key: "weekly:2026-10-26",
      period: { from: "2026-10-26", to: "2026-11-01", days: 7, timeZone: BERLIN },
    });
    // Chosen on Monday at 10:00, after this Monday's send time: nothing until next Monday.
    const late = at("2026-11-02T09:00:00Z");
    expect(
      dueReportMail({ frequency: "weekly", timeZone: BERLIN, now: at("2026-11-02T12:00:00Z"), since: late }),
    ).toBe(null);
    expect(
      dueReportMail({ frequency: "weekly", timeZone: BERLIN, now: at("2026-11-09T06:00:00Z"), since: late })
        ?.key,
    ).toBe("weekly:2026-11-02");
  });

  it("the key is the same for every tick of one period, so a repeated hour cannot send twice", () => {
    const since = at("2026-01-01T00:00:00Z");
    // 00:30 UTC and 01:30 UTC on 25 October are both "02:30" local in Berlin (the repeated hour).
    const a = dueReportMail({ frequency: "daily", timeZone: BERLIN, now: at("2026-10-25T00:30:00Z"), since });
    const b = dueReportMail({ frequency: "daily", timeZone: BERLIN, now: at("2026-10-25T01:30:00Z"), since });
    expect(a?.key).toBe("daily:2026-10-23");
    expect(b?.key).toBe(a?.key);
  });
});

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

describe("websites worst first", () => {
  it("orders by worst state, then counts, then software, then certificate, then name", () => {
    const rows = [
      row("b.example.com"),
      row("a.example.com"),
      row("cert.example.com", { certificateDays: 3 }),
      row("old.example.com", { software: { outdated: [], endOfLife: ["PHP 7.4"] } }),
      row("high.example.com", { worst: "high", open: { ...emptyCounts(), high: 1 } }),
      row("crit.example.com", { worst: "critical", open: { ...emptyCounts(), critical: 1 } }),
      row("high2.example.com", { worst: "high", open: { ...emptyCounts(), high: 2 } }),
    ];
    expect(rows.sort(compareWebsites).map((r) => r.value)).toEqual([
      "crit.example.com",
      "high2.example.com",
      "high.example.com",
      "old.example.com",
      "cert.example.com",
      "a.example.com",
      "b.example.com",
    ]);
  });
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
      neverScanned: [{ id: "r3", name: "docs" }],
      neverScannedCount: 1,
    },
    gates: { passed: 5, notes: 1, blocked: 2 },
    earlyWarnings: { repositories: 0, runtime: null },
    accepted: { total: 1, expired: 0, endingSoon: 0 },
    top: {
      repositories: [{ id: "r1", name: "web", open: { critical: 2, high: 3, medium: 0, low: 1 } }],
      hosts: null,
    },
    hosts: null,
    websites: [
      row("down.example.com", { availability: { enabled: true, state: "down", since: null }, worst: "high" }),
    ],
    vulnDb: { builtAt: "2026-11-01T03:00:00.000Z", freshness: "current" },
    ...patch,
  };
  return { ...base, nextSteps: organizationNextSteps(base) };
}

describe("next steps", () => {
  it("names what is due, worst first, and 'nothing' when nothing is", () => {
    const report = organizationReport();
    expect(report.nextSteps.map((s) => s.code)).toEqual([
      "fixCritical",
      "gatesBlocked",
      "neverScanned",
      "websitesDown",
    ]);
    const repository = repositoryNextSteps({
      kind: "repository",
      generatedAt: "",
      repository: { id: "r", name: "r", url: "", branch: null, inactive: false },
      lastScan: { state: "succeeded", at: "" },
      lastSuccessfulScan: { at: "", commit: null, packages: 1 },
      vulnDb: { builtAt: "2026-11-01T00:00:00Z", freshness: "current" },
      open: emptyCounts(),
      fixable: emptyCounts(),
      knownExploited: 0,
      accepted: { total: 0, expired: 0 },
      grade: { grade: "A", stale: false },
      gate: null,
      earlyWarnings: { open: 0, worst: null },
      top: [],
    });
    expect(repository).toEqual([{ code: "nothing" }]);
  });
});

describe("PDF document writer", () => {
  it("wraps long text and breaks words longer than a line", () => {
    const lines = wrap(`${"word ".repeat(40)}${"x".repeat(300)}`, 200, 10);
    expect(lines.length).toBeGreaterThan(5);
  });

  it("escapes hostile text and repeats a table over pages", () => {
    const pdf = toPdfDocument({
      title: "T",
      meta: [],
      blocks: [
        {
          kind: "table",
          columns: [{ label: "Name", width: 1 }],
          rows: Array.from({ length: 120 }, (_, i) => [`row ${i} ) Tj (injected`]),
        },
      ],
    });
    const text = pageText(pdf);
    expect(text).toContain("row 119 \\) Tj \\(injected");
    expect(pdf.toString("latin1")).toMatch(/\/Count [2-9]/);
  });

  it("names report files with safe characters only", () => {
    expect(reportFileName("../My Repo!", "2026-11-02")).toBe("garnetops-report-my-repo-2026-11-02.pdf");
    expect(reportFileName("", "2026-11-02")).toBe("garnetops-report-2026-11-02.pdf");
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
