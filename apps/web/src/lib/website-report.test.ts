import type { PassiveSnapshot } from "@garnetops/core/exposure";
import { resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";
import { REPORT_AREAS, websiteReport } from "./website-report.ts";
import type { ExposureDetail, ExposureFindingRow } from "./websites.ts";

const empty = { percent: null, averageMs: null, checks: 0 };

function detail(over: Partial<ExposureDetail> = {}): ExposureDetail {
  return {
    id: "exa_1",
    kind: "domain",
    value: "www.example.com",
    includeSubdomains: false,
    verification: {
      state: "verified",
      method: "dns",
      confirmedAt: null,
      checkedAt: null,
      error: null,
      effective: true,
      via: "self",
      parent: null,
    },
    stage1: { enabled: true, lastAt: "2026-10-30T06:00:00.000Z", error: null, run: null, summary: null },
    stage2: {
      enabled: false,
      schedule: "daily",
      acknowledgedAt: null,
      lastAt: null,
      error: null,
      run: null,
      summary: null,
      nextManualAt: null,
    },
    open: { critical: 0, high: 0, medium: 0, low: 0 },
    uptime: { enabled: false, intervalMinutes: 5, state: null, since: null, checkedAt: null },
    createdAt: "2026-10-22T10:00:00.000Z",
    passive: {
      httpsOpen: true,
      dns: { dnssec: { state: "secure" } },
    } as unknown as PassiveSnapshot,
    active: null,
    findings: [],
    ports: [],
    runs: [],
    suggestions: [],
    software: [],
    instructions: null,
    limits: { ports: 0, scheduleHours: {} },
    availability: { day: empty, week: empty, month: empty, hours: [], incidents: [] },
    ...over,
  };
}

const finding = (
  rule: string,
  severity: ExposureFindingRow["severity"],
  state: "open" | "resolved" = "open",
) =>
  ({
    id: `exf_${rule}`,
    stage: "passive",
    rule,
    subject: "www.example.com",
    severity,
    state,
    params: {},
    firstSeenAt: "2026-10-29T06:00:00.000Z",
    lastSeenAt: "2026-10-30T06:00:00.000Z",
    resolvedAt: null,
  }) satisfies ExposureFindingRow;

const states = (d: ExposureDetail) => Object.fromEntries(websiteReport(d).map((r) => [r.area, r.state.kind]));

describe("the report of a website", () => {
  it("lists every area in a fixed order, fine when nothing is open, and what is off as not checked", () => {
    const rows = websiteReport(detail());
    expect(rows.map((r) => r.area)).toEqual([...REPORT_AREAS]);
    expect(states(detail())).toMatchObject({
      availability: "notChecked",
      certificate: "ok",
      headers: "ok",
      mail: "ok",
      dnssec: "ok",
      ports: "notChecked",
    });
  });

  it("names the worst open finding of each area and ignores resolved ones", () => {
    const rows = websiteReport(
      detail({
        findings: [
          finding("httpCspMissing", "low"),
          finding("httpHstsMissing", "medium"),
          finding("tlsExpired", "critical", "resolved"),
          finding("dnsNoDmarc", "medium"),
        ],
      }),
    );
    const headers = rows.find((r) => r.area === "headers");
    expect(headers?.state).toMatchObject({ kind: "problem", severity: "medium" });
    expect(headers?.tab).toBe("http");
    expect(rows.find((r) => r.area === "certificate")?.state.kind).toBe("ok");
    expect(rows.find((r) => r.area === "mail")?.state).toMatchObject({ kind: "problem", severity: "medium" });
  });

  it("counts software judged past its end of life even before a finding names it", () => {
    const software = [
      {
        product: "nginx",
        name: "nginx",
        version: "1.22.1",
        source: "server",
        status: "endOfLife",
        cycle: "1.22",
        eol: "2023-04-11",
        latest: "1.22.1",
      },
      {
        product: "wordpress",
        name: "WordPress",
        version: "6.4.2",
        source: "generator",
        status: "outdated",
        cycle: "6.4",
        eol: null,
        latest: "6.4.7",
      },
    ] as unknown as ExposureDetail["software"];
    const row = websiteReport(detail({ software })).find((r) => r.area === "software");
    // A CMS names itself exactly, so WordPress behind its line (medium) ties with the nginx header past its end (medium).
    expect(row?.state).toMatchObject({ kind: "problem", severity: "medium" });
  });

  it("leaves out mail, DNS and DNSSEC for an address, and says when nothing was looked at yet", () => {
    const rows = websiteReport(detail({ kind: "ip", passive: null }));
    expect(rows.map((r) => r.area)).not.toContain("mail");
    expect(rows.map((r) => r.area)).not.toContain("dnssec");
    expect(rows.find((r) => r.area === "certificate")?.state).toEqual({
      kind: "notChecked",
      reason: "noRun",
    });
  });

  it("counts a website that is down as high and a slow one as medium", () => {
    const up = { enabled: true, intervalMinutes: 5, since: null, checkedAt: null };
    expect(websiteReport(detail({ uptime: { ...up, state: "down" } }))[0]?.state).toMatchObject({
      kind: "problem",
      severity: "high",
    });
    const slow = detail({
      uptime: { ...up, state: "up" },
      availability: {
        day: { percent: 100, averageMs: 4500, checks: 10 },
        week: empty,
        month: empty,
        hours: [],
        incidents: [],
      },
    });
    expect(websiteReport(slow)[0]?.state).toMatchObject({ kind: "problem", severity: "medium" });
  });

  it("has a name and a sentence for every area and state in English and German", () => {
    for (const lang of ["en", "de"] as const) {
      const report = (
        resources[lang].translation.websites as unknown as Record<
          string,
          Record<string, Record<string, string>>
        >
      ).report;
      expect(Object.keys(report?.area ?? {}).sort()).toEqual([...REPORT_AREAS].sort());
      expect(Object.keys(report?.notChecked ?? {}).sort()).toEqual(["noRun", "off", "unknown"]);
    }
  });
});
