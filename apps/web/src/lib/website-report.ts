import type { ExposureRule, ExposureSeverity } from "@garnetops/core/exposure";
import { softwareSeverity } from "@garnetops/core/software";
import { UPTIME_SLOW_MS } from "@garnetops/core/uptime";
import type { WebsiteTab } from "./search.ts";
import { type ExposureDetail, type ExposureFindingRow, SEVERITY_ORDER } from "./websites.ts";

/**
 * The report of one website: every area that is checked, in one list, with a plain state each. It adds nothing new: it reads the
 * open findings, the snapshots and the availability that the other tabs show in detail.
 */
export const REPORT_AREAS = [
  "availability",
  "certificate",
  "https",
  "headers",
  "software",
  "mail",
  "dns",
  "dnssec",
  "ports",
] as const;
export type ReportArea = (typeof REPORT_AREAS)[number];

/** Which area each rule belongs to. A Record, so a new rule cannot be forgotten here. */
export const RULE_AREA: Record<ExposureRule, ReportArea> = {
  tlsExpired: "certificate",
  tlsExpiring: "certificate",
  tlsUntrusted: "certificate",
  tlsNameMismatch: "certificate",
  tlsWeakKey: "certificate",
  tlsLegacyProtocol: "certificate",
  httpNoHttps: "https",
  httpNoRedirectToHttps: "https",
  httpHstsMissing: "headers",
  httpHstsWeak: "headers",
  httpCspMissing: "headers",
  httpNosniffMissing: "headers",
  httpFramingMissing: "headers",
  httpReferrerPolicyMissing: "headers",
  httpPermissionsPolicyMissing: "headers",
  httpBannerVersion: "headers",
  softwareEndOfLife: "software",
  softwareOutdated: "software",
  dnsNoSpf: "mail",
  dnsSpfMultiple: "mail",
  dnsSpfPermissive: "mail",
  dnsNoDmarc: "mail",
  dnsDmarcNone: "mail",
  dnsNoCaa: "dns",
  dnsDanglingCname: "dns",
  dnsNonPublicAddress: "dns",
  dnssecMissing: "dnssec",
  dnssecNotDelegated: "dnssec",
  dnssecBroken: "dnssec",
  dnssecExpiring: "dnssec",
  dnssecWeakAlgorithm: "dnssec",
  dnssecSha1Digest: "dnssec",
  portExposed: "ports",
};

/** The tab that shows the details of an area. */
export const AREA_TAB: Record<ReportArea, WebsiteTab> = {
  availability: "availability",
  certificate: "tls",
  https: "http",
  headers: "http",
  software: "http",
  mail: "dns",
  dns: "dns",
  dnssec: "dns",
  ports: "ports",
};

export type ReportState =
  /** Open findings; `severity` is the worst of them. */
  | {
      kind: "problem";
      severity: ExposureSeverity;
      findings: ExposureFindingRow[];
      /** Software judged past its end of life or behind its line, when no finding names it (yet). */
      software?: { name: string; version: string; status: "endOfLife" | "outdated" };
    }
  /** Checked, nothing open. */
  | { kind: "ok" }
  /** Not looked at yet, switched off, or not answerable from the last look. Areas that do not apply (mail for an address) are left out. */
  | { kind: "notChecked"; reason: "noRun" | "off" | "unknown" };

export interface ReportRow {
  area: ReportArea;
  state: ReportState;
  tab: WebsiteTab;
}

const worst = (findings: ExposureFindingRow[]): ExposureSeverity =>
  SEVERITY_ORDER.find((s) => findings.some((f) => f.severity === s)) ?? "low";

export function websiteReport(detail: ExposureDetail): ReportRow[] {
  const open = detail.findings.filter((f) => f.state === "open");
  const byArea = new Map<ReportArea, ExposureFindingRow[]>();
  for (const f of open) {
    const area = RULE_AREA[f.rule as ExposureRule];
    if (!area) continue;
    byArea.set(area, [...(byArea.get(area) ?? []), f]);
  }
  const passive = detail.passive;
  const dnsArea = detail.kind === "domain";

  function stateOf(area: ReportArea): ReportState | null {
    const findings = byArea.get(area) ?? [];
    if (area === "availability") {
      const u = detail.uptime;
      if (!u.enabled) return { kind: "notChecked", reason: "off" };
      if (u.state === null) return { kind: "notChecked", reason: "noRun" };
      if (u.state === "down") return { kind: "problem", severity: "high", findings: [] };
      const slow = (detail.availability.day.averageMs ?? 0) > UPTIME_SLOW_MS;
      return slow ? { kind: "problem", severity: "medium", findings: [] } : { kind: "ok" };
    }
    if (area === "mail" || area === "dns" || area === "dnssec") {
      if (!dnsArea) return null;
    }
    if (findings.length > 0) return { kind: "problem", severity: worst(findings), findings };
    if (area === "software") {
      // The judgements of the last look count even before a finding names them, so the report never contradicts the HTTP tab.
      const judged = detail.software
        .map((j) => ({ j, severity: softwareSeverity(j) }))
        .filter(
          (x): x is { j: (typeof detail.software)[number]; severity: "high" | "medium" | "low" } =>
            x.severity !== null,
        )
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
      const first = judged[0];
      if (first && (first.j.status === "endOfLife" || first.j.status === "outdated")) {
        return {
          kind: "problem",
          severity: first.severity,
          findings: [],
          software: { name: first.j.name, version: first.j.version, status: first.j.status },
        };
      }
    }
    if (area === "ports") {
      if (!detail.stage2.enabled) return { kind: "notChecked", reason: "off" };
      return detail.active ? { kind: "ok" } : { kind: "notChecked", reason: "noRun" };
    }
    if (!passive) return { kind: "notChecked", reason: "noRun" };
    if (area === "dnssec" && (!passive.dns || passive.dns.dnssec === "unknown")) {
      return { kind: "notChecked", reason: "unknown" };
    }
    if ((area === "certificate" || area === "headers" || area === "software") && !passive.httpsOpen) {
      // Without HTTPS there is nothing to judge here; the HTTPS area names the problem.
      return { kind: "notChecked", reason: "unknown" };
    }
    if ((area === "mail" || area === "dns") && !passive.dns) return { kind: "notChecked", reason: "unknown" };
    return { kind: "ok" };
  }

  const rows: ReportRow[] = [];
  for (const area of REPORT_AREAS) {
    const state = stateOf(area);
    if (state) rows.push({ area, state, tab: AREA_TAB[area] });
  }
  return rows;
}
