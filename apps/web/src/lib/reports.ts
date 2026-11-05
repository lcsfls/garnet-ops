/**
 * Reports on the web side (ADR 0047): the shapes the API sends (from packages/core) and the download links. The server builds
 * every report, PDF included, with the signed-in person's visibility; the links carry the person's display zone and language,
 * so the file's dates are their own calendar days.
 */
import type { ReportSeverity, SeverityCounts } from "@garnetops/core/reports";
import { REPORT_SEVERITIES } from "@garnetops/core/reports";
import { language } from "./i18n.svelte.ts";
import { toQuery } from "./search.ts";
import { displayTimeZone } from "./time-zone.svelte.ts";

export type {
  HostReport,
  NextStep,
  OrganizationReport,
  ReportFindingRow,
  ReportFrequency,
  ReportSeverity,
  RepositoryReport,
  SeverityCounts,
  WebsiteOverviewRow,
} from "@garnetops/core/reports";
export { compareWebsites, REPORT_FREQUENCIES, REPORT_RANGES } from "@garnetops/core/reports";

/** The PDF of a report: `/reports/repositories/{id}`, `/reports/hosts/{id}` or `/reports/organization` with `days`. */
export function reportPdfHref(
  path: string,
  params: Record<string, string | number | undefined> = {},
): string {
  return `/api/v1${path}${toQuery({ ...params, format: "pdf", tz: displayTimeZone(), lang: language() })}`;
}

/** The severities that have open findings, worst first. */
export function openSeverities(counts: SeverityCounts): { severity: ReportSeverity; count: number }[] {
  return REPORT_SEVERITIES.filter((s) => counts[s] > 0).map((severity) => ({
    severity,
    count: counts[severity],
  }));
}

/** The person's report mail settings (`/me/report-mail`). */
export interface ReportMailSettings {
  frequency: import("@garnetops/core/reports").ReportFrequency | null;
  attachPdf: boolean;
  mailAvailable: boolean;
  timeZone: string;
}
