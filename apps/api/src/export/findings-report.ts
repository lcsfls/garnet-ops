import { type Language, type Messages, resources } from "@garnetops/i18n";
import type { Column, Report } from "./table.ts";

export const EXPORT_FORMATS = ["csv", "xlsx", "pdf", "txt"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export const CONTENT_TYPES: Record<ExportFormat, string> = {
  csv: "text/csv; charset=utf-8",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pdf: "application/pdf",
  txt: "text/plain; charset=utf-8",
};

/** A finding row as the export query returns it. */
export interface ExportRow {
  severity: string;
  vulnerabilityId: string;
  packageName: string;
  packageVersion: string;
  packageType: string;
  fixedIn: string[] | null;
  cvssScore: number | null;
  epss: number | null;
  knownExploited: boolean;
  publishedAt: Date | null;
  state: string;
  repositoryName: string;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedAt: Date | null;
  acceptedUntil: Date | null;
}

export interface ReportContext {
  language: Language;
  /** IANA zone for every date in the file; it is named in the report. */
  timeZone: string;
  /** The filters as the user set them, already in words. */
  filters: string[];
  repositoryName: string | null;
  total: number;
  now?: Date;
}

/** `{name}` placeholders of a plain message (the export texts use no plural forms). */
const fill = (template: string, params: Record<string, string | number>) =>
  template.replace(/\{(\w+)\}/g, (match, name: string) => (name in params ? String(params[name]) : match));

/** "2026-10-21" in the report's zone: sortable in every spreadsheet and the same in every language. */
function day(value: Date | null, timeZone: string): string | null {
  if (!value) return null;
  return new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(value);
}

function dayTime(value: Date, timeZone: string): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(value);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}`;
}

/** The findings list as a report: same columns in every format, labels in the user's language. */
export function findingsReport(rows: ExportRow[], context: ReportContext): Report {
  const m: Messages = resources[context.language].translation;
  const e = m.export;
  const columns: Column[] = [
    { label: e.columnSeverity, width: 9 },
    { label: m.findings.columnFinding, width: 16 },
    { label: m.findings.columnPackage, width: 20 },
    { label: e.columnVersion, width: 11 },
    { label: e.columnType, width: 9, wide: true },
    { label: m.findings.columnFixedIn, width: 12 },
    { label: m.findings.columnCvss, width: 5, kind: "number" },
    { label: m.findings.epss, width: 6, kind: "number" },
    { label: m.findings.kev, width: 9 },
    { label: m.findings.columnPublished, width: 10, wide: true },
    { label: e.columnState, width: 9 },
    { label: m.findings.columnRepository, width: 15 },
    { label: m.findings.columnFirstSeen, width: 13 },
    { label: e.columnLastSeen, width: 13, wide: true },
    { label: e.columnResolved, width: 10, wide: true },
    { label: e.columnAcceptedUntil, width: 10, wide: true },
  ];
  const severityName = (s: string) => (m.severity as Record<string, string>)[s] ?? s;
  const stateName = (s: string) => (m.findingState as Record<string, string>)[s] ?? s;
  const tz = context.timeZone;
  const now = context.now ?? new Date();

  return {
    title: context.repositoryName ? fill(e.titleRepository, { repository: context.repositoryName }) : e.title,
    meta: [
      fill(e.created, { when: dayTime(now, tz), zone: tz }),
      context.filters.length ? fill(e.filters, { filters: context.filters.join(", ") }) : e.noFilters,
      fill(e.count, { count: context.total }),
    ],
    columns,
    rows: rows.map((r) => [
      severityName(r.severity),
      r.vulnerabilityId,
      r.packageName,
      r.packageVersion,
      r.packageType,
      r.fixedIn?.join(", ") || null,
      r.cvssScore,
      // EPSS as a percentage with up to two decimals, e.g. 21.33.
      r.epss === null ? null : Math.round(r.epss * 10_000) / 100,
      r.knownExploited ? e.yes : e.no,
      day(r.publishedAt, tz),
      stateName(r.state),
      r.repositoryName,
      dayTime(r.firstSeenAt, tz),
      dayTime(r.lastSeenAt, tz),
      day(r.resolvedAt, tz),
      day(r.acceptedUntil, tz),
    ]),
    note:
      rows.length < context.total
        ? fill(e.truncated, { shown: rows.length, total: context.total })
        : undefined,
  };
}

/** `garnetops-findings-seeded-app-2026-10-21.csv`: safe characters only. */
export function exportFileName(
  format: ExportFormat,
  repositoryName: string | null,
  timeZone: string,
  now = new Date(),
) {
  const slug = repositoryName
    ? `-${repositoryName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 60)}`
    : "";
  return `garnetops-findings${slug}-${day(now, timeZone)}.${format}`;
}
