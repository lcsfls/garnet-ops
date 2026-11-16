import { SEVERITIES, SEVERITY_RANK } from "@garnetops/core";
import { type Messages, resources } from "@garnetops/i18n";
import { dayTime, fill, type ReportContext } from "./findings-report.ts";
import type { Column, Report } from "./table.ts";

/**
 * A package as the export query returns it (0.1.8). Names, versions, licences and registry messages are scanned or fetched text,
 * which every writer escapes for its format.
 */
export interface PackageExportRow {
  name: string;
  version: string;
  type: string;
  purl: string | null;
  licenses: string[] | null;
  repositoryName: string;
  openFindings: number;
  worstSeverityRank: number | null;
  grade: string | null;
  deprecation: { state: string; message: string | null } | null;
}

/** The packages list as a report: the same columns in every format, labels in the user's language. */
export function packagesReport(rows: PackageExportRow[], context: ReportContext): Report {
  const m: Messages = resources[context.language].translation;
  const e = m.export;
  const x = m.packages.export;
  const columns: Column[] = [
    { label: m.packages.columnName, width: 24 },
    { label: m.packages.columnVersion, width: 12 },
    { label: m.packages.columnType, width: 10 },
    { label: m.findings.columnRepository, width: 16 },
    { label: m.grades.column, width: 6 },
    { label: x.columnWorst, width: 9 },
    { label: m.packages.columnOpen, width: 8, kind: "number" },
    { label: m.packages.columnLicenses, width: 16, wide: true },
    { label: x.columnRegistry, width: 12 },
    { label: x.columnMessage, width: 28, wide: true },
    { label: x.columnPurl, width: 30, wide: true },
  ];
  const severityOfRank = (rank: number | null) => {
    if (rank === null) return null;
    const severity = SEVERITIES.find((s) => SEVERITY_RANK[s] === rank);
    return severity ? ((m.severity as Record<string, string>)[severity] ?? severity) : null;
  };
  const registryState = (state: string | undefined) =>
    state === "deprecated" ? m.deprecated.deprecated : state === "yanked" ? m.deprecated.yanked : null;
  const now = context.now ?? new Date();

  return {
    title: context.repositoryName ? fill(x.titleRepository, { repository: context.repositoryName }) : x.title,
    meta: [
      fill(e.created, { when: dayTime(now, context.timeZone), zone: context.timeZone }),
      context.filters.length ? fill(e.filters, { filters: context.filters.join(", ") }) : x.noFilters,
      fill(x.count, { count: context.total }),
    ],
    columns,
    rows: rows.map((r) => [
      r.name,
      r.version || null,
      r.type,
      r.repositoryName,
      r.grade,
      r.openFindings > 0 ? severityOfRank(r.worstSeverityRank) : null,
      r.openFindings,
      r.licenses?.length ? r.licenses.join(", ") : null,
      registryState(r.deprecation?.state),
      r.deprecation?.message ?? null,
      r.purl,
    ]),
    note:
      rows.length < context.total
        ? fill(x.truncated, { shown: rows.length, total: context.total })
        : undefined,
  };
}

/** A package of the affected view (0.1.9): one row over all the repositories that have it. */
export interface AffectedExportRow {
  name: string;
  version: string;
  type: string;
  repositories: number;
  repositoryList: { name: string }[];
  openFindings: number;
  worstSeverityRank: number;
  grade: string | null;
  fix: { version: string; majorUpgrade: boolean; unresolved: number } | null;
  deprecation: { state: string; message: string | null } | null;
}

/** The affected view as a report: worst first, with the version that fixes every open finding. */
export function affectedPackagesReport(rows: AffectedExportRow[], context: ReportContext): Report {
  const m: Messages = resources[context.language].translation;
  const e = m.export;
  const x = m.packages.export;
  const columns: Column[] = [
    { label: m.packages.columnName, width: 24 },
    { label: m.packages.columnVersion, width: 12 },
    { label: m.packages.columnType, width: 10, wide: true },
    { label: x.columnWorst, width: 9 },
    { label: m.packages.columnOpen, width: 8, kind: "number" },
    { label: x.columnFix, width: 14 },
    { label: x.columnRepositories, width: 8, kind: "number" },
    { label: x.columnRepositoryNames, width: 30 },
    { label: m.grades.column, width: 6, wide: true },
    { label: x.columnRegistry, width: 12, wide: true },
  ];
  const severityOfRank = (rank: number) => {
    const severity = SEVERITIES.find((s) => SEVERITY_RANK[s] === rank);
    return severity ? ((m.severity as Record<string, string>)[severity] ?? severity) : null;
  };
  const fixText = (fix: AffectedExportRow["fix"]) =>
    fix ? (fix.majorUpgrade ? fill(x.fixMajor, { version: fix.version }) : fix.version) : x.noFix;
  const now = context.now ?? new Date();
  return {
    title: context.repositoryName
      ? fill(x.titleAffectedRepository, { repository: context.repositoryName })
      : x.titleAffected,
    meta: [
      fill(e.created, { when: dayTime(now, context.timeZone), zone: context.timeZone }),
      context.filters.length ? fill(e.filters, { filters: context.filters.join(", ") }) : x.noFiltersAffected,
      fill(x.count, { count: context.total }),
    ],
    columns,
    rows: rows.map((r) => [
      r.name,
      r.version || null,
      r.type,
      severityOfRank(r.worstSeverityRank),
      r.openFindings,
      fixText(r.fix),
      r.repositories,
      r.repositoryList.map((l) => l.name).join(", ") +
        (r.repositories > r.repositoryList.length ? ", …" : ""),
      r.grade,
      r.deprecation?.state === "deprecated"
        ? m.deprecated.deprecated
        : r.deprecation?.state === "yanked"
          ? m.deprecated.yanked
          : null,
    ]),
    note:
      rows.length < context.total
        ? fill(x.truncated, { shown: rows.length, total: context.total })
        : undefined,
  };
}
