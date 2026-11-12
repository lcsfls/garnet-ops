import { isSensitiveFileRule } from "@garnetops/core/secrets";
import { type Messages, resources } from "@garnetops/i18n";
import { day, dayTime, fill, type ReportContext } from "./findings-report.ts";
import type { Column, Report } from "./table.ts";

/**
 * A secret as the export query returns it (ADR 0049). There is no value to export: GarnetOps never has it. Paths, rule ids and
 * reasons are scanned or typed text, which every writer escapes for its format.
 */
export interface SecretExportRow {
  severity: string;
  ruleId: string;
  state: "open" | "revoked" | "dismissed";
  ignored: boolean;
  repositoryName: string;
  inTree: boolean;
  treeLocations: { path: string; line: number | null }[];
  treeLocationCount: number;
  historyLocations: { path: string; line: number | null; commit?: string }[];
  historyLocationCount: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  stateAt: Date | null;
  stateReason: string | null;
}

const place = (p: { path: string; line: number | null } | undefined) =>
  p ? (p.line ? `${p.path}:${p.line}` : p.path) : null;

/** The secrets list as a report: the same columns in every format, labels in the user's language. */
export function secretsReport(rows: SecretExportRow[], context: ReportContext): Report {
  const m: Messages = resources[context.language].translation;
  const e = m.export;
  const x = m.secrets.export;
  const columns: Column[] = [
    { label: e.columnSeverity, width: 9 },
    { label: m.secrets.columnRule, width: 22 },
    { label: x.columnRuleId, width: 16, wide: true },
    { label: e.columnState, width: 9 },
    { label: m.secrets.columnRepository, width: 15 },
    { label: m.secrets.columnWhere, width: 28 },
    { label: x.columnInFiles, width: 7 },
    { label: x.columnPlacesInFiles, width: 7, kind: "number" },
    { label: x.columnPlacesInHistory, width: 7, kind: "number", wide: true },
    { label: m.secrets.columnFirstSeen, width: 13 },
    { label: e.columnLastSeen, width: 13, wide: true },
    { label: x.columnClosedOn, width: 10, wide: true },
    { label: x.columnReason, width: 24, wide: true },
  ];
  const severityName = (s: string) => (m.severity as Record<string, string>)[s] ?? s;
  const ruleName = (id: string) =>
    isSensitiveFileRule(id) ? ((m.secrets.fileRule as Record<string, string>)[id] ?? id) : id;
  const tz = context.timeZone;
  const now = context.now ?? new Date();

  return {
    title: context.repositoryName ? fill(x.titleRepository, { repository: context.repositoryName }) : x.title,
    meta: [
      fill(e.created, { when: dayTime(now, tz), zone: tz }),
      context.filters.length ? fill(e.filters, { filters: context.filters.join(", ") }) : x.noFilters,
      fill(x.count, { count: context.total }),
      x.noValue,
    ],
    columns,
    rows: rows.map((r) => [
      severityName(r.severity),
      ruleName(r.ruleId),
      r.ruleId,
      r.state === "open" && r.ignored ? m.secrets.state.ignored : m.secrets.state[r.state],
      r.repositoryName,
      // In the files when it is there, else where the history has it.
      place(r.treeLocations[0]) ?? place(r.historyLocations[0]),
      r.inTree ? e.yes : e.no,
      r.treeLocationCount,
      r.historyLocationCount,
      dayTime(r.firstSeenAt, tz),
      dayTime(r.lastSeenAt, tz),
      r.state === "open" ? null : day(r.stateAt, tz),
      r.state === "open" ? null : r.stateReason,
    ]),
    note:
      rows.length < context.total
        ? fill(x.truncated, { shown: rows.length, total: context.total })
        : undefined,
  };
}
