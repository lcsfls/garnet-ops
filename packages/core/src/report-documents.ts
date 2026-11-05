/**
 * Reports as PDF and as the text of the report mail (ADR 0047). The words come from the reader's language (`reports` and
 * `severity` of packages/i18n, passed in so this package stays free of it); dates are written in the reader's zone.
 *
 * Every value from the database (names, versions, ids) is written as text by the PDF writer, which removes control
 * characters and escapes everything. The organisation report and the mail carry names, counts and dates only, never
 * vulnerability ids, package names, paths or code (ADR 0010): they may leave the network by mail.
 */
import { type PdfBlock, type PdfCell, type PdfDocument, type PdfMark, toPdfDocument } from "./pdf.ts";
import {
  type Freshness,
  type HostReport,
  type NextStep,
  type NextStepCode,
  type OrganizationReport,
  REPORT_SEVERITIES,
  type ReportFindingRow,
  type ReportFrequency,
  type ReportSeverity,
  type RepositoryReport,
  type SeverityCounts,
  totalOf,
  type VulnDbState,
  type WebsiteOverviewRow,
} from "./reports.ts";

type Texts<K extends string> = Record<K, string>;

/** The words a report needs: `resources[language].translation` of packages/i18n fits this shape. */
export interface ReportMessages {
  severity: Texts<ReportSeverity>;
  reports: Texts<
    | "created"
    | "visibility"
    | "never"
    | "none"
    | "notChecked"
    | "andMore"
    | "yes"
    | "no"
    | "columnSeverity"
    | "columnOpen"
    | "columnNew"
    | "columnFixed"
    | "columnWithFix"
    | "columnName"
    | "columnVulnerability"
    | "columnPackage"
    | "columnVersion"
    | "columnFixedIn"
    | "columnExploited"
    | "columnWhere"
    | "columnTotal"
    | "vulnDbValue"
    | "vulnDbUnknown"
    | "severityLine"
    | "noneOpen"
    | "nextTitle"
    | "worstTitle"
  > & {
    freshness: Texts<Freshness>;
    next: Texts<NextStepCode>;
    repository: Texts<
      | "title"
      | "grade"
      | "gradeStale"
      | "gate"
      | "lastScan"
      | "lastSuccessfulScan"
      | "scanValue"
      | "vulnDb"
      | "open"
      | "knownExploited"
      | "accepted"
      | "acceptedValue"
      | "earlyWarnings"
      | "branch"
      | "defaultBranch"
      | "inactive"
    > & {
      gateResult: Texts<"passed" | "notes" | "blocked" | "none">;
      scanState: Texts<"queued" | "running" | "succeeded" | "failed">;
    };
    host: Texts<
      | "title"
      | "lastReport"
      | "notReporting"
      | "agent"
      | "os"
      | "kernel"
      | "kernelValue"
      | "kernelNotChecked"
      | "packages"
      | "packagesValue"
      | "packagesNone"
      | "images"
      | "imagesValue"
      | "vulnDb"
      | "earlyWarnings"
      | "bySource"
      | "sourceKernel"
      | "sourcePackages"
      | "sourceImages"
      | "whereKernel"
      | "wherePackages"
    >;
    organization: Texts<
      | "title"
      | "periodValue"
      | "summary"
      | "openNow"
      | "newInPeriod"
      | "fixedInPeriod"
      | "trend"
      | "topRepositories"
      | "topHosts"
      | "gates"
      | "gatesValue"
      | "earlyWarnings"
      | "earlyWarningsValue"
      | "earlyWarningsRepositories"
      | "accepted"
      | "acceptedValue"
      | "coverage"
      | "repositories"
      | "repositoriesValue"
      | "neverScanned"
      | "hosts"
      | "hostsValue"
      | "notReportingList"
      | "vulnDb"
      | "websites"
      | "noRepositories"
      | "noHosts"
    >;
    websites: Texts<
      | "columnWebsite"
      | "columnAvailability"
      | "columnCertificate"
      | "columnWorst"
      | "columnSoftware"
      | "columnVerification"
      | "columnChecked"
      | "up"
      | "down"
      | "off"
      | "noLook"
      | "certificateDays"
      | "certificateEnded"
      | "certificateNone"
      | "worstNone"
      | "softwareFine"
      | "softwareBehind"
      | "softwareEndOfLife"
      | "verified"
      | "unverified"
      | "lost"
      | "checkFailed"
    >;
    mail: Texts<
      | "subjectDaily"
      | "subjectWeekly"
      | "subjectMonthly"
      | "intro"
      | "open"
      | "changes"
      | "gates"
      | "websitesDown"
      | "hostsNotReporting"
      | "attached"
      | "link"
      | "scope"
      | "footer"
    >;
  };
}

export interface RenderContext {
  /** "en" or "de": the language of the words and of dates. */
  language: string;
  /** IANA zone every date is written in; it is named in the report. */
  timeZone: string;
}

type Values = Record<string, string | number>;

/** The index of the brace that closes the one at `open`. */
function closing(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

/**
 * Fills a message in a single pass: `{name}` placeholders and the ICU plural form the web app uses too
 * (`{count, plural, =0 {…} one {# item} other {# items}}`, with the language's plural rules). Only the message itself is ever
 * parsed; inserted values are text and are never read as a placeholder again.
 */
export function format(template: string, values: Values, language = "en"): string {
  let out = "";
  let i = 0;
  while (i < template.length) {
    const end = template[i] === "{" ? closing(template, i) : -1;
    if (end < 0) {
      out += template[i];
      i++;
      continue;
    }
    const inner = template.slice(i + 1, end);
    const plural = /^\s*(\w+)\s*,\s*plural\s*,([\s\S]*)$/.exec(inner);
    if (plural) {
      out += pluralForm(plural[2] ?? "", Number(values[plural[1] ?? ""] ?? 0), values, language);
    } else {
      const key = inner.trim();
      out += key in values ? String(values[key]) : `{${inner}}`;
    }
    i = end + 1;
  }
  return out;
}

function pluralForm(body: string, n: number, values: Values, language: string): string {
  const forms = new Map<string, string>();
  let i = 0;
  while (i < body.length) {
    const selector = /^\s*(=\d+|\w+)\s*/.exec(body.slice(i));
    if (!selector) break;
    const open = i + selector[0].length;
    if (body[open] !== "{") break;
    const end = closing(body, open);
    if (end < 0) break;
    forms.set(selector[1] ?? "", body.slice(open + 1, end));
    i = end + 1;
  }
  const chosen =
    forms.get(`=${n}`) ?? forms.get(new Intl.PluralRules(language).select(n)) ?? forms.get("other") ?? "";
  // "#" is the number; the branch is a message of its own.
  return format(chosen.replace(/#/g, String(n)), values, language);
}

/** A `format` for one language. */
const formatter = (language: string) => (template: string, values: Values) =>
  format(template, values, language);

/** A calendar date "YYYY-MM-DD" in the reader's words ("21 Oct 2026"). */
export function formatDay(date: string, language: string): string {
  return new Intl.DateTimeFormat(language, { dateStyle: "medium", timeZone: "UTC" }).format(
    new Date(`${date}T12:00:00Z`),
  );
}

/** An instant in the reader's zone and words. */
export function formatInstant(at: string | Date, ctx: RenderContext): string {
  return new Intl.DateTimeFormat(ctx.language, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: ctx.timeZone,
  }).format(new Date(at));
}

const markOf = (s: ReportSeverity): PdfMark => s;
const severityCell = (m: ReportMessages, s: ReportSeverity): PdfCell => ({
  text: m.severity[s],
  mark: markOf(s),
});

export function severityLine(m: ReportMessages, counts: SeverityCounts, language: string): string {
  const fill = formatter(language);
  return fill(m.reports.severityLine, { total: totalOf(counts), ...counts });
}

export function nextStepText(m: ReportMessages, s: NextStep, language: string): string {
  const fill = formatter(language);
  return fill(m.reports.next[s.code], { count: s.count ?? 0 });
}

function vulnDbText(m: ReportMessages, db: VulnDbState, ctx: RenderContext): string {
  const fill = formatter(ctx.language);
  if (!db.builtAt) return m.reports.vulnDbUnknown;
  return fill(m.reports.vulnDbValue, {
    date: formatInstant(db.builtAt, ctx),
    freshness: m.reports.freshness[db.freshness],
  });
}

function createdLine(m: ReportMessages, generatedAt: string, ctx: RenderContext): string {
  const fill = formatter(ctx.language);
  return fill(m.reports.created, { when: formatInstant(generatedAt, ctx), zone: ctx.timeZone });
}

function nextBlocks(m: ReportMessages, steps: NextStep[], language: string): PdfBlock[] {
  return [
    { kind: "heading", text: m.reports.nextTitle },
    { kind: "list", items: steps.map((s) => nextStepText(m, s, language)) },
  ];
}

function findingsTable(m: ReportMessages, rows: ReportFindingRow[], withWhere: boolean): PdfBlock {
  const r = m.reports;
  return {
    kind: "table",
    columns: [
      { label: r.columnSeverity, width: 10 },
      { label: r.columnVulnerability, width: 17 },
      { label: r.columnPackage, width: withWhere ? 16 : 22 },
      { label: r.columnVersion, width: 11 },
      ...(withWhere ? [{ label: r.columnWhere, width: 16 }] : []),
      { label: r.columnFixedIn, width: 12 },
      { label: r.columnExploited, width: 11 },
    ],
    rows: rows.map((f) => [
      severityCell(m, f.severity),
      f.vulnerabilityId,
      f.packageName,
      f.packageVersion,
      ...(withWhere ? [f.where ?? ""] : []),
      f.fixedIn.join(", ") || "–",
      f.knownExploited ? r.yes : r.no,
    ]),
    empty: r.noneOpen,
  };
}

function countsTable(m: ReportMessages, columns: { label: string; counts: SeverityCounts }[]): PdfBlock {
  return {
    kind: "table",
    columns: [
      { label: m.reports.columnSeverity, width: 16 },
      ...columns.map((c) => ({ label: c.label, width: 10, align: "right" as const })),
    ],
    rows: [
      ...REPORT_SEVERITIES.map((s) => [severityCell(m, s), ...columns.map((c) => String(c.counts[s]))]),
      [m.reports.columnTotal, ...columns.map((c) => String(totalOf(c.counts)))],
    ],
  };
}

/* -------------------------------------------------------------------------- */
/* One repository                                                              */
/* -------------------------------------------------------------------------- */

export function repositoryReportDocument(
  report: RepositoryReport,
  m: ReportMessages,
  ctx: RenderContext,
): PdfDocument {
  const fill = formatter(ctx.language);
  const r = m.reports;
  const t = r.repository;
  const when = (at: string) => formatInstant(at, ctx);
  const facts = [
    {
      label: r.repository.branch,
      value: report.repository.branch ?? t.defaultBranch,
    },
    {
      label: t.grade,
      value: report.grade
        ? report.grade.stale
          ? fill(t.gradeStale, { grade: report.grade.grade })
          : report.grade.grade
        : r.notChecked,
    },
    {
      label: t.gate,
      value: report.gate
        ? fill(t.gateResult[report.gate.result], { when: when(report.gate.at) })
        : t.gateResult.none,
    },
    {
      label: t.lastScan,
      value: report.lastScan
        ? fill(t.scanState[report.lastScan.state], { when: when(report.lastScan.at) })
        : r.never,
    },
    {
      label: t.lastSuccessfulScan,
      value: report.lastSuccessfulScan
        ? fill(t.scanValue, {
            when: when(report.lastSuccessfulScan.at),
            commit: report.lastSuccessfulScan.commit?.slice(0, 12) ?? "–",
            packages: report.lastSuccessfulScan.packages ?? "–",
          })
        : r.never,
    },
    { label: t.vulnDb, value: vulnDbText(m, report.vulnDb, ctx) },
    { label: t.open, value: severityLine(m, report.open, ctx.language) },
    { label: t.knownExploited, value: String(report.knownExploited) },
    {
      label: t.accepted,
      value: fill(t.acceptedValue, { total: report.accepted.total, expired: report.accepted.expired }),
    },
    { label: t.earlyWarnings, value: String(report.earlyWarnings.open) },
  ];
  return {
    title: fill(t.title, { name: report.repository.name }),
    meta: [
      report.repository.url,
      createdLine(m, report.generatedAt, ctx),
      ...(report.repository.inactive ? [t.inactive] : []),
    ],
    blocks: [
      { kind: "heading", text: r.organization.summary },
      { kind: "facts", rows: facts },
      { kind: "heading", text: r.organization.trend },
      countsTable(m, [
        { label: r.columnOpen, counts: report.open },
        { label: r.columnWithFix, counts: report.fixable },
      ]),
      ...nextBlocks(m, report.nextSteps, ctx.language),
      { kind: "heading", text: r.worstTitle },
      findingsTable(m, report.top, false),
    ],
  };
}

/* -------------------------------------------------------------------------- */
/* One host                                                                    */
/* -------------------------------------------------------------------------- */

export function hostReportDocument(report: HostReport, m: ReportMessages, ctx: RenderContext): PdfDocument {
  const fill = formatter(ctx.language);
  const r = m.reports;
  const t = r.host;
  const when = (at: string) => formatInstant(at, ctx);
  const lastReport = report.lastReportAt
    ? report.reporting
      ? when(report.lastReportAt)
      : fill(t.notReporting, { when: when(report.lastReportAt) })
    : r.never;
  const release = report.kernel.release ?? "–";
  const facts = [
    { label: t.lastReport, value: lastReport },
    {
      label: t.agent,
      value: [report.host.agentVersion, report.host.runtime].filter(Boolean).join(", ") || "–",
    },
    { label: t.os, value: report.host.os ?? "–" },
    {
      label: t.kernel,
      value: report.kernel.checked
        ? fill(t.kernelValue, { release, count: totalOf(report.kernel.open) })
        : fill(t.kernelNotChecked, { release }),
    },
    {
      label: t.packages,
      value: report.packages
        ? fill(t.packagesValue, { count: report.packages.count ?? 0, open: totalOf(report.packages.open) })
        : t.packagesNone,
    },
    {
      label: t.images,
      value: fill(t.imagesValue, {
        containers: report.images.containers,
        images: report.images.images,
        serious: report.images.withSerious,
        updates: report.images.updates,
      }),
    },
    { label: t.vulnDb, value: vulnDbText(m, report.vulnDb, ctx) },
    { label: t.earlyWarnings, value: String(report.earlyWarnings.open) },
  ];
  return {
    title: fill(t.title, { name: report.host.name }),
    meta: [report.host.hostname, createdLine(m, report.generatedAt, ctx)],
    blocks: [
      { kind: "heading", text: r.organization.summary },
      { kind: "facts", rows: facts },
      { kind: "heading", text: t.bySource },
      countsTable(m, [
        { label: t.sourceKernel, counts: report.kernel.open },
        ...(report.packages ? [{ label: t.sourcePackages, counts: report.packages.open }] : []),
        { label: t.sourceImages, counts: report.images.open },
        { label: r.columnTotal, counts: report.open },
      ]),
      ...nextBlocks(m, report.nextSteps, ctx.language),
      { kind: "heading", text: r.worstTitle },
      findingsTable(
        m,
        report.top.map((f) => ({
          ...f,
          where: f.where === "kernel" ? t.whereKernel : f.where === "packages" ? t.wherePackages : f.where,
        })),
        true,
      ),
    ],
  };
}

/* -------------------------------------------------------------------------- */
/* Websites                                                                    */
/* -------------------------------------------------------------------------- */

export function websiteCells(m: ReportMessages, row: WebsiteOverviewRow, ctx: RenderContext): PdfCell[] {
  const fill = formatter(ctx.language);
  const w = m.reports.websites;
  const availability = !row.availability.enabled
    ? w.off
    : row.availability.state === "down"
      ? { text: w.down, mark: "high" as const }
      : row.availability.state === "up"
        ? w.up
        : w.noLook;
  const certificate =
    row.certificateDays === null
      ? w.certificateNone
      : row.certificateDays < 0
        ? { text: w.certificateEnded, mark: "critical" as const }
        : fill(w.certificateDays, { days: row.certificateDays });
  const worst: PdfCell = row.worst
    ? { text: `${m.severity[row.worst]} (${totalOf(row.open)})`, mark: row.worst }
    : w.worstNone;
  const software = [
    row.software.endOfLife.length > 0
      ? fill(w.softwareEndOfLife, { count: row.software.endOfLife.length })
      : null,
    row.software.outdated.length > 0 ? fill(w.softwareBehind, { count: row.software.outdated.length }) : null,
  ]
    .filter(Boolean)
    .join(", ");
  const verification = row.verified ? w.verified : row.verifyState === "lost" ? w.lost : w.unverified;
  const checked = row.checkError
    ? w.checkFailed
    : row.lastCheckedAt
      ? new Intl.DateTimeFormat(ctx.language, {
          dateStyle: "short",
          timeStyle: "short",
          timeZone: ctx.timeZone,
        }).format(new Date(row.lastCheckedAt))
      : w.noLook;
  return [row.value, availability, certificate, worst, software || w.softwareFine, verification, checked];
}

function websitesTable(m: ReportMessages, rows: WebsiteOverviewRow[], ctx: RenderContext): PdfBlock {
  const w = m.reports.websites;
  return {
    kind: "table",
    columns: [
      { label: w.columnWebsite, width: 22 },
      { label: w.columnAvailability, width: 11 },
      { label: w.columnCertificate, width: 12 },
      { label: w.columnWorst, width: 13 },
      { label: w.columnSoftware, width: 13 },
      { label: w.columnVerification, width: 12 },
      { label: w.columnChecked, width: 17 },
    ],
    rows: rows.map((row) => websiteCells(m, row, ctx)),
  };
}

/* -------------------------------------------------------------------------- */
/* The organisation                                                            */
/* -------------------------------------------------------------------------- */

const LIST_MAX = 20;

function namesList(m: ReportMessages, names: string[], total: number, language: string): PdfBlock {
  const fill = formatter(language);
  const items: PdfCell[] = names.slice(0, LIST_MAX);
  if (total > items.length) items.push(fill(m.reports.andMore, { count: total - items.length }));
  return { kind: "list", items };
}

function riskTable(
  m: ReportMessages,
  rows: { name: string; open: SeverityCounts }[],
  empty: string,
): PdfBlock {
  return {
    kind: "table",
    columns: [
      { label: m.reports.columnName, width: 40 },
      ...REPORT_SEVERITIES.map((s) => ({ label: m.severity[s], width: 10, align: "right" as const })),
    ],
    rows: rows.map((row) => [row.name, ...REPORT_SEVERITIES.map((s) => String(row.open[s]))]),
    empty,
  };
}

export function periodText(m: ReportMessages, report: OrganizationReport, language: string): string {
  const fill = formatter(language);
  return fill(m.reports.organization.periodValue, {
    from: formatDay(report.period.from, language),
    to: formatDay(report.period.to, language),
    days: report.period.days,
  });
}

export function organizationReportDocument(
  report: OrganizationReport,
  m: ReportMessages,
  ctx: RenderContext,
): PdfDocument {
  const fill = formatter(ctx.language);
  const r = m.reports;
  const t = r.organization;
  const f = report.findings;
  const summary = [
    { label: t.openNow, value: severityLine(m, f.open, ctx.language) },
    { label: t.newInPeriod, value: String(totalOf(f.opened)) },
    { label: t.fixedInPeriod, value: String(totalOf(f.fixed)) },
    { label: r.repository.knownExploited, value: String(f.knownExploited) },
    { label: t.gates, value: fill(t.gatesValue, report.gates) },
    {
      label: t.earlyWarnings,
      value:
        report.earlyWarnings.runtime === null
          ? fill(t.earlyWarningsRepositories, { repositories: report.earlyWarnings.repositories })
          : fill(t.earlyWarningsValue, {
              repositories: report.earlyWarnings.repositories,
              runtime: report.earlyWarnings.runtime,
            }),
    },
    {
      label: t.accepted,
      value: fill(t.acceptedValue, {
        total: report.accepted.total,
        expired: report.accepted.expired,
        soon: report.accepted.endingSoon,
      }),
    },
  ];
  const coverage = [
    {
      label: t.repositories,
      value: fill(t.repositoriesValue, {
        total: report.repositories.total,
        scanned: report.repositories.scanned,
        failed: report.repositories.failedScans,
      }),
    },
    ...(report.hosts
      ? [
          {
            label: t.hosts,
            value: fill(t.hostsValue, {
              total: report.hosts.total,
              notReporting: report.hosts.notReporting.length,
            }),
          },
        ]
      : []),
    { label: t.vulnDb, value: vulnDbText(m, report.vulnDb, ctx) },
  ];

  const blocks: PdfBlock[] = [
    { kind: "heading", text: t.summary },
    { kind: "facts", rows: summary },
    ...nextBlocks(m, report.nextSteps, ctx.language),
    { kind: "heading", text: t.trend },
    countsTable(m, [
      { label: r.columnOpen, counts: f.open },
      { label: r.columnNew, counts: f.opened },
      { label: r.columnFixed, counts: f.fixed },
    ]),
    { kind: "heading", text: t.topRepositories },
    riskTable(m, report.top.repositories, t.noRepositories),
  ];
  if (report.top.hosts) {
    blocks.push({ kind: "heading", text: t.topHosts }, riskTable(m, report.top.hosts, t.noHosts));
  }
  if (report.websites && report.websites.length > 0) {
    blocks.push({ kind: "heading", text: t.websites }, websitesTable(m, report.websites, ctx));
  }
  blocks.push({ kind: "heading", text: t.coverage }, { kind: "facts", rows: coverage });
  if (report.repositories.neverScannedCount > 0) {
    blocks.push(
      { kind: "text", text: t.neverScanned },
      namesList(
        m,
        report.repositories.neverScanned.map((x) => x.name),
        report.repositories.neverScannedCount,
        ctx.language,
      ),
    );
  }
  if (report.hosts && report.hosts.notReporting.length > 0) {
    blocks.push(
      { kind: "text", text: t.notReportingList },
      namesList(
        m,
        report.hosts.notReporting.map((h) =>
          h.lastReportAt ? `${h.name} (${formatInstant(h.lastReportAt, ctx)})` : `${h.name} (${r.never})`,
        ),
        report.hosts.notReporting.length,
        ctx.language,
      ),
    );
  }
  return {
    title: fill(t.title, { organization: report.organization }),
    meta: [periodText(m, report, ctx.language), createdLine(m, report.generatedAt, ctx), r.visibility],
    blocks,
  };
}

export const toReportPdf = (doc: PdfDocument): Buffer => toPdfDocument(doc);

/* -------------------------------------------------------------------------- */
/* The report mail                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The subject and the short plain-text body of a report mail: counts and a link, never names of findings or packages
 * (ADR 0010). `origin` is the installation's public address; without one the links are left out.
 */
export function reportMail(
  report: OrganizationReport,
  frequency: ReportFrequency,
  m: ReportMessages,
  ctx: RenderContext,
  options: { origin: string; attached: boolean },
): { subject: string; text: string } {
  const fill = formatter(ctx.language);
  const t = m.reports.mail;
  const from = formatDay(report.period.from, ctx.language);
  const to = formatDay(report.period.to, ctx.language);
  const month = new Intl.DateTimeFormat(ctx.language, {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${report.period.from}T12:00:00Z`));
  const organization = report.organization;
  const subject =
    frequency === "daily"
      ? fill(t.subjectDaily, { organization, date: from })
      : frequency === "weekly"
        ? fill(t.subjectWeekly, { organization, from, to })
        : fill(t.subjectMonthly, { organization, month });
  const down = report.websites?.filter((w) => w.availability.state === "down").length ?? 0;
  const lines = [
    fill(t.intro, { organization, from, to, zone: ctx.timeZone }),
    "",
    fill(t.open, { line: severityLine(m, report.findings.open, ctx.language) }),
    fill(t.changes, { opened: totalOf(report.findings.opened), fixed: totalOf(report.findings.fixed) }),
    fill(t.gates, { passed: report.gates.passed, blocked: report.gates.blocked }),
    ...(down > 0 ? [fill(t.websitesDown, { count: down })] : []),
    ...(report.hosts && report.hosts.notReporting.length > 0
      ? [fill(t.hostsNotReporting, { count: report.hosts.notReporting.length })]
      : []),
    "",
    ...report.nextSteps.slice(0, 5).map((s) => `- ${nextStepText(m, s, ctx.language)}`),
    "",
    ...(options.attached ? [t.attached] : []),
    ...(options.origin ? [fill(t.link, { link: `${options.origin}/statistics` })] : []),
    "",
    options.origin
      ? fill(t.scope, { link: `${options.origin}/account?section=notifications` })
      : m.reports.visibility,
    "",
    fill(t.footer, { organization }),
  ];
  return { subject: subject.replace(/[\r\n]+/g, " "), text: lines.join("\n") };
}
