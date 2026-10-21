import { inflateRawSync, inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { toCsv } from "./csv.ts";
import { type ExportRow, exportFileName, findingsReport } from "./findings-report.ts";
import { toPdf } from "./pdf.ts";
import type { Report } from "./table.ts";
import { toText } from "./txt.ts";
import { toXlsx } from "./xlsx.ts";

/** Scanned data is hostile: a package name that is a formula, quotes, a newline, a control character. */
const HOSTILE = '=HYPERLINK("http://evil.test","x")';

const report: Report = {
  title: "Findings",
  meta: ["Created 2026-10-21 12:00 (Europe/Berlin)"],
  columns: [
    { label: "Package", width: 20 },
    { label: "Note", width: 20, wide: true },
    { label: "CVSS", width: 5, kind: "number" },
  ],
  rows: [
    [HOSTILE, 'say "hi",\nbye', 9.8],
    ["lodash", "Ünïcödé ✓ \u0007bell", null],
    ["-1+2", "@sum", 5],
  ],
};

/** Reads the entries of a ZIP file (deflated or stored), as our writer produces them. */
function unzip(file: Buffer): Map<string, string> {
  const entries = new Map<string, string>();
  let offset = 0;
  while (file.readUInt32LE(offset) === 0x04034b50) {
    const method = file.readUInt16LE(offset + 8);
    const size = file.readUInt32LE(offset + 18);
    const nameLength = file.readUInt16LE(offset + 26);
    const extra = file.readUInt16LE(offset + 28);
    const name = file.toString("utf8", offset + 30, offset + 30 + nameLength);
    const start = offset + 30 + nameLength + extra;
    const data = file.subarray(start, start + size);
    entries.set(name, (method === 8 ? inflateRawSync(data) : data).toString("utf8"));
    offset = start + size;
  }
  return entries;
}

describe("CSV", () => {
  it("quotes, keeps UTF-8 and never lets a cell become a formula", () => {
    const text = toCsv(report).toString("utf8");
    expect(text.startsWith("﻿Package,Note,CVSS\r\n")).toBe(true);
    expect(text).toContain(`"'=HYPERLINK(""http://evil.test"",""x"")"`);
    expect(text).toContain('"say ""hi"",\nbye",9.8');
    expect(text).toContain("'-1+2,'@sum,5");
    expect(text).toContain("Ünïcödé ✓");
  });
});

describe("text", () => {
  it("aligns columns and removes control characters", () => {
    const text = toText(report).toString("utf8");
    const lines = text.split("\n");
    expect(lines[0]).toBe("Findings");
    expect(text).not.toContain("\u0007");
    expect(text).not.toMatch(/bye\n/);
    // Numbers are right-aligned under their header.
    const header = lines.find((l) => l.startsWith("Package")) ?? "";
    const row = lines.find((l) => l.startsWith("-1+2")) ?? "";
    expect(header.length).toBe(row.length);
  });
});

describe("XLSX", () => {
  it("is a valid package with inline strings only, never formulas", () => {
    const entries = unzip(toXlsx(report));
    expect([...entries.keys()]).toEqual(
      expect.arrayContaining([
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/styles.xml",
        "xl/worksheets/sheet1.xml",
      ]),
    );
    const sheet = entries.get("xl/worksheets/sheet1.xml") ?? "";
    expect(sheet).not.toContain("<f>");
    expect(sheet).toContain(
      't="inlineStr"><is><t xml:space="preserve">=HYPERLINK(&quot;http://evil.test&quot;',
    );
    expect(sheet).toContain("<v>9.8</v>");
    expect(sheet).not.toContain("\u0007");
    expect(sheet).toContain('<autoFilter ref="A1:C4"/>');
  });
});

describe("PDF", () => {
  it("has a correct cross-reference table, one page per page of rows and no wide columns", () => {
    const many: Report = { ...report, rows: Array.from({ length: 120 }, (_, i) => [`pkg-${i}`, "x", i]) };
    const file = toPdf(many);
    const text = file.toString("latin1");
    expect(text.startsWith("%PDF-1.4")).toBe(true);
    expect(text.trimEnd().endsWith("%%EOF")).toBe(true);
    const pages = Number(/\/Count (\d+)/.exec(text)?.[1]);
    expect(pages).toBeGreaterThan(1);
    // Every xref offset points at its object.
    const xrefAt = Number(/startxref\n(\d+)/.exec(text)?.[1]);
    const offsets = text
      .slice(xrefAt)
      .split("\n")
      .filter((l) => / 00000 n $/.test(l))
      .map((l) => Number(l.slice(0, 10)));
    offsets.forEach((offset, i) => {
      expect(text.slice(offset, offset + 12)).toMatch(new RegExp(`^${i + 1} 0 obj`));
    });
    // Page content: the header row repeats, the wide column is left out.
    const streams = [...text.matchAll(/stream\n([\s\S]*?)\nendstream/g)].map((m) =>
      inflateSync(Buffer.from(m[1] ?? "", "latin1")).toString("latin1"),
    );
    expect(streams).toHaveLength(pages);
    for (const stream of streams) expect(stream).toContain("(Package)");
    expect(streams.join("")).not.toContain("(Note)");
  });

  it("escapes text and keeps Latin-1 characters", () => {
    const file = toPdf({ ...report, rows: [["a(b)\\c", "", 1]], title: "Größe (Test)" });
    const content = file.toString("latin1");
    expect(content).toContain("/Title (Gr\xF6\xDFe \\(Test\\))");
    const stream = /stream\n([\s\S]*?)\nendstream/.exec(content)?.[1] ?? "";
    expect(inflateSync(Buffer.from(stream, "latin1")).toString("latin1")).toContain("(a\\(b\\)\\\\c)");
  });
});

describe("findings report", () => {
  const row: ExportRow = {
    severity: "critical",
    vulnerabilityId: "CVE-2099-0001",
    packageName: "pkg",
    packageVersion: "1.0.0",
    packageType: "npm",
    fixedIn: ["1.0.1", "2.0.0"],
    cvssScore: 9.8,
    epss: 0.21334,
    knownExploited: true,
    publishedAt: new Date("2021-02-15T00:00:00Z"),
    state: "open",
    repositoryName: "seeded-app",
    // 23:30 UTC is already the next day in Berlin.
    firstSeenAt: new Date("2026-10-20T23:30:00Z"),
    lastSeenAt: new Date("2026-10-21T08:00:00Z"),
    resolvedAt: null,
    acceptedUntil: null,
  };

  it("labels columns in the chosen language and dates in the chosen zone", () => {
    const de = findingsReport([row], {
      language: "de",
      timeZone: "Europe/Berlin",
      filters: ["Schweregrad Kritisch"],
      repositoryName: "seeded-app",
      total: 1,
      now: new Date("2026-10-21T10:00:00Z"),
    });
    expect(de.title).toBe("Findings: seeded-app");
    expect(de.columns[0]?.label).toBe("Schweregrad");
    expect(de.meta).toContain("Erstellt 2026-10-21 12:00 (Europe/Berlin)");
    expect(de.rows[0]?.slice(0, 2)).toEqual(["Kritisch", "CVE-2099-0001"]);
    expect(de.rows[0]).toContain("2026-10-21 01:30");
    expect(de.rows[0]).toContain(21.33);
    expect(de.rows[0]).toContain("1.0.1, 2.0.0");
    expect(de.note).toBeUndefined();
  });

  it("says when the file does not hold every match", () => {
    const en = findingsReport([row], {
      language: "en",
      timeZone: "UTC",
      filters: [],
      repositoryName: null,
      total: 7,
    });
    expect(en.note).toBe("1 of 7 findings. Download CSV or Excel for the complete list.");
    expect(en.meta).toContain("No filters: all findings");
  });

  it("builds a safe file name", () => {
    const now = new Date("2026-10-21T10:00:00Z");
    expect(exportFileName("xlsx", 'Team "App" / ÜI', "UTC", now)).toBe(
      "garnetops-findings-team-app-i-2026-10-21.xlsx",
    );
    expect(exportFileName("pdf", null, "UTC", now)).toBe("garnetops-findings-2026-10-21.pdf");
  });
});
