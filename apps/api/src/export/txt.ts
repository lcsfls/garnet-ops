import { cellText, type Report } from "./table.ts";

/** Longest a column gets in the text file; longer values are cut with "…". */
const MAX_WIDTH = 48;

/** Control characters from scanned data would break the layout (or a terminal); they become spaces. */
const clean = (text: string) => text.replace(/\p{Cc}/gu, " ");

function clip(text: string, width: number): string {
  const chars = [...text];
  return chars.length > width ? `${chars.slice(0, width - 1).join("")}…` : text;
}

/** A plain-text report with aligned columns, readable in any editor or terminal. */
export function toText(report: Report): Buffer {
  const rows = report.rows.map((row) => row.map((cell) => clean(cellText(cell))));
  const widths = report.columns.map((column, i) =>
    Math.min(MAX_WIDTH, Math.max([...column.label].length, ...rows.map((row) => [...(row[i] ?? "")].length))),
  );
  const line = (cells: string[]) =>
    cells
      .map((cell, i) => {
        const width = widths[i] ?? 0;
        const text = clip(cell, width);
        const pad = " ".repeat(Math.max(0, width - [...text].length));
        return report.columns[i]?.kind === "number" ? pad + text : text + pad;
      })
      .join("  ")
      .trimEnd();
  const out = [
    report.title,
    ...report.meta,
    "",
    line(report.columns.map((c) => c.label)),
    widths.map((w) => "-".repeat(w)).join("  "),
    ...rows.map(line),
  ];
  if (report.note) out.push("", report.note);
  return Buffer.from(`${out.join("\n")}\n`, "utf8");
}
