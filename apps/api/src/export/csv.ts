import { type Cell, cellText, neutralizeFormula, type Report } from "./table.ts";

function field(cell: Cell): string {
  const text = typeof cell === "number" ? String(cell) : neutralizeFormula(cellText(cell));
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * RFC 4180 CSV in UTF-8 with a byte order mark, so spreadsheet programs detect the
 * encoding. Only the rows: title and filters are in the file name and the other formats.
 */
export function toCsv(report: Report): Buffer {
  const lines = [report.columns.map((c) => field(c.label)), ...report.rows.map((row) => row.map(field))];
  return Buffer.from(`﻿${lines.map((l) => l.join(",")).join("\r\n")}\r\n`, "utf8");
}
