import { assemblePdf, clip, textAt, width, winAnsi } from "@garnetops/core/pdf";
import { type Cell, cellText, type Report } from "./table.ts";

/**
 * The findings list as a PDF: A4 landscape, a repeated header row and page numbers. The writing itself (fonts, WinAnsi
 * text, the file structure) is shared with the reports in `@garnetops/core/pdf`.
 *
 * Text is encoded as WinAnsi (Latin-1 plus typographic quotes and dashes); characters
 * outside it become "?". Cell text is cut to its column with "…".
 */

const PAGE_W = 842;
const PAGE_H = 595;
const MARGIN = 36;
const FONT_SIZE = 7.5;
const ROW_H = 12;
const CELL_PAD = 4;

export function toPdf(report: Report): Buffer {
  const columns = report.columns.map((c, i) => ({ ...c, index: i })).filter((c) => !c.wide);
  const usable = PAGE_W - 2 * MARGIN;
  const totalWeight = columns.reduce((sum, c) => sum + c.width, 0);
  let x = MARGIN;
  const layout = columns.map((c) => {
    const w = (c.width / totalWeight) * usable;
    const placed = { ...c, x, w };
    x += w;
    return placed;
  });

  const headerTop = PAGE_H - MARGIN - 18 - report.meta.length * 11 - 8;
  const firstRowsPerPage = Math.floor((headerTop - ROW_H - MARGIN - 14) / ROW_H);
  const otherRowsPerPage = Math.floor((PAGE_H - 2 * MARGIN - ROW_H - 14) / ROW_H);

  const pages: Cell[][][] = [];
  let rest = report.rows;
  pages.push(rest.slice(0, firstRowsPerPage));
  rest = rest.slice(firstRowsPerPage);
  while (rest.length > 0) {
    pages.push(rest.slice(0, otherRowsPerPage));
    rest = rest.slice(otherRowsPerPage);
  }

  const streams = pages.map((rows, p) => {
    const ops: string[] = [];
    let y = PAGE_H - MARGIN;
    if (p === 0) {
      ops.push(textAt(MARGIN, y - 14, clip(report.title, usable, 14, true), "F2", 14));
      y -= 18;
      for (const line of report.meta) {
        y -= 11;
        ops.push("0.35 0.33 0.33 rg", textAt(MARGIN, y, clip(line, usable, 8.5), "F1", 8.5), "0 0 0 rg");
      }
      y -= 8;
    }
    // Header row on a light band.
    ops.push(`0.94 0.93 0.93 rg ${MARGIN} ${(y - ROW_H).toFixed(2)} ${usable} ${ROW_H} re f 0 0 0 rg`);
    for (const c of layout) {
      const label = clip(c.label, c.w - 2 * CELL_PAD, FONT_SIZE, true);
      const lx = c.kind === "number" ? c.x + c.w - CELL_PAD - width(label, FONT_SIZE, true) : c.x + CELL_PAD;
      ops.push(textAt(lx, y - ROW_H + 3.5, label, "F2", FONT_SIZE));
    }
    y -= ROW_H;
    for (const row of rows) {
      for (const c of layout) {
        const text = clip(cellText(row[c.index] ?? null), c.w - 2 * CELL_PAD, FONT_SIZE);
        const tx = c.kind === "number" ? c.x + c.w - CELL_PAD - width(text, FONT_SIZE) : c.x + CELL_PAD;
        ops.push(textAt(tx, y - ROW_H + 3.5, text, "F1", FONT_SIZE));
      }
      y -= ROW_H;
      ops.push(`0.85 0.84 0.84 RG 0.4 w ${MARGIN} ${y.toFixed(2)} m ${PAGE_W - MARGIN} ${y.toFixed(2)} l S`);
    }
    if (p === pages.length - 1 && report.note) {
      ops.push(textAt(MARGIN, y - 14, clip(report.note, usable, 8.5), "F1", 8.5));
    }
    const footer = winAnsi(`${p + 1} / ${pages.length}`);
    ops.push(
      "0.35 0.33 0.33 rg",
      textAt(MARGIN, MARGIN - 16, "GarnetOps", "F1", 8),
      textAt(PAGE_W - MARGIN - width(footer, 8), MARGIN - 16, footer, "F1", 8),
    );
    return ops.join("\n");
  });

  return assemblePdf(streams, report.title, { width: PAGE_W, height: PAGE_H });
}
