import { deflateSync } from "node:zlib";
import { type Cell, cellText, type Report } from "./table.ts";

/**
 * A minimal PDF writer for tabular reports: A4 landscape, the standard Helvetica fonts
 * (no embedded font files), a repeated header row and page numbers. Written here
 * instead of adding a dependency; a findings list needs nothing more.
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

/** Helvetica advance widths (1/1000 em) for ASCII 32 to 126, from the standard AFM metrics. */
const HELVETICA = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
  556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
  500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469,
  556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
  278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

const WIN_ANSI_EXTRA: Record<string, number> = {
  "€": 0x80,
  "‚": 0x82,
  "„": 0x84,
  "…": 0x85,
  "‘": 0x91,
  "’": 0x92,
  "“": 0x93,
  "”": 0x94,
  "•": 0x95,
  "–": 0x96,
  "—": 0x97,
};

/** Unicode text as WinAnsi bytes (in a latin1 string); unknown characters become "?". */
function winAnsi(text: string): string {
  let out = "";
  for (const ch of text.replace(/\p{Cc}/gu, " ")) {
    const code = ch.codePointAt(0) ?? 63;
    if ((code >= 32 && code <= 126) || (code >= 160 && code <= 255)) out += ch;
    else out += String.fromCharCode(WIN_ANSI_EXTRA[ch] ?? 63);
  }
  return out;
}

function width(text: string, size: number, bold = false): number {
  let units = 0;
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    units += code >= 32 && code <= 126 ? (HELVETICA[code - 32] ?? 556) : 556;
  }
  return (units / 1000) * size * (bold ? 1.06 : 1);
}

/** The longest start of `text` that fits `max` points, with "…" when it was cut. */
function clip(text: string, max: number, size: number, bold = false): string {
  const encoded = winAnsi(text);
  if (width(encoded, size, bold) <= max) return encoded;
  let cut = encoded;
  while (cut.length > 0 && width(`${cut}\x85`, size, bold) > max) cut = cut.slice(0, -1);
  return `${cut}\x85`;
}

const literal = (text: string) => `(${text.replace(/[\\()]/g, "\\$&")})`;

function textAt(x: number, y: number, text: string, font: "F1" | "F2", size: number): string {
  return `BT /${font} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td ${literal(text)} Tj ET`;
}

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
    return deflateSync(Buffer.from(ops.join("\n"), "latin1"));
  });

  // Objects: 1 catalog, 2 page tree, 3 and 4 fonts, 5 info, then a page and its content per page.
  const objects: (string | Buffer)[] = [];
  const pageIds = pages.map((_, i) => 6 + i * 2);
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  objects[5] = `<< /Title ${literal(winAnsi(report.title))} /Producer (GarnetOps) >>`;
  streams.forEach((stream, i) => {
    const pageId = 6 + i * 2;
    objects[pageId] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${pageId + 1} 0 R >>`;
    objects[pageId + 1] = Buffer.concat([
      Buffer.from(`<< /Length ${stream.length} /Filter /FlateDecode >>\nstream\n`, "latin1"),
      stream,
      Buffer.from("\nendstream", "latin1"),
    ]);
  });

  const chunks: Buffer[] = [Buffer.from("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", "latin1")];
  let length = chunks[0]?.length ?? 0;
  const offsets: number[] = [];
  for (let id = 1; id < objects.length; id++) {
    offsets[id] = length;
    const body = objects[id] ?? "";
    const chunk = Buffer.concat([
      Buffer.from(`${id} 0 obj\n`, "latin1"),
      typeof body === "string" ? Buffer.from(body, "latin1") : body,
      Buffer.from("\nendobj\n", "latin1"),
    ]);
    chunks.push(chunk);
    length += chunk.length;
  }
  const xref = [
    "xref",
    `0 ${objects.length}`,
    "0000000000 65535 f ",
    ...offsets.slice(1).map((o) => `${String(o).padStart(10, "0")} 00000 n `),
    "trailer",
    `<< /Size ${objects.length} /Root 1 0 R /Info 5 0 R >>`,
    "startxref",
    String(length),
    "%%EOF",
    "",
  ].join("\n");
  chunks.push(Buffer.from(xref, "latin1"));
  return Buffer.concat(chunks);
}
