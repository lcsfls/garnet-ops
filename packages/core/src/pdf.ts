import { deflateSync } from "node:zlib";

/**
 * A minimal PDF writer: the standard Helvetica fonts (no embedded font files), WinAnsi text, page numbers. Written here
 * instead of adding a dependency; the findings export (a table, A4 landscape) and the reports (headings, facts, lists and
 * tables, A4 portrait) need nothing more.
 *
 * Text often comes from scanned or reported data (names, versions, ids) and is hostile input (AGENTS.md rule 1): it is
 * encoded as WinAnsi with control characters removed, characters outside WinAnsi become "?", and every string is written
 * as an escaped PDF literal. Nothing in a document is ever interpreted.
 */

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
export function winAnsi(text: string): string {
  let out = "";
  for (const ch of text.replace(/\p{Cc}/gu, " ")) {
    const code = ch.codePointAt(0) ?? 63;
    if ((code >= 32 && code <= 126) || (code >= 160 && code <= 255)) out += ch;
    else out += String.fromCharCode(WIN_ANSI_EXTRA[ch] ?? 63);
  }
  return out;
}

/** Width in points of WinAnsi text. */
export function width(text: string, size: number, bold = false): number {
  let units = 0;
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    units += code >= 32 && code <= 126 ? (HELVETICA[code - 32] ?? 556) : 556;
  }
  return (units / 1000) * size * (bold ? 1.06 : 1);
}

/** The longest start of `text` that fits `max` points, with "…" when it was cut. */
export function clip(text: string, max: number, size: number, bold = false): string {
  const encoded = winAnsi(text);
  if (width(encoded, size, bold) <= max) return encoded;
  let cut = encoded;
  while (cut.length > 0 && width(`${cut}\x85`, size, bold) > max) cut = cut.slice(0, -1);
  return `${cut}\x85`;
}

/** `text` broken into lines of at most `max` points, at spaces where possible. */
export function wrap(text: string, max: number, size: number, bold = false): string[] {
  const lines: string[] = [];
  for (const paragraph of winAnsi(text).split(/\s*\n\s*/)) {
    let line = "";
    for (const word of paragraph.split(" ").filter(Boolean)) {
      const candidate = line ? `${line} ${word}` : word;
      if (width(candidate, size, bold) <= max) {
        line = candidate;
        continue;
      }
      if (line) lines.push(line);
      // A single word longer than the line is broken by characters.
      let rest = word;
      while (width(rest, size, bold) > max) {
        let cut = rest;
        while (cut.length > 1 && width(cut, size, bold) > max) cut = cut.slice(0, -1);
        lines.push(cut);
        rest = rest.slice(cut.length);
      }
      line = rest;
    }
    lines.push(line);
  }
  return lines;
}

export const literal = (text: string) => `(${text.replace(/[\\()]/g, "\\$&")})`;

export function textAt(x: number, y: number, text: string, font: "F1" | "F2", size: number): string {
  return `BT /${font} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td ${literal(text)} Tj ET`;
}

/**
 * The file around finished page contents: catalog, page tree, the two fonts, the document information and one page per
 * content stream (already in PDF operators, latin1).
 */
export function assemblePdf(
  pageStreams: string[],
  title: string,
  size: { width: number; height: number },
): Buffer {
  const streams = pageStreams.map((ops) => deflateSync(Buffer.from(ops, "latin1")));
  // Objects: 1 catalog, 2 page tree, 3 and 4 fonts, 5 info, then a page and its content per page.
  const objects: (string | Buffer)[] = [];
  const pageIds = streams.map((_, i) => 6 + i * 2);
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${streams.length} >>`;
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  objects[5] = `<< /Title ${literal(winAnsi(title))} /Producer (GarnetOps) >>`;
  streams.forEach((stream, i) => {
    const pageId = 6 + i * 2;
    objects[pageId] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${size.width} ${size.height}] ` +
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

/* -------------------------------------------------------------------------- */
/* Documents: headings, text, facts, lists and tables on A4 portrait           */
/* -------------------------------------------------------------------------- */

/** The fixed severity colours (AGENTS.md rule 6): critical vermilion, high orange, medium amber, low grey. */
export type PdfMark = "critical" | "high" | "medium" | "low";
const MARK_RGB: Record<PdfMark, string> = {
  critical: "0.82 0.23 0.16",
  high: "0.88 0.48 0.16",
  medium: "0.85 0.65 0.18",
  low: "0.62 0.61 0.61",
};

/** A table cell: text, optionally with a small square in a severity's colour before it (the text always names it too). */
export type PdfCell = string | { text: string; mark?: PdfMark };

export type PdfBlock =
  | { kind: "heading"; text: string }
  | { kind: "text"; text: string; muted?: boolean }
  | { kind: "facts"; rows: { label: string; value: string }[] }
  | { kind: "list"; items: PdfCell[] }
  | {
      kind: "table";
      columns: { label: string; width: number; align?: "left" | "right" }[];
      rows: PdfCell[][];
      /** Shown instead of the table when it has no rows. */
      empty?: string;
    };

export interface PdfDocument {
  title: string;
  /** Short lines under the title: what, for whom, when, in which zone. */
  meta: string[];
  blocks: PdfBlock[];
  /** Left of the page number in the footer. */
  footer?: string;
}

const A4 = { width: 595, height: 842 };
const M = 48;
const BODY = 9.5;
const LINE = 13;
const SMALL = 8.5;

const cellText = (cell: PdfCell) => (typeof cell === "string" ? cell : cell.text);
const cellMark = (cell: PdfCell) => (typeof cell === "string" ? undefined : cell.mark);

/** Renders a document: A4 portrait, text wrapped to the page, tables that repeat their header on a new page. */
export function toPdfDocument(doc: PdfDocument): Buffer {
  const usable = A4.width - 2 * M;
  const bottom = M + 18;
  const pages: string[][] = [];
  let ops: string[] = [];
  let y = 0;

  const newPage = () => {
    ops = [];
    pages.push(ops);
    y = A4.height - M;
  };
  /** Starts a new page when `needed` points do not fit any more. Returns true when it did. */
  const ensure = (needed: number) => {
    if (y - needed >= bottom) return false;
    newPage();
    return true;
  };
  const muted = (op: string) => ops.push("0.35 0.33 0.33 rg", op, "0 0 0 rg");
  const mark = (x: number, baseline: number, m: PdfMark | undefined) => {
    if (!m) return 0;
    ops.push(`${MARK_RGB[m]} rg ${x.toFixed(2)} ${(baseline - 0.5).toFixed(2)} 6.5 6.5 re f 0 0 0 rg`);
    return 10;
  };

  newPage();
  for (const line of wrap(doc.title, usable, 18, true)) {
    y -= 20;
    ops.push(textAt(M, y, line, "F2", 18));
  }
  y -= 4;
  for (const meta of doc.meta) {
    for (const line of wrap(meta, usable, SMALL)) {
      y -= 11;
      muted(textAt(M, y, line, "F1", SMALL));
    }
  }
  y -= 6;
  ops.push(`0.85 0.84 0.84 RG 0.6 w ${M} ${y.toFixed(2)} m ${A4.width - M} ${y.toFixed(2)} l S`);
  y -= 4;

  for (const block of doc.blocks) {
    switch (block.kind) {
      case "heading": {
        // Keep a heading with at least two lines of what follows.
        ensure(22 + 2 * LINE);
        y -= 22;
        ops.push(textAt(M, y, clip(block.text, usable, 12.5, true), "F2", 12.5));
        y -= 4;
        break;
      }
      case "text": {
        for (const line of wrap(block.text, usable, BODY)) {
          ensure(LINE);
          y -= LINE;
          const op = textAt(M, y, line, "F1", BODY);
          if (block.muted) muted(op);
          else ops.push(op);
        }
        break;
      }
      case "facts": {
        const labelW = Math.min(170, usable * 0.36);
        for (const row of block.rows) {
          const lines = wrap(row.value, usable - labelW, BODY);
          ensure(LINE * Math.min(lines.length, 3));
          y -= LINE;
          muted(textAt(M, y, clip(row.label, labelW - 8, BODY), "F1", BODY));
          lines.forEach((line, i) => {
            if (i > 0) {
              ensure(LINE);
              y -= LINE;
            }
            ops.push(textAt(M + labelW, y, line, "F1", BODY));
          });
        }
        break;
      }
      case "list": {
        for (const item of block.items) {
          const indent = 12 + (cellMark(item) ? 10 : 0);
          const lines = wrap(cellText(item), usable - indent, BODY);
          lines.forEach((line, i) => {
            ensure(LINE);
            y -= LINE;
            if (i === 0) {
              ops.push(textAt(M, y, "\x95", "F1", BODY));
              mark(M + 12, y, cellMark(item));
            }
            ops.push(textAt(M + indent, y, line, "F1", BODY));
          });
        }
        break;
      }
      case "table": {
        if (block.rows.length === 0) {
          if (block.empty) {
            for (const line of wrap(block.empty, usable, BODY)) {
              ensure(LINE);
              y -= LINE;
              muted(textAt(M, y, line, "F1", BODY));
            }
          }
          break;
        }
        const total = block.columns.reduce((sum, c) => sum + c.width, 0);
        let x = M;
        const layout = block.columns.map((c) => {
          const w = (c.width / total) * usable;
          const placed = { ...c, x, w };
          x += w;
          return placed;
        });
        const ROW = 14;
        const header = () => {
          ops.push(`0.94 0.93 0.93 rg ${M} ${(y - ROW).toFixed(2)} ${usable} ${ROW} re f 0 0 0 rg`);
          for (const c of layout) {
            const label = clip(c.label, c.w - 8, SMALL, true);
            const lx = c.align === "right" ? c.x + c.w - 4 - width(label, SMALL, true) : c.x + 4;
            ops.push(textAt(lx, y - ROW + 4, label, "F2", SMALL));
          }
          y -= ROW;
        };
        ensure(ROW * 3);
        y -= 4;
        header();
        for (const row of block.rows) {
          if (ensure(ROW)) header();
          layout.forEach((c, i) => {
            const cell = row[i] ?? "";
            const room = c.w - 8 - (cellMark(cell) ? 10 : 0);
            const text = clip(cellText(cell), room, SMALL);
            if (c.align === "right") {
              ops.push(textAt(c.x + c.w - 4 - width(text, SMALL), y - ROW + 4, text, "F1", SMALL));
            } else {
              const shift = mark(c.x + 4, y - ROW + 4, cellMark(cell));
              ops.push(textAt(c.x + 4 + shift, y - ROW + 4, text, "F1", SMALL));
            }
          });
          y -= ROW;
          ops.push(`0.85 0.84 0.84 RG 0.4 w ${M} ${y.toFixed(2)} m ${A4.width - M} ${y.toFixed(2)} l S`);
        }
        break;
      }
    }
  }

  const footer = winAnsi(doc.footer ?? "GarnetOps");
  const streams = pages.map((page, p) => {
    const number = `${p + 1} / ${pages.length}`;
    page.push(
      "0.35 0.33 0.33 rg",
      textAt(M, M - 16, clip(footer, usable - 60, 8), "F1", 8),
      textAt(A4.width - M - width(number, 8), M - 16, number, "F1", 8),
    );
    return page.join("\n");
  });
  return assemblePdf(streams, doc.title, A4);
}
