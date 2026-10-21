/**
 * A report as plain data, written by each export format (CSV, XLSX, PDF, text).
 *
 * Cell text often comes from scanned data (package names, versions, CVE ids) and is
 * hostile input (AGENTS.md rule 1): every writer escapes it for its format, and
 * spreadsheet formats never let it become a formula.
 */
export interface Column {
  label: string;
  /** Numbers are written as numbers in spreadsheets and right-aligned elsewhere. */
  kind?: "text" | "number";
  /** Relative width in the PDF, in characters of an average text line. */
  width: number;
  /** Left out of the PDF, which has room for fewer columns than a spreadsheet. */
  wide?: boolean;
}

export type Cell = string | number | null;

export interface Report {
  title: string;
  /** Lines under the title: filters, time zone, when it was made. */
  meta: string[];
  columns: Column[];
  rows: Cell[][];
  /** Shown after the rows when not every matching row is in the file. */
  note?: string;
}

/** A cell as text, the same in every format. */
export function cellText(cell: Cell): string {
  if (cell === null) return "";
  return typeof cell === "number" ? String(cell) : cell;
}

/**
 * Text that a spreadsheet would read as a formula (=, +, -, @, tab, carriage return)
 * gets a leading apostrophe, the usual defence against CSV injection (OWASP).
 */
export function neutralizeFormula(text: string): string {
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}
