import { decodeCursor, encodeCursor, InvalidCursorError, type Page } from "@garnetops/core/pagination";

/**
 * Keyset pagination over a list that is already in memory (a few hundred rows at most, for
 * example the aggregated source addresses of one window). Same envelope and same cursor semantics
 * as the SQL helper in paginate.ts: a cursor names the sort value and id of the boundary row, so
 * the page does not move when rows come and go, and a damaged cursor is refused.
 *
 * `key` returns the sort value (numbers compare as numbers, everything else as text); ties are
 * broken by `id`.
 */
export function pageInMemory<T>(
  rows: readonly T[],
  options: {
    id: (row: T) => string;
    key: (row: T) => string | number;
    numeric: boolean;
    dir: "asc" | "desc";
    cursor: string | undefined;
    pageSize: number;
  },
): Page<T> {
  const sign = options.dir === "asc" ? 1 : -1;
  const compareKeys = (a: string | number, b: string | number) =>
    options.numeric ? Number(a) - Number(b) : String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
  const compare = (a: T, b: T) =>
    sign * compareKeys(options.key(a), options.key(b)) ||
    sign * (options.id(a) < options.id(b) ? -1 : options.id(a) > options.id(b) ? 1 : 0);
  const sorted = [...rows].sort(compare);

  const cursor = decodeCursor(options.cursor);
  let start = 0;
  let end = sorted.length;
  if (cursor) {
    const boundaryKey: string | number = options.numeric ? Number(cursor.k) : String(cursor.k);
    if (options.numeric && !Number.isFinite(boundaryKey as number)) throw new InvalidCursorError();
    // Position of the boundary: the number of rows that sort at or before it.
    const before = (row: T) =>
      sign * compareKeys(options.key(row), boundaryKey) ||
      sign * (options.id(row) < cursor.id ? -1 : options.id(row) > cursor.id ? 1 : 0);
    if (cursor.d === "a") {
      start = sorted.findIndex((row) => before(row) > 0);
      if (start === -1) start = sorted.length;
      end = Math.min(sorted.length, start + options.pageSize);
    } else {
      end = sorted.findIndex((row) => before(row) >= 0);
      if (end === -1) end = sorted.length;
      start = Math.max(0, end - options.pageSize);
    }
  } else {
    end = Math.min(sorted.length, options.pageSize);
  }
  const items = sorted.slice(start, end);
  const first = items[0];
  const last = items[items.length - 1];
  const make = (row: T | undefined, d: "a" | "b") =>
    row ? encodeCursor({ k: String(options.key(row)), id: options.id(row), d }) : null;
  return {
    items,
    total: rows.length,
    pageSize: options.pageSize,
    next: end < sorted.length ? make(last, "a") : null,
    prev: start > 0 ? make(first, "b") : null,
  };
}
