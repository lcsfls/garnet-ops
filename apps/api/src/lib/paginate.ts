import {
  type Cursor,
  decodeCursor,
  encodeCursor,
  InvalidCursorError,
  type Page,
} from "@garnetops/core/pagination";
import { type SQL, sql } from "drizzle-orm";
import type { AnyPgColumn } from "drizzle-orm/pg-core";

/**
 * Keyset pagination over a composite sort key, all columns in the same direction.
 *
 * `keys` are the sort columns ending with the unique ID. The cursor stores the
 * key values of the boundary row joined with "\u001f" (unit separator), which
 * cannot appear in IDs, numbers or ISO timestamps.
 */
export interface KeysetSpec<Row> {
  keys: (AnyPgColumn | SQL)[];
  direction: "asc" | "desc";
  /** Reads the key values from a result row, in the same order as `keys`. */
  keyOf: (row: Row) => (string | number | Date)[];
  /** Converts stored cursor strings back to SQL parameter values, per key. */
  parse: ((value: string) => string | number | Date)[];
}

const SEP = "\u001f";

function encodeKey(values: (string | number | Date)[]): string {
  return values.map((v) => (v instanceof Date ? v.toISOString() : String(v))).join(SEP);
}

export interface KeysetQuery {
  /** Extra WHERE condition for the cursor, or undefined on the first page. */
  where: SQL | undefined;
  /** ORDER BY expressions for the query. */
  orderBy: SQL[];
  /** True when paging backwards: rows come back reversed and must be flipped. */
  backwards: boolean;
  /** Fetch one more than the page size to know whether another page exists. */
  limit: number;
}

export function keysetQuery<Row>(
  spec: KeysetSpec<Row>,
  rawCursor: string | undefined,
  pageSize: number,
): KeysetQuery {
  const cursor = decodeCursor(rawCursor);
  const backwards = cursor?.d === "b";
  // Going backwards flips the comparison and the order; results are reversed afterwards.
  const effectiveDir = backwards ? (spec.direction === "desc" ? "asc" : "desc") : spec.direction;
  const cmp = effectiveDir === "desc" ? sql.raw("<") : sql.raw(">");
  const dirSql = sql.raw(effectiveDir === "desc" ? "desc" : "asc");

  let where: SQL | undefined;
  if (cursor) {
    const parts = String(cursor.k).split(SEP);
    if (parts.length !== spec.keys.length) throw new InvalidCursorError();
    const values = parts.map((p, i) => {
      const parse = spec.parse[i];
      if (!parse) throw new InvalidCursorError();
      return parse(p);
    });
    const cols = sql.join(spec.keys, sql`, `);
    const params = sql.join(
      values.map((v) => sql`${v}`),
      sql`, `,
    );
    where = sql`(${cols}) ${cmp} (${params})`;
  }

  return {
    where,
    orderBy: spec.keys.map((k) => sql`${k} ${dirSql}`),
    backwards,
    limit: pageSize + 1,
  };
}

export function toPage<Row, Out>(
  spec: KeysetSpec<Row>,
  q: KeysetQuery,
  rows: Row[],
  total: number,
  pageSize: number,
  hadCursor: boolean,
  map: (row: Row) => Out,
): Page<Out> {
  const hasMore = rows.length > pageSize;
  const slice = rows.slice(0, pageSize);
  if (q.backwards) slice.reverse();
  const first = slice[0];
  const last = slice[slice.length - 1];
  const make = (row: Row | undefined, d: Cursor["d"]) =>
    row ? encodeCursor({ k: encodeKey(spec.keyOf(row)), id: "k", d }) : null;

  // Forward: there is a next page if we fetched more; a previous page exists if we came via a cursor.
  // Backward: there is a previous page if we fetched more; a next page always exists (we came from it).
  const next = q.backwards ? make(last, "a") : hasMore ? make(last, "a") : null;
  const prev = q.backwards ? (hasMore ? make(first, "b") : null) : hadCursor ? make(first, "b") : null;

  return { items: slice.map(map), total, pageSize, next, prev };
}

export const parseInt10 = (v: string) => {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new InvalidCursorError();
  return n;
};
export const parseDate = (v: string) => {
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new InvalidCursorError();
  return d;
};
export const parseText = (v: string) => v;

type KeyValue = string | number | Date;

/**
 * One way a list can be sorted: its key expressions (without the unique id, which is
 * always the last key) and how to read cursor values back. Nullable values must be
 * wrapped in coalesce() so every row has a comparable key.
 */
export interface SortOption {
  keys: (AnyPgColumn | SQL)[];
  parse: ((value: string) => KeyValue)[];
  /** Direction when the user has not chosen one, e.g. "desc" for scores. */
  dir: "asc" | "desc";
}

export type SortedRow = { id: string; sortKeys: KeyValue[] };

/**
 * A keyset spec for a user-chosen column and direction. The sort keys are selected as
 * one array column (`sortKeys`), so the page boundary can be encoded without knowing
 * the row type.
 */
export function sortSpec(
  option: SortOption,
  dir: "asc" | "desc" | undefined,
  id: AnyPgColumn,
): { spec: KeysetSpec<SortedRow>; select: SQL<KeyValue[]> } {
  return {
    spec: {
      keys: [...option.keys, id],
      direction: dir ?? option.dir,
      keyOf: (row) => [...row.sortKeys, row.id],
      parse: [...option.parse, parseText],
    },
    // A row constructor read back as JSON keeps each key's type (numbers, ISO times, text).
    select: sql<KeyValue[]>`json_build_array(${sql.join(option.keys, sql`, `)})`,
  };
}

export const parseNumber = (v: string) => {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new InvalidCursorError();
  return n;
};
