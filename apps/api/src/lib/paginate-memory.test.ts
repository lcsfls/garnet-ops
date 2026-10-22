import type { Page } from "@garnetops/core/pagination";
import { describe, expect, it } from "vitest";
import { pageInMemory } from "./paginate-memory.ts";

interface Row {
  id: string;
  n: number;
  s: string;
}
const rows: Row[] = Array.from({ length: 23 }, (_, i) => ({
  id: `r${String(i).padStart(2, "0")}`,
  n: i % 5,
  s: `x${i % 4}`,
}));

const page = (cursor: string | undefined, dir: "asc" | "desc" = "desc", numeric = true, list: Row[] = rows) =>
  pageInMemory(list, {
    id: (r) => r.id,
    key: (r) => (numeric ? r.n : r.s),
    numeric,
    dir,
    cursor,
    pageSize: 5,
  });

function walk(dir: "asc" | "desc", numeric: boolean): Row[] {
  const out: Row[] = [];
  let p: Page<Row> = page(undefined, dir, numeric);
  out.push(...p.items);
  while (p.next) {
    p = page(p.next, dir, numeric);
    out.push(...p.items);
  }
  return out;
}

describe("keyset paging in memory", () => {
  it("visits every row once, in order, for both directions and both key types", () => {
    for (const dir of ["asc", "desc"] as const) {
      for (const numeric of [true, false]) {
        const all = walk(dir, numeric);
        expect(all).toHaveLength(23);
        expect(new Set(all.map((r) => r.id)).size).toBe(23);
        const key = (r: Row) => (numeric ? r.n : r.s);
        for (let i = 1; i < all.length; i++) {
          const a = key(all[i - 1] as Row);
          const b = key(all[i] as Row);
          expect(dir === "asc" ? a <= b : a >= b).toBe(true);
        }
      }
    }
  });

  it("goes back to exactly the previous page and reports the total", () => {
    const first = page(undefined);
    expect(first.total).toBe(23);
    expect(first.prev).toBeNull();
    const second = page(first.next as string);
    expect(second.prev).not.toBeNull();
    const back = page(second.prev as string);
    expect(back.items.map((r) => r.id)).toEqual(first.items.map((r) => r.id));
    expect(back.prev).toBeNull();
  });

  it("stays put when a row is removed after the cursor was issued", () => {
    const first = page(undefined);
    const without = rows.filter((r) => r.id !== first.items[0]?.id);
    const second = page(first.next as string, "desc", true, without);
    const all = page(undefined, "desc", true, without);
    // The boundary is the last row of the first page, so the second page does not shift.
    expect(second.items.map((r) => r.id)).toEqual(
      walk("desc", true)
        .slice(5, 10)
        .map((r) => r.id),
    );
    expect(all.total).toBe(22);
  });

  it("returns an empty page for no rows and refuses a damaged cursor", () => {
    expect(page(undefined, "desc", true, []).items).toEqual([]);
    expect(() => page("not-a-cursor")).toThrow();
    const cursor = page(undefined).next as string;
    expect(() =>
      pageInMemory(rows, {
        id: (r) => r.id,
        key: (r) => r.s,
        numeric: true,
        dir: "asc",
        cursor: Buffer.from(JSON.stringify({ k: "abc", id: "r1", d: "a" })).toString("base64url"),
        pageSize: 5,
      }),
    ).toThrow();
    expect(cursor.length).toBeGreaterThan(10);
  });
});
