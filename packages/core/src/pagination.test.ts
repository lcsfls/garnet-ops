import { describe, expect, it } from "vitest";
import { decodeCursor, encodeCursor, InvalidCursorError, pageSizeSchema } from "./pagination.ts";

describe("cursor", () => {
  it("round-trips", () => {
    const c = { k: "2026-10-19T10:00:00.000Z", id: "fnd_1", d: "a" } as const;
    expect(decodeCursor(encodeCursor(c))).toEqual(c);
  });

  it("returns null for an empty cursor", () => {
    expect(decodeCursor(undefined)).toBeNull();
    expect(decodeCursor("")).toBeNull();
  });

  it("rejects garbage and oversized cursors", () => {
    expect(() => decodeCursor("not-base64-json")).toThrow(InvalidCursorError);
    expect(() => decodeCursor(encodeCursor({ k: 1, id: "x", d: "a" }).slice(0, 10))).toThrow(
      InvalidCursorError,
    );
    expect(() => decodeCursor("a".repeat(600))).toThrow(InvalidCursorError);
  });
});

describe("page size", () => {
  it("accepts only the offered sizes", () => {
    expect(pageSizeSchema.parse("50")).toBe(50);
    expect(pageSizeSchema.parse(undefined)).toBe(25);
    expect(() => pageSizeSchema.parse("1000")).toThrow();
  });
});
