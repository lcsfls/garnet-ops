import { describe, expect, it } from "vitest";
import { columnPath, niceTicks } from "./chart.ts";

describe("chart geometry", () => {
  it("picks clean whole-number axis values that reach the largest value", () => {
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(1)).toEqual([0, 1]);
    expect(niceTicks(2)).toEqual([0, 1, 2]);
    expect(niceTicks(7)).toEqual([0, 5, 10]);
    expect(niceTicks(16)).toEqual([0, 10, 20]);
    expect(niceTicks(30)).toEqual([0, 10, 20, 30]);
    expect(niceTicks(31)).toEqual([0, 20, 40]);
    expect(niceTicks(1234)).toEqual([0, 500, 1000, 1500]);
  });

  it("rounds a column at its data end only, never more than half its width or its height", () => {
    expect(columnPath(10, 20, 100, 20, "top")).toBe("M10,100v-76a4,4 0 0 1 4,-4h12a4,4 0 0 1 4,4v76Z");
    expect(columnPath(10, 100, 180, 20, "bottom")).toBe("M10,100h20v76a4,4 0 0 1 -4,4h-12a4,4 0 0 1 -4,-4Z");
    expect(columnPath(0, 98, 100, 6, "top")).toBe("M0,100v0a2,2 0 0 1 2,-2h2a2,2 0 0 1 2,2v0Z");
    expect(columnPath(0, 50, 100, 20, null)).toBe("M0,100v-50a0,0 0 0 1 0,0h20a0,0 0 0 1 0,0v50Z");
  });
});
