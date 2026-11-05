import { describe, expect, it } from "vitest";
import { pdfRgb, SEVERITY_FILL_HEX } from "./severity-colours.ts";

describe("severity colours for the PDF", () => {
  it("writes a hex colour as the 0 to 1 components of a PDF colour operator", () => {
    expect(pdfRgb("#ffffff")).toBe("1 1 1");
    expect(pdfRgb("#000000")).toBe("0 0 0");
    expect(pdfRgb("#c1291b")).toBe("0.757 0.161 0.106");
  });

  it("has a colour for each of the four severities", () => {
    expect(Object.keys(SEVERITY_FILL_HEX)).toEqual(["critical", "high", "medium", "low"]);
    for (const hex of Object.values(SEVERITY_FILL_HEX)) expect(pdfRgb(hex)).toMatch(/^[\d.]+ [\d.]+ [\d.]+$/);
  });

  it("refuses anything but a six-digit hex colour", () => {
    expect(() => pdfRgb("red")).toThrow();
    expect(() => pdfRgb("#fff")).toThrow();
  });
});
