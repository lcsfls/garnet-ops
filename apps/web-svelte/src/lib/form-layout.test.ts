import { describe, expect, it } from "vitest";
import { formColumnTemplate } from "./form-layout.ts";

describe("formColumnTemplate", () => {
  it("makes equal columns that may shrink", () => {
    expect(formColumnTemplate(2)).toBe("minmax(0,1fr) minmax(0,1fr)");
    expect(formColumnTemplate(3)).toBe("minmax(0,1fr) minmax(0,1fr) minmax(0,1fr)");
  });

  it("keeps fixed tracks and makes bare fractions shrinkable", () => {
    expect(formColumnTemplate(["1fr", "8rem"])).toBe("minmax(0,1fr) 8rem");
    expect(formColumnTemplate(["10rem", "minmax(0,1fr)"])).toBe("10rem minmax(0,1fr)");
    expect(formColumnTemplate(["2fr", "1fr"])).toBe("minmax(0,2fr) minmax(0,1fr)");
  });

  it("refuses anything that is not a plain size, so no CSS can be injected through the template", () => {
    expect(() => formColumnTemplate(["1fr", "8rem; display:none"])).toThrow(RangeError);
    expect(() => formColumnTemplate(["var(--x)"])).toThrow(RangeError);
    expect(() => formColumnTemplate(["min-content"])).toThrow(RangeError);
  });

  it("limits the number of columns", () => {
    expect(() => formColumnTemplate(0)).toThrow(RangeError);
    expect(() => formColumnTemplate(5)).toThrow(RangeError);
    expect(() => formColumnTemplate([])).toThrow(RangeError);
    expect(() => formColumnTemplate(1.5)).toThrow(RangeError);
  });
});
