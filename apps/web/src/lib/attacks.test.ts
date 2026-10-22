import { describe, expect, it } from "vitest";
import { ApiError } from "./api.ts";
import { countryName, legendSteps, MAP_FILL, shadeStep, stepCeiling, uploadReason } from "./attacks.ts";
import { attacksSearch } from "./search.ts";

describe("map colour steps", () => {
  it("has a class for every step", () => {
    for (let step = 0; step <= 5; step++) expect(MAP_FILL[step]).toMatch(/^fill-/);
  });

  it("builds a legend whose ranges match the steps countries get", () => {
    for (const max of [1, 2, 7, 100, 4711, 100_000]) {
      const legend = legendSteps(max);
      expect(legend.at(-1)?.upTo).toBe(max);
      let previous = 0;
      for (const { step, upTo } of legend) {
        expect(upTo).toBeGreaterThan(previous);
        expect(shadeStep(upTo, max)).toBe(step);
        if (previous + 1 <= max) expect(shadeStep(previous + 1, max)).toBe(step);
        previous = upTo;
      }
    }
  });

  it("finds the upper bound of a step", () => {
    expect(stepCeiling(5, 100)).toBe(100);
    expect(stepCeiling(1, 100)).toBe(4);
    expect(shadeStep(4, 100)).toBe(1);
    expect(shadeStep(5, 100)).toBe(2);
  });
});

describe("country names", () => {
  it("names a country in the language and falls back to the code", () => {
    expect(countryName("DE", "en")).toBe("Germany");
    expect(countryName("DE", "de")).toBe("Deutschland");
    expect(countryName("XK", "en").length).toBeGreaterThan(0);
    expect(countryName("not a code", "en")).toBe("not a code");
  });
});

describe("upload errors", () => {
  it("reads the reason from the problem details", () => {
    const problem = (reason: unknown, status = 422) =>
      new ApiError(status, { type: "x/geoip-invalid", title: "t", status, reason });
    expect(uploadReason(problem("notGzip"))).toBe("notGzip");
    expect(uploadReason(new ApiError(413, null))).toBe("tooLarge");
    expect(uploadReason(new ApiError(409, { type: "x/geoip-busy", title: "t", status: 409 }))).toBe("busy");
    expect(uploadReason(new Error("x"))).toBe("generic");
  });
});

describe("search params of the Attacks page", () => {
  it("keeps valid filters and drops anything else", () => {
    expect(
      attacksSearch.parse({
        period: "7d",
        country: "DE",
        asn: 64500,
        agent: "002",
        group: "web_scan",
        sort: "lastSeen",
        dir: "asc",
        pageSize: 50,
      }),
    ).toMatchObject({
      period: "7d",
      country: "DE",
      asn: "64500",
      agent: "002",
      group: "web_scan",
      sort: "lastSeen",
      dir: "asc",
      pageSize: 50,
    });
    const bad = attacksSearch.parse({
      period: "1h",
      country: "Germany",
      asn: "abc",
      agent: "<script>",
      group: "Web Scan!",
      sort: "password",
      dir: "sideways",
      pageSize: 7,
    });
    expect(bad).toEqual({});
    expect(attacksSearch.parse({ country: "internal" }).country).toBe("internal");
    expect(attacksSearch.parse({ country: "unknown" }).country).toBe("unknown");
  });
});
