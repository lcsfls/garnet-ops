import { describe, expect, it } from "vitest";
import { CAPITALS, COUNTRY_CODES, capitalOf, isCountryCode } from "./countries.ts";
import { checkHomeLocation, parseCoordinate, resolveHomePoint, roundCoordinate } from "./home-location.ts";

describe("capitals", () => {
  it("has plausible entries: codes, ranges, two decimals at most", () => {
    expect(COUNTRY_CODES.length).toBeGreaterThan(220);
    for (const [code, [name, lat, lon]] of Object.entries(CAPITALS)) {
      expect(code, code).toMatch(/^[A-Z]{2}$/);
      expect(name.length, code).toBeGreaterThan(1);
      expect(Math.abs(lat), code).toBeLessThanOrEqual(90);
      expect(Math.abs(lon), code).toBeLessThanOrEqual(180);
      expect(roundCoordinate(lat), code).toBe(lat);
      expect(roundCoordinate(lon), code).toBe(lon);
    }
    expect(capitalOf("DE")).toEqual({ name: "Berlin", lat: 52.52, lon: 13.4 });
    expect(capitalOf("XK")?.name).toBe("Pristina");
  });
  it("knows only real codes, and not inherited object properties", () => {
    expect(isCountryCode("DE")).toBe(true);
    for (const bad of ["de", "ZZ", "AQ", "", "__proto__", "constructor", "toString", null, 5]) {
      expect(isCountryCode(bad), String(bad)).toBe(false);
    }
    expect(capitalOf("__proto__")).toBeNull();
  });
});

describe("coordinates", () => {
  it("rounds to two decimals and never returns minus zero", () => {
    expect(roundCoordinate(52.5234)).toBe(52.52);
    expect(roundCoordinate(13.4049)).toBe(13.4);
    expect(roundCoordinate(-0.001)).toBe(0);
    expect(Object.is(roundCoordinate(-0.001), -0)).toBe(false);
    expect(roundCoordinate(-122.4194)).toBe(-122.42);
  });
  it("reads a typed coordinate with a point or a comma and nothing else", () => {
    expect(parseCoordinate("52.52")).toBe(52.52);
    expect(parseCoordinate(" -13,4 ")).toBe(-13.4);
    expect(parseCoordinate("+7")).toBe(7);
    for (const bad of [
      "",
      "abc",
      "1e2",
      "52.52.1",
      "--5",
      "52°",
      "1,000.5",
      "0x10",
      "Infinity",
      "NaN",
      "1234",
      "52.",
      ".5",
    ]) {
      expect(parseCoordinate(bad), bad).toBeNull();
    }
  });
});

describe("home location", () => {
  it("accepts a country alone, or a country with a point, and rounds the point", () => {
    expect(checkHomeLocation({ country: "DE" })).toEqual({
      ok: true,
      home: { country: "DE", lat: null, lon: null },
    });
    expect(checkHomeLocation({ country: " de ", lat: 52.5234, lon: 13.4049 })).toEqual({
      ok: true,
      home: { country: "DE", lat: 52.52, lon: 13.4 },
    });
    expect(checkHomeLocation({ country: "NZ", lat: -90, lon: 180 })).toMatchObject({ ok: true });
  });
  it("refuses an unknown country, a point out of range, half a point and anything that is not a number", () => {
    const problems = (input: Record<string, unknown>) => {
      const r = checkHomeLocation(input);
      return r.ok ? [] : r.problems;
    };
    expect(problems({})).toEqual(["country"]);
    expect(problems({ country: "ZZ" })).toEqual(["country"]);
    expect(problems({ country: "Germany" })).toEqual(["country"]);
    expect(problems({ country: "DE", lat: 91, lon: 0 })).toEqual(["latitude"]);
    expect(problems({ country: "DE", lat: 0, lon: -181 })).toEqual(["longitude"]);
    expect(problems({ country: "DE", lat: 10 })).toEqual(["pair"]);
    expect(problems({ country: "DE", lon: 10 })).toEqual(["pair"]);
    expect(problems({ country: "DE", lat: "52.5", lon: 13 })).toEqual(["latitude"]);
    expect(problems({ country: "DE", lat: Number.NaN, lon: 13 })).toEqual(["latitude"]);
    expect(problems({ country: "DE", lat: Number.POSITIVE_INFINITY, lon: 13 })).toEqual(["latitude"]);
    expect(problems({ country: "XX", lat: 100, lon: 200 }).sort()).toEqual([
      "country",
      "latitude",
      "longitude",
    ]);
  });
  it("places the marker at the stored point, or at the capital when only a country was chosen, or nowhere", () => {
    expect(resolveHomePoint({ country: "DE", lat: 50.94, lon: 6.96 })).toEqual({
      lat: 50.94,
      lon: 6.96,
      source: "set",
    });
    expect(resolveHomePoint({ country: "DE", lat: null, lon: null })).toEqual({
      lat: 52.52,
      lon: 13.4,
      source: "capital",
    });
    expect(resolveHomePoint({ country: "ZZ", lat: null, lon: null })).toBeNull();
    expect(resolveHomePoint(null)).toBeNull();
    expect(resolveHomePoint(undefined)).toBeNull();
  });
});
