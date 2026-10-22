import { geoArea, geoCentroid, geoContains } from "d3-geo";
import { describe, expect, it } from "vitest";
import { WORLD_GEO } from "../assets/world-geo.ts";
import { decodeArcs, decodeWorld, stitchRing } from "./world-geo.ts";

describe("globe geometry", () => {
  const world = decodeWorld(WORLD_GEO);
  const byCode = new Map(world.filter((c) => c.code).map((c) => [c.code as string, c]));

  it("decodes every country: closed rings with real coordinates", () => {
    expect(world.length).toBeGreaterThan(170);
    for (const country of world) {
      expect(country.geometry.coordinates.length, country.name).toBeGreaterThan(0);
      for (const polygon of country.geometry.coordinates) {
        for (const ring of polygon) {
          expect(ring.length, country.name).toBeGreaterThanOrEqual(4);
          expect(ring[0], country.name).toEqual(ring.at(-1));
          for (const [lon, lat] of ring) {
            expect(lon).toBeGreaterThanOrEqual(-180.001);
            expect(lon).toBeLessThanOrEqual(180.001);
            expect(lat).toBeGreaterThanOrEqual(-90.001);
            expect(lat).toBeLessThanOrEqual(90.001);
          }
        }
      }
    }
  });

  it("has unique ISO codes, including Kosovo, and the areas without a code", () => {
    const codes = world.map((c) => c.code).filter(Boolean);
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of ["DE", "FR", "US", "BR", "CN", "RU", "XK", "AQ", "AU", "ZA"]) {
      expect(byCode.has(code), code).toBe(true);
    }
    expect(
      world
        .filter((c) => c.code === null)
        .map((c) => c.name)
        .sort(),
    ).toEqual(["N. Cyprus", "Somaliland"]);
  });

  it("puts the countries where they are: a point inside Germany, the centroid inside its own country", () => {
    const germany = byCode.get("DE");
    expect(
      germany && geoContains({ type: "Feature", properties: {}, geometry: germany.geometry }, [10.0, 51.0]),
    ).toBe(true);
    expect(
      germany && geoContains({ type: "Feature", properties: {}, geometry: germany.geometry }, [2.35, 48.86]),
    ).toBe(false);
    for (const code of ["DE", "FR", "US", "BR", "CN", "AU", "RU"]) {
      const c = byCode.get(code);
      expect(c, code).toBeDefined();
      expect(
        c && geoContains({ type: "Feature", properties: {}, geometry: c.geometry }, c.centroid),
        `${code} centroid ${c?.centroid}`,
      ).toBe(true);
    }
  });

  it("starts the arcs of France in Europe, not in French Guiana, and those of the USA in the contiguous states", () => {
    const [frLon, frLat] = byCode.get("FR")?.centroid ?? [0, 0];
    expect(frLon).toBeGreaterThan(-5);
    expect(frLon).toBeLessThan(10);
    expect(frLat).toBeGreaterThan(40);
    const [usLon] = byCode.get("US")?.centroid ?? [0, 0];
    expect(usLon).toBeGreaterThan(-130);
    expect(usLon).toBeLessThan(-70);
  });

  it("keeps the winding d3-geo expects: no country covers more than half the sphere", () => {
    for (const country of world) {
      const area = geoArea({ type: "Feature", properties: {}, geometry: country.geometry });
      expect(area, country.name).toBeLessThan(2 * Math.PI);
      expect(area, country.name).toBeGreaterThan(0);
    }
    // Russia is large but a small part of the sphere.
    expect(
      geoCentroid({ type: "Feature", properties: {}, geometry: byCode.get("RU")?.geometry as never })[0],
    ).toBeGreaterThan(50);
  });

  it("stitches a ring from arcs, walking reversed arcs backwards and sharing end points", () => {
    const decoded = decodeArcs({
      scale: [1, 1],
      translate: [0, 0],
      arcs: [
        [
          [0, 0],
          [2, 0],
        ],
        [
          [2, 0],
          [0, 2],
        ],
        [
          [2, 2],
          [-2, -2],
        ],
      ],
    });
    expect(decoded[0]).toEqual([
      [0, 0],
      [2, 0],
    ]);
    expect(stitchRing([0, 1, 2], decoded)).toEqual([
      [0, 0],
      [2, 0],
      [2, 2],
      [0, 0],
    ]);
    expect(stitchRing([~2, ~1, ~0], decoded)).toEqual([
      [0, 0],
      [2, 2],
      [2, 0],
      [0, 0],
    ]);
    expect(() => stitchRing([99], decoded)).toThrow("Unknown arc");
  });
});
