/**
 * Decodes the globe's country geometry (assets/world-geo.ts, a TopoJSON subset) into GeoJSON that d3-geo can draw.
 *
 * This is the part of topojson-client that is needed here (delta decoding, reversed arcs, stitching the arcs of a ring);
 * writing it out keeps one more dependency out of the product. Winding is kept as the data has it, which is the
 * convention d3-geo expects.
 */
import type { WorldGeo, WorldGeoCountry } from "../assets/world-geo.ts";

export type Position = [number, number];

/** GeoJSON MultiPolygon, written out so that this file needs no type package of its own. */
export interface MultiPolygon {
  type: "MultiPolygon";
  coordinates: Position[][][];
}

/** Decodes every arc: positions are cumulative sums of the stored deltas, then scaled and translated. */
export function decodeArcs(geo: Pick<WorldGeo, "arcs" | "scale" | "translate">): Position[][] {
  const [sx, sy] = geo.scale;
  const [tx, ty] = geo.translate;
  return geo.arcs.map((arc) => {
    let x = 0;
    let y = 0;
    return arc.map(([dx, dy]) => {
      x += dx;
      y += dy;
      return [x * sx + tx, y * sy + ty] as Position;
    });
  });
}

/** One ring from its arc indexes; a negative index (`~i`) is arc `i` walked backwards. Shared end points are kept once. */
export function stitchRing(arcs: readonly number[], decoded: readonly Position[][]): Position[] {
  const ring: Position[] = [];
  for (const index of arcs) {
    const source = decoded[index < 0 ? ~index : index];
    if (!source) throw new Error("Unknown arc");
    const points = index < 0 ? [...source].reverse() : source;
    for (let i = ring.length > 0 ? 1 : 0; i < points.length; i++) ring.push(points[i] as Position);
  }
  return ring;
}

export interface GlobeCountry {
  /** ISO 3166-1 alpha-2; null for the two areas without a code (drawn as neutral land). */
  code: string | null;
  name: string;
  /** Longitude and latitude of the centroid of the country's largest part. */
  centroid: Position;
  geometry: MultiPolygon;
}

export function decodeCountry(country: WorldGeoCountry, decoded: readonly Position[][]): GlobeCountry {
  return {
    code: country.code,
    name: country.name,
    centroid: [country.centroid[0], country.centroid[1]],
    geometry: {
      type: "MultiPolygon",
      coordinates: country.polygons.map((rings) => rings.map((ring) => stitchRing(ring, decoded))),
    },
  };
}

export function decodeWorld(geo: WorldGeo): GlobeCountry[] {
  const decoded = decodeArcs(geo);
  return geo.countries.map((country) => decodeCountry(country, decoded));
}
