/**
 * Pure helpers of the globe on the Attacks page (ADR 0021): where the view is centred and how it moves, how an arc is
 * sampled and animated, and which colour class and stroke width an arc gets. No DOM and no React here, so the
 * behaviour is tested without a browser. Drawing itself is in components/attack-globe.tsx.
 *
 * Motion is short and purposeful (AGENTS.md rule 6): an arc draws in once over about a second and a live arc fades
 * after a few seconds. Nothing pulses and nothing loops except the slow turn of the globe, which stops under
 * prefers-reduced-motion and can be paused.
 */
import { ARC_STEPS, arcStep, arcTone } from "@garnetops/core/attacks";
import { capitalOf } from "@garnetops/core/countries";
import { geoDistance, geoInterpolate } from "d3-geo";

export type LonLat = readonly [lon: number, lat: number];

/** Stroke width in pixels per step of `arcStep`: three discrete widths, none for step 0. */
export const ARC_WIDTH: readonly number[] = [0, 1.25, 2, 3];
export const LIVE_ARC_WIDTH = 2;
/** Radius of the dot at the start of an arc, per step. */
export const POINT_RADIUS: readonly number[] = [0, 3, 4, 5.5];

/** An arc draws in over this long; a staggered start per arc keeps the whole load under 1.2 seconds. */
export const ARC_DRAW_MS = 800;
export const ARC_STAGGER_MS = 15;
export const ARC_STAGGER_MAX_MS = 350;
/** Live arcs: draw in, stay, fade. */
export const LIVE_DRAW_MS = 1100;
export const LIVE_HOLD_MS = 3500;
export const LIVE_FADE_MS = 2500;
export const LIVE_ARC_LIFETIME_MS = LIVE_DRAW_MS + LIVE_HOLD_MS + LIVE_FADE_MS;
export const MAX_LIVE_ARCS = 30;
/** Degrees of longitude per second of the slow turn. */
export const AUTO_ROTATE_DEG_PER_SECOND = 4;
export const MAX_LATITUDE = 75;
export const KEY_STEP_DEGREES = 10;

export const wrapLongitude = (lon: number): number =>
  lon >= -180 && lon <= 180 ? lon : ((((lon + 180) % 360) + 360) % 360) - 180;
export const clampLatitude = (lat: number): number => Math.max(-MAX_LATITUDE, Math.min(MAX_LATITUDE, lat));

/** The point at the middle of the view, as longitude and latitude. */
export interface View {
  lon: number;
  lat: number;
}

/** d3's rotation for a view centred on `view`. */
export const rotationOf = (view: View): [number, number] => [-view.lon, -view.lat];

/** The first view: centred on the home point, or on Europe-ish 10 degrees east if there is none. */
export function initialView(home: LonLat | null): View {
  return home ? { lon: wrapLongitude(home[0]), lat: clampLatitude(home[1] * 0.6) } : { lon: 10, lat: 20 };
}

/** Degrees per pixel when the surface is dragged: a drag across the whole diameter turns the globe about 150 degrees. */
export const dragSensitivity = (diameter: number): number => 150 / Math.max(120, diameter);

/** The view after dragging by (dx, dy) pixels: the surface follows the pointer. */
export function dragView(view: View, dx: number, dy: number, diameter: number): View {
  const k = dragSensitivity(diameter);
  return { lon: wrapLongitude(view.lon - dx * k), lat: clampLatitude(view.lat + dy * k) };
}

/** The view after an arrow key, or null for any other key. Right turns the view east, up turns it north. */
export function keyView(view: View, key: string, step = KEY_STEP_DEGREES): View | null {
  switch (key) {
    case "ArrowLeft":
      return { lon: wrapLongitude(view.lon - step), lat: view.lat };
    case "ArrowRight":
      return { lon: wrapLongitude(view.lon + step), lat: view.lat };
    case "ArrowUp":
      return { lon: view.lon, lat: clampLatitude(view.lat + step) };
    case "ArrowDown":
      return { lon: view.lon, lat: clampLatitude(view.lat - step) };
    default:
      return null;
  }
}

/** The view after `ms` of the slow turn. */
export const autoRotate = (view: View, ms: number): View => ({
  lon: wrapLongitude(view.lon + (AUTO_ROTATE_DEG_PER_SECOND * ms) / 1000),
  lat: view.lat,
});

/** Whether a point is on the visible half of the globe. */
export const isFacing = (view: View, point: LonLat): boolean =>
  geoDistance([view.lon, view.lat], point as [number, number]) < Math.PI / 2 - 0.02;

/* -------------------------------------------------------------------------- */
/* Arcs                                                                        */
/* -------------------------------------------------------------------------- */

/** Width in pixels of an arc for a count: three discrete steps, relative to the busiest country. */
export const arcWidthFor = (count: number, max: number): number => ARC_WIDTH[arcStep(count, max)] ?? 0;
export const pointRadiusFor = (count: number, max: number): number => POINT_RADIUS[arcStep(count, max)] ?? 0;
export { ARC_STEPS };

/** Colour class of an arc: vermilion above an abuse score of 80 (OSINT on and a score), otherwise orange. */
export const ARC_STROKE = { high: "stroke-chart-critical", observed: "stroke-chart-high" } as const;
export const POINT_FILL = { high: "fill-chart-critical", observed: "fill-chart-high" } as const;
export const toneOf = arcTone;

/**
 * The great-circle arc from `from` to `to`, drawn up to `progress` (0 to 1) with `samples` segments along the whole
 * arc. Fewer points are returned for a partial arc, so a path of it ends where the drawing has got to.
 */
export function arcLine(from: LonLat, to: LonLat, progress: number, samples = 48): [number, number][] {
  const p = Math.max(0, Math.min(1, progress));
  if (p === 0) return [];
  const interpolate = geoInterpolate(from as [number, number], to as [number, number]);
  const count = Math.max(2, Math.ceil(samples * p));
  const points: [number, number][] = [];
  for (let i = 0; i <= count; i++) points.push(interpolate((p * i) / count) as [number, number]);
  return points;
}

const easeOut = (t: number) => 1 - (1 - t) ** 3;

/** How much of an arc is drawn `ageMs` after it started, easing out; 0 before the start, 1 after the draw time. */
export function arcProgress(ageMs: number, drawMs = ARC_DRAW_MS): number {
  if (ageMs <= 0) return 0;
  if (ageMs >= drawMs) return 1;
  return easeOut(ageMs / drawMs);
}

/** The start delay of the `index`-th arc of a batch. The whole load stays under 1.2 seconds. */
export const arcDelay = (index: number): number => Math.min(ARC_STAGGER_MAX_MS, index * ARC_STAGGER_MS);

/** Opacity of a live arc: full while it draws and holds, then fading to nothing. */
export function liveOpacity(ageMs: number): number {
  const fadeStart = LIVE_DRAW_MS + LIVE_HOLD_MS;
  if (ageMs <= fadeStart) return 1;
  return Math.max(0, 1 - (ageMs - fadeStart) / LIVE_FADE_MS);
}

/* -------------------------------------------------------------------------- */
/* Places                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Where the arcs of a country start: the centroid of its largest part, or - for a country too small for the 110m
 * shapes - its capital. Null for a code that is in neither.
 */
export function sourcePoint(code: string, centroids: ReadonlyMap<string, LonLat>): LonLat | null {
  const centroid = centroids.get(code);
  if (centroid) return centroid;
  const capital = capitalOf(code);
  return capital ? [capital.lon, capital.lat] : null;
}

/** The names of the busiest countries for the text alternative of the globe: "Germany (67), France (22)". */
export function topCountriesText(
  countries: readonly { country: string; alerts: number }[],
  nameOf: (code: string) => string,
  limit = 3,
): string {
  return [...countries]
    .sort((a, b) => b.alerts - a.alerts || a.country.localeCompare(b.country))
    .slice(0, limit)
    .map((c) => `${nameOf(c.country)} (${c.alerts})`)
    .join(", ");
}

/** Whether the user asked their system for less motion. Safe where `matchMedia` does not exist. */
export function prefersReducedMotion(): boolean {
  try {
    return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Remembering the choice                                                      */
/* -------------------------------------------------------------------------- */

export type MapView = "globe" | "map";
export const MAP_VIEW_KEY = "garnetops.attacks.view";

/** The remembered choice between globe and flat map. The globe by default, and whenever storage is unavailable. */
export function readMapView(): MapView {
  try {
    return localStorage.getItem(MAP_VIEW_KEY) === "map" ? "map" : "globe";
  } catch {
    return "globe";
  }
}

export function writeMapView(view: MapView): void {
  try {
    localStorage.setItem(MAP_VIEW_KEY, view);
  } catch {
    // Storage can be blocked or full; the choice then lasts until the page is closed.
  }
}
