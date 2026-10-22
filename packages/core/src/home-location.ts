/**
 * The home location of the attack overview (ADR 0021): the point where the globe ends the arcs of the attack
 * sources. A country is required; a city-level point (latitude and longitude, two decimals) is optional and is entered
 * by hand or taken from the country's capital. There are no default coordinates: an organisation without a home
 * location gets points on the globe and no arcs.
 *
 * Two decimals are about one kilometre. That is all the picture needs, and it keeps a precise address of the
 * customer's premises out of the database. Pure functions; the API validates with them, the web app uses them for
 * the form and for placing the marker.
 */
import { capitalOf, isCountryCode } from "./countries.ts";

export const HOME_DECIMALS = 2;

export interface HomeLocation {
  /** ISO 3166-1 alpha-2, from `CAPITALS`. */
  country: string;
  /** Both or neither. */
  lat: number | null;
  lon: number | null;
}

export type HomeProblem = "country" | "latitude" | "longitude" | "pair";

/** Rounds to two decimals; never returns -0. */
export function roundCoordinate(value: number): number {
  const rounded = Math.round(value * 10 ** HOME_DECIMALS) / 10 ** HOME_DECIMALS;
  return rounded === 0 ? 0 : rounded;
}

/**
 * A coordinate typed into a form: plain decimal notation with a point or a comma ("52.52", "-13,4"). Anything else
 * (exponents, units, several signs, text) is not a coordinate. Returns null for empty or invalid input.
 */
export function parseCoordinate(text: string): number | null {
  const trimmed = text.trim();
  if (!/^[-+]?\d{1,3}(?:[.,]\d{1,10})?$/.test(trimmed)) return null;
  const value = Number(trimmed.replace(",", "."));
  return Number.isFinite(value) ? value : null;
}

/** Validates a home location from the outside and returns the rounded value to store. */
export function checkHomeLocation(input: {
  country?: unknown;
  lat?: unknown;
  lon?: unknown;
}): { ok: true; home: HomeLocation } | { ok: false; problems: HomeProblem[] } {
  const problems: HomeProblem[] = [];
  const country = typeof input.country === "string" ? input.country.trim().toUpperCase() : "";
  if (!isCountryCode(country)) problems.push("country");
  const given = (v: unknown) => v !== undefined && v !== null;
  let lat: number | null = null;
  let lon: number | null = null;
  if (given(input.lat) !== given(input.lon)) problems.push("pair");
  if (given(input.lat)) {
    if (typeof input.lat !== "number" || !Number.isFinite(input.lat) || Math.abs(input.lat) > 90) {
      problems.push("latitude");
    } else lat = roundCoordinate(input.lat);
  }
  if (given(input.lon)) {
    if (typeof input.lon !== "number" || !Number.isFinite(input.lon) || Math.abs(input.lon) > 180) {
      problems.push("longitude");
    } else lon = roundCoordinate(input.lon);
  }
  if (problems.length > 0) return { ok: false, problems };
  return { ok: true, home: { country, lat, lon } };
}

/**
 * The point the globe draws the home marker at: the stored point, or the capital of the country if only a country was
 * chosen. Null when there is nothing to place (no country, or a country the table does not know).
 */
export function resolveHomePoint(
  home: HomeLocation | null | undefined,
): { lat: number; lon: number; source: "set" | "capital" } | null {
  if (!home) return null;
  if (home.lat !== null && home.lon !== null) return { lat: home.lat, lon: home.lon, source: "set" };
  const capital = capitalOf(home.country);
  return capital ? { lat: capital.lat, lon: capital.lon, source: "capital" } : null;
}
