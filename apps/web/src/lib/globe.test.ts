import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ARC_DRAW_MS,
  ARC_STAGGER_MAX_MS,
  ARC_WIDTH,
  AUTO_ROTATE_DEG_PER_SECOND,
  arcDelay,
  arcLine,
  arcProgress,
  arcWidthFor,
  autoRotate,
  clampLatitude,
  dragSensitivity,
  dragView,
  initialView,
  isFacing,
  keyView,
  LIVE_ARC_LIFETIME_MS,
  LIVE_DRAW_MS,
  liveOpacity,
  MAP_VIEW_KEY,
  MAX_LATITUDE,
  pointRadiusFor,
  prefersReducedMotion,
  readMapView,
  rotationOf,
  sourcePoint,
  toneOf,
  topCountriesText,
  wrapLongitude,
  writeMapView,
} from "./globe.ts";

describe("stroke width of an arc", () => {
  it("has three discrete widths, growing with the count, none for no alerts", () => {
    expect(ARC_WIDTH).toEqual([0, 1.25, 2, 3]);
    expect(arcWidthFor(0, 100)).toBe(0);
    expect(arcWidthFor(1, 100)).toBe(1.25);
    expect(arcWidthFor(30, 100)).toBe(2);
    expect(arcWidthFor(100, 100)).toBe(3);
    const widths = new Set(Array.from({ length: 200 }, (_, i) => arcWidthFor(i + 1, 200)));
    expect([...widths].sort()).toEqual([1.25, 2, 3]);
    // Never wider than the widest step, whatever the input.
    expect(arcWidthFor(10_000, 100)).toBe(3);
    expect(arcWidthFor(5, 0)).toBe(0);
  });
  it("uses the same steps for the dot at the start of an arc", () => {
    expect(pointRadiusFor(0, 10)).toBe(0);
    expect(pointRadiusFor(1, 100)).toBeLessThan(pointRadiusFor(100, 100));
  });
  it("is vermilion above an abuse score of 80 and orange otherwise", () => {
    expect(toneOf(95, true)).toBe("high");
    expect(toneOf(80, true)).toBe("observed");
    expect(toneOf(95, false)).toBe("observed");
    expect(toneOf(null, true)).toBe("observed");
  });
});

describe("moving the view", () => {
  it("wraps longitude into -180..180 and clamps latitude", () => {
    expect(wrapLongitude(190)).toBe(-170);
    expect(wrapLongitude(-190)).toBe(170);
    expect(wrapLongitude(360)).toBe(0);
    expect(wrapLongitude(180)).toBe(180);
    expect(wrapLongitude(-180)).toBe(-180);
    expect(clampLatitude(90)).toBe(MAX_LATITUDE);
    expect(clampLatitude(-90)).toBe(-MAX_LATITUDE);
    expect(clampLatitude(12)).toBe(12);
  });
  it("starts on the home point, or somewhere sensible without one", () => {
    expect(initialView([13.4, 52.52])).toEqual({ lon: 13.4, lat: 52.52 * 0.6 });
    expect(initialView(null)).toEqual({ lon: 10, lat: 20 });
    expect(rotationOf({ lon: 13.4, lat: 20 })).toEqual([-13.4, -20]);
  });
  it("follows a drag: the surface moves with the pointer, never beyond the poles limit", () => {
    const view = { lon: 0, lat: 0 };
    const right = dragView(view, 100, 0, 500);
    expect(right.lon).toBeLessThan(0); // the surface moved right, the view moved west
    expect(right.lon).toBeCloseTo(-100 * dragSensitivity(500));
    const down = dragView(view, 0, 100, 500);
    expect(down.lat).toBeGreaterThan(0);
    expect(dragView(view, 0, 100_000, 500).lat).toBe(MAX_LATITUDE);
    expect(dragView(view, 0, -100_000, 500).lat).toBe(-MAX_LATITUDE);
    // The same drag turns a small globe more than a big one.
    expect(dragSensitivity(250)).toBeGreaterThan(dragSensitivity(1000));
  });
  it("turns with the arrow keys and ignores every other key", () => {
    const view = { lon: 0, lat: 0 };
    expect(keyView(view, "ArrowRight")).toEqual({ lon: 10, lat: 0 });
    expect(keyView(view, "ArrowLeft")).toEqual({ lon: -10, lat: 0 });
    expect(keyView(view, "ArrowUp")).toEqual({ lon: 0, lat: 10 });
    expect(keyView(view, "ArrowDown")).toEqual({ lon: 0, lat: -10 });
    expect(keyView({ lon: 175, lat: 0 }, "ArrowRight")).toEqual({ lon: -175, lat: 0 });
    expect(keyView({ lon: 0, lat: 74 }, "ArrowUp")?.lat).toBe(MAX_LATITUDE);
    for (const key of ["a", "Enter", " ", "Tab", "Home"]) expect(keyView(view, key), key).toBeNull();
  });
  it("turns slowly by itself: a few degrees a second", () => {
    expect(AUTO_ROTATE_DEG_PER_SECOND).toBeLessThanOrEqual(6);
    expect(autoRotate({ lon: 0, lat: 5 }, 1000)).toEqual({ lon: AUTO_ROTATE_DEG_PER_SECOND, lat: 5 });
    expect(autoRotate({ lon: 179, lat: 5 }, 1000).lon).toBeCloseTo(-177);
  });
  it("knows which points are on the visible half", () => {
    const view = { lon: 0, lat: 0 };
    expect(isFacing(view, [10, 10])).toBe(true);
    expect(isFacing(view, [170, 0])).toBe(false);
    expect(isFacing(view, [89.9, 0])).toBe(false); // right at the edge it is hidden
  });
});

describe("arcs", () => {
  const berlin = [13.4, 52.52] as const;
  const tokyo = [139.69, 35.68] as const;
  it("samples a great circle from the start to the end", () => {
    const full = arcLine(tokyo, berlin, 1);
    expect(full[0]?.[0]).toBeCloseTo(tokyo[0], 5);
    expect(full[0]?.[1]).toBeCloseTo(tokyo[1], 5);
    expect(full.at(-1)?.[0]).toBeCloseTo(berlin[0], 5);
    expect(full.at(-1)?.[1]).toBeCloseTo(berlin[1], 5);
    expect(full.length).toBeGreaterThan(20);
  });
  it("draws part of an arc as a shorter line that starts at the same place", () => {
    const half = arcLine(tokyo, berlin, 0.5);
    expect(half.length).toBeLessThan(arcLine(tokyo, berlin, 1).length);
    expect(half[0]).toEqual(arcLine(tokyo, berlin, 1)[0]);
    expect(arcLine(tokyo, berlin, 0)).toEqual([]);
    expect(arcLine(tokyo, berlin, -1)).toEqual([]);
    expect(arcLine(tokyo, berlin, 7).length).toBe(arcLine(tokyo, berlin, 1).length);
  });
  it("draws in once, in under 1.2 seconds, easing out", () => {
    expect(arcProgress(-5)).toBe(0);
    expect(arcProgress(0)).toBe(0);
    expect(arcProgress(ARC_DRAW_MS / 2)).toBeGreaterThan(0.5);
    expect(arcProgress(ARC_DRAW_MS)).toBe(1);
    expect(arcProgress(10 * ARC_DRAW_MS)).toBe(1);
    // The last of a batch of arcs is done within 1.2 s.
    expect(ARC_STAGGER_MAX_MS + ARC_DRAW_MS).toBeLessThanOrEqual(1200);
    expect(arcDelay(0)).toBe(0);
    expect(arcDelay(100)).toBe(ARC_STAGGER_MAX_MS);
    expect(arcDelay(3)).toBeLessThan(arcDelay(4));
  });
  it("lets a live arc draw in, stay and fade to nothing, then end", () => {
    expect(LIVE_DRAW_MS).toBeLessThanOrEqual(1200);
    expect(liveOpacity(0)).toBe(1);
    expect(liveOpacity(LIVE_DRAW_MS + 100)).toBe(1);
    expect(liveOpacity(LIVE_ARC_LIFETIME_MS - 100)).toBeGreaterThan(0);
    expect(liveOpacity(LIVE_ARC_LIFETIME_MS - 100)).toBeLessThan(0.2);
    expect(liveOpacity(LIVE_ARC_LIFETIME_MS)).toBe(0);
    expect(liveOpacity(1e9)).toBe(0);
    expect(LIVE_ARC_LIFETIME_MS).toBeLessThan(10_000);
  });
});

describe("places", () => {
  it("starts arcs at the centroid, or at the capital for a country with no shape", () => {
    const centroids = new Map<string, readonly [number, number]>([["DE", [10.3, 51.1]]]);
    expect(sourcePoint("DE", centroids)).toEqual([10.3, 51.1]);
    expect(sourcePoint("SG", centroids)).toEqual([103.82, 1.35]);
    expect(sourcePoint("ZZ", centroids)).toBeNull();
    expect(sourcePoint("__proto__", centroids)).toBeNull();
  });
  it("names the busiest countries for the text alternative", () => {
    const names: Record<string, string> = { DE: "Germany", FR: "France", BR: "Brazil", NL: "Netherlands" };
    const text = topCountriesText(
      [
        { country: "BR", alerts: 3 },
        { country: "DE", alerts: 67 },
        { country: "FR", alerts: 22 },
        { country: "NL", alerts: 1 },
      ],
      (c) => names[c] ?? c,
    );
    expect(text).toBe("Germany (67), France (22), Brazil (3)");
    expect(topCountriesText([], (c) => c)).toBe("");
  });
});

describe("remembering globe or map", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  const store = () => {
    const data = new Map<string, string>();
    return {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      data,
    };
  };
  it("is the globe by default, and the flat map once it was chosen", () => {
    const local = store();
    vi.stubGlobal("localStorage", local);
    expect(readMapView()).toBe("globe");
    writeMapView("map");
    expect(local.data.get(MAP_VIEW_KEY)).toBe("map");
    expect(readMapView()).toBe("map");
    writeMapView("globe");
    expect(readMapView()).toBe("globe");
    local.setItem(MAP_VIEW_KEY, "nonsense");
    expect(readMapView()).toBe("globe");
  });
  it("works without storage: private windows, blocked site data", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    });
    expect(readMapView()).toBe("globe");
    expect(() => writeMapView("map")).not.toThrow();
  });
  it("reads the motion preference, and a missing matchMedia as no preference", () => {
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("reduce") }));
    expect(prefersReducedMotion()).toBe(true);
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
    expect(prefersReducedMotion()).toBe(false);
    vi.stubGlobal("matchMedia", undefined);
    expect(prefersReducedMotion()).toBe(false);
  });
});
