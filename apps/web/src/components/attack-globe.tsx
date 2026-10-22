import { arcTone, shadeStep } from "@garnetops/core/attacks";
import { type GeoPath, type GeoProjection, geoGraticule10, geoOrthographic, geoPath } from "d3-geo";
import { Pause, Play } from "lucide-react";
import { type KeyboardEvent, type PointerEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { WORLD_GEO } from "../assets/world-geo.ts";
import { countryName, MAP_FILL } from "../lib/attacks.ts";
import { cn } from "../lib/cn.ts";
import {
  ARC_STROKE,
  type ArcToneName,
  arcDelay,
  arcLine,
  arcProgress,
  arcWidthFor,
  autoRotate,
  BLOCKED_DASH,
  dragView,
  initialView,
  isFacing,
  keyView,
  LIVE_ARC_LIFETIME_MS,
  LIVE_ARC_WIDTH,
  LIVE_DRAW_MS,
  type LonLat,
  liveOpacity,
  MAX_LIVE_ARCS,
  POINT_FILL,
  pointRadiusFor,
  prefersReducedMotion,
  rotationOf,
  sourcePoint,
  topCountriesText,
  type View,
} from "../lib/globe.ts";
import type { AttackEvent } from "../lib/types.ts";
import { decodeWorld } from "../lib/world-geo.ts";
import { MapLegend } from "./attack-map.tsx";

export interface GlobeCountryData {
  country: string;
  alerts: number;
  sources: number;
  /** The highest cached abuse score among the country's addresses (only while OSINT is on). */
  topScore?: number | undefined;
  /** Of `alerts`, the ones a UniFi console blocked (ADR 0022). */
  blocked?: number | undefined;
}

export interface AttackGlobeProps {
  countries: GlobeCountryData[];
  /** Where the lines end; null shows the sources as points only. */
  home: { lat: number; lon: number } | null;
  osintEnabled: boolean;
  /** The latest events, newest first; undefined until they are loaded. New ones draw a live line. */
  events: AttackEvent[] | undefined;
  selected: string | undefined;
}

/** The areas of the world, decoded once when this chunk loads. */
const WORLD = decodeWorld(WORLD_GEO);
const FEATURES = WORLD.map((c) => ({
  key: c.code ?? c.name,
  code: c.code,
  feature: { type: "Feature" as const, properties: {}, geometry: c.geometry },
}));
const CENTROIDS = new Map<string, LonLat>(
  WORLD.flatMap((c) => (c.code ? [[c.code, [c.centroid[0], c.centroid[1]] as LonLat] as const] : [])),
);
const GRATICULE = geoGraticule10();

interface StaticArc {
  key: string;
  from: LonLat;
  width: number;
  radius: number;
  tone: ArcToneName;
  /** Whether this arc draws the start dot (a country with observed and blocked alerts draws one dot). */
  dot: boolean;
}
interface LiveArc {
  id: number;
  from: LonLat;
  tone: ArcToneName;
  start: number;
}

/** While the globe only turns slowly, 30 frames a second are plenty. */
const TURNING_FRAME_MS = 33;

/**
 * The globe of the Attacks page (ADR 0021): an orthographic SVG globe, drawn with d3-geo from the vendored Natural Earth
 * shapes, with lines from each source country to the organisation's home location.
 *
 * - Countries are filled by their alerts on the same single-hue scale as the flat map (never a severity colour).
 * - A line's width is one of three steps by count; it is vermilion for an OSINT abuse score above 80 and orange
 *   otherwise. Lines draw in once, in under 1.2 seconds. A live event draws its own line, which fades after a few
 *   seconds. Nothing pulses.
 * - The globe is turned by dragging it or with the arrow keys when it has focus. It also turns slowly by itself, but
 *   not under prefers-reduced-motion, not after the person has touched it, not while it has focus, and not while the
 *   tab is hidden (no frames are requested then). A button pauses it.
 * - The picture is for the eyes: the lists beside it carry the same numbers as tables and are the route for keyboard
 *   and screen reader users. The SVG has a text alternative that names the busiest countries.
 *
 * Frames are drawn by changing attributes of the elements directly, not through React, so a turning globe costs no
 * renders. The CSP forbids inline styles; colours and widths are classes and presentation attributes.
 */
export default function AttackGlobe({ countries, home, osintEnabled, events, selected }: AttackGlobeProps) {
  const { t, i18n } = useTranslation();
  const frame = useRef<HTMLButtonElement>(null);
  const hintId = useId();
  const svg = useRef<SVGSVGElement>(null);
  const [size, setSize] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(prefersReducedMotion);
  const [turning, setTurning] = useState(() => !prefersReducedMotion());
  const [liveArcs, setLiveArcs] = useState<LiveArc[]>([]);

  const homeLat = home?.lat ?? null;
  const homeLon = home?.lon ?? null;
  const hasHome = homeLat !== null && homeLon !== null;
  const max = Math.max(1, ...countries.map((c) => c.alerts));
  const byCode = useMemo(() => new Map(countries.map((c) => [c.country, c])), [countries]);
  // The legend names "Blocked by UniFi" only when something was blocked in this period or a live event was.
  const hasBlocked =
    countries.some((c) => (c.blocked ?? 0) > 0) || (events ?? []).some((e) => e.action === "blocked");

  // The lines (or, without a home, the points) of the countries that have alerts.
  const arcs = useMemo<StaticArc[]>(() => {
    const out: StaticArc[] = [];
    for (const c of countries) {
      const from = sourcePoint(c.country, CENTROIDS);
      if (!from) continue;
      // Alerts a UniFi console blocked are a dashed steel-blue line of their own; the rest keep the usual line.
      const blocked = Math.min(c.blocked ?? 0, c.alerts);
      const observed = c.alerts - blocked;
      if (observed > 0 || blocked === 0) {
        out.push({
          key: c.country,
          from,
          width: arcWidthFor(observed || c.alerts, max),
          radius: pointRadiusFor(c.alerts, max),
          tone: arcTone(c.topScore, osintEnabled),
          dot: true,
        });
      }
      if (blocked > 0) {
        out.push({
          key: `${c.country}:blocked`,
          from,
          width: arcWidthFor(blocked, max),
          radius: pointRadiusFor(c.alerts, max),
          tone: "blocked",
          dot: observed === 0,
        });
      }
    }
    return out.sort((a, b) => b.width - a.width || a.key.localeCompare(b.key));
  }, [countries, max, osintEnabled]);

  /* ---- everything the drawing loop reads lives in refs, so a frame never waits for React ---- */
  const model = useRef<{
    arcs: StaticArc[];
    live: LiveArc[];
    home: LonLat | null;
    size: number;
    turning: boolean;
    reduced: boolean;
  }>({ arcs, live: liveArcs, home: null, size, turning, reduced: reducedMotion });
  const view = useRef<View>(initialView(hasHome ? [homeLon, homeLat] : null));
  const started = useRef(new Map<string, number>());
  const dirty = useRef(true);
  const focused = useRef(false);
  const drag = useRef<{ id: number; x: number; y: number } | null>(null);
  const kick = useRef<() => void>(() => {});
  const parts = useRef({
    land: new Map<string, SVGPathElement>(),
    lines: new Map<string, SVGPathElement>(),
    dots: new Map<string, SVGCircleElement>(),
    liveLines: new Map<number, SVGPathElement>(),
    liveDots: new Map<number, SVGCircleElement>(),
    graticule: null as SVGPathElement | null,
    home: null as SVGGElement | null,
  });

  // The size of the picture: as large as the frame allows, square.
  useEffect(() => {
    const node = frame.current;
    if (!node || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const box = entry?.contentRect;
      if (box) setSize(Math.max(0, Math.floor(Math.min(box.width, box.height))));
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  // The person's system can ask for less motion at any time.
  useEffect(() => {
    if (typeof matchMedia !== "function") return;
    const query = matchMedia("(prefers-reduced-motion: reduce)");
    const change = () => {
      setReducedMotion(query.matches);
      if (query.matches) setTurning(false);
    };
    query.addEventListener("change", change);
    return () => query.removeEventListener("change", change);
  }, []);

  // New events draw a live line. The first list that arrives only sets the starting point.
  const baseline = useRef<number | null>(null);
  const liveId = useRef(0);
  useEffect(() => {
    if (!events) return;
    if (baseline.current === null) {
      baseline.current = events[0]?.seq ?? 0;
      return;
    }
    const known = baseline.current;
    const fresh = events
      .filter((e) => e.seq > known)
      .sort((a, b) => a.seq - b.seq)
      .slice(-12);
    if (fresh.length === 0) return;
    baseline.current = Math.max(known, ...fresh.map((e) => e.seq));
    // Nothing is drawn for a hidden page: nobody sees it, and no frames are requested.
    if (document.hidden) return;
    const now = performance.now();
    const added: LiveArc[] = [];
    for (const event of fresh) {
      if (event.scope !== "public" || !event.country) continue;
      const from = sourcePoint(event.country, CENTROIDS);
      if (!from) continue;
      added.push({
        id: ++liveId.current,
        from,
        tone: event.action === "blocked" ? "blocked" : arcTone(event.score, osintEnabled),
        start: now,
      });
    }
    if (added.length === 0) return;
    setLiveArcs((old) => [...old, ...added].slice(-MAX_LIVE_ARCS));
    for (const arc of added) {
      setTimeout(() => setLiveArcs((old) => old.filter((a) => a.id !== arc.id)), LIVE_ARC_LIFETIME_MS + 100);
    }
  }, [events, osintEnabled]);

  // New data for the loop. Arcs that were not there before draw in once, one after the other; the rest keep their state.
  useEffect(() => {
    model.current = {
      arcs,
      live: liveArcs,
      home: homeLat !== null && homeLon !== null ? [homeLon, homeLat] : null,
      size,
      turning,
      reduced: reducedMotion,
    };
    const now = performance.now();
    let index = 0;
    for (const arc of arcs) {
      if (!started.current.has(arc.key)) started.current.set(arc.key, now + arcDelay(index++));
    }
    kick.current();
  }, [arcs, liveArcs, homeLat, homeLon, size, turning, reducedMotion]);

  // The drawing loop. It asks for frames only while something moves and the page is visible.
  useEffect(() => {
    if (size <= 0) return;
    const projection: GeoProjection = geoOrthographic()
      .scale(size / 2 - 2)
      .translate([size / 2, size / 2])
      .clipAngle(90)
      .precision(0.6);
    const path: GeoPath = geoPath(projection);
    const els = parts.current;
    let raf: number | null = null;
    let last = 0;
    let lastDraw = 0;
    dirty.current = true;

    /** Puts a dot where the point is, or hides it on the far side of the globe. */
    const place = (el: SVGElement | null | undefined, point: LonLat, visible: boolean) => {
      if (!el) return;
      const xy = visible && isFacing(view.current, point) ? projection(point as [number, number]) : null;
      if (!xy) {
        el.setAttribute("visibility", "hidden");
        return;
      }
      el.setAttribute("visibility", "visible");
      el.setAttribute("cx", xy[0].toFixed(1));
      el.setAttribute("cy", xy[1].toFixed(1));
    };

    /** Draws everything for the time `now`; returns whether something is still moving by itself. */
    const draw = (now: number): boolean => {
      const m = model.current;
      let animating = false;
      projection.rotate(rotationOf(view.current));
      if (dirty.current) {
        els.graticule?.setAttribute("d", path(GRATICULE) ?? "");
        for (const item of FEATURES) els.land.get(item.key)?.setAttribute("d", path(item.feature) ?? "");
        dirty.current = false;
      }
      for (const arc of m.arcs) {
        const progress = m.reduced ? 1 : arcProgress(now - (started.current.get(arc.key) ?? now));
        if (progress < 1) animating = true;
        // With a home the start dot appears as the line begins; without one the dots are all there is.
        place(els.dots.get(arc.key), arc.from, !m.home || progress > 0);
        const line = els.lines.get(arc.key);
        if (line) {
          line.setAttribute(
            "d",
            m.home && progress > 0
              ? (path({ type: "LineString", coordinates: arcLine(arc.from, m.home, progress) }) ?? "")
              : "",
          );
        }
      }
      const marker = els.home;
      if (marker) {
        const xy = m.home && isFacing(view.current, m.home) ? projection(m.home as [number, number]) : null;
        if (xy) {
          marker.setAttribute("visibility", "visible");
          marker.setAttribute("transform", `translate(${xy[0].toFixed(1)} ${xy[1].toFixed(1)})`);
        } else marker.setAttribute("visibility", "hidden");
      }
      for (const arc of m.live) {
        const age = now - arc.start;
        if (age < LIVE_ARC_LIFETIME_MS) animating = true;
        const opacity = liveOpacity(age).toFixed(2);
        const line = els.liveLines.get(arc.id);
        if (line) {
          const progress = m.reduced ? 1 : arcProgress(age, LIVE_DRAW_MS);
          line.setAttribute(
            "d",
            m.home
              ? (path({ type: "LineString", coordinates: arcLine(arc.from, m.home, progress) }) ?? "")
              : "",
          );
          line.setAttribute("opacity", opacity);
        }
        const dot = els.liveDots.get(arc.id);
        place(dot, arc.from, age >= 0);
        dot?.setAttribute("opacity", opacity);
      }
      svg.current?.setAttribute(
        "data-rotation",
        `${view.current.lon.toFixed(1)},${view.current.lat.toFixed(1)}`,
      );
      return animating;
    };

    const tick = (now: number) => {
      raf = null;
      const dt = Math.min(100, last ? now - last : 0);
      last = now;
      const m = model.current;
      const turningNow = m.turning && !m.reduced && !focused.current && drag.current === null;
      if (turningNow) {
        view.current = autoRotate(view.current, dt);
        dirty.current = true;
        if (now - lastDraw < TURNING_FRAME_MS) {
          raf = requestAnimationFrame(tick);
          return;
        }
      }
      lastDraw = now;
      const animating = draw(performance.now());
      if (turningNow || animating) raf = requestAnimationFrame(tick);
      else last = 0;
    };

    const schedule = () => {
      if (raf !== null || document.hidden) return;
      raf = requestAnimationFrame(tick);
    };
    kick.current = () => {
      dirty.current = true;
      schedule();
    };
    const visibility = () => {
      if (document.hidden) {
        if (raf !== null) cancelAnimationFrame(raf);
        raf = null;
        last = 0;
      } else schedule();
    };
    document.addEventListener("visibilitychange", visibility);
    schedule();
    return () => {
      document.removeEventListener("visibilitychange", visibility);
      if (raf !== null) cancelAnimationFrame(raf);
      kick.current = () => {};
    };
  }, [size]);

  const onPointerDown = (e: PointerEvent<HTMLButtonElement>) => {
    if (e.button !== 0) return;
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY };
    e.currentTarget.setPointerCapture?.(e.pointerId);
    setTurning(false);
  };
  const onPointerMove = (e: PointerEvent<HTMLButtonElement>) => {
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    d.x = e.clientX;
    d.y = e.clientY;
    view.current = dragView(view.current, dx, dy, model.current.size);
    kick.current();
  };
  const endDrag = (e: PointerEvent<HTMLButtonElement>) => {
    if (drag.current?.id === e.pointerId) drag.current = null;
    if (e.currentTarget.hasPointerCapture?.(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
  };
  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const next = keyView(view.current, e.key);
    if (!next) return;
    e.preventDefault();
    view.current = next;
    setTurning(false);
    kick.current();
  };

  const nameOf = (code: string) => countryName(code, i18n.language);
  const label =
    countries.length === 0
      ? t("attacks.globe.labelEmpty")
      : t(hasHome ? "attacks.globe.label" : "attacks.globe.labelNoHome", {
          top: topCountriesText(countries, nameOf),
        });
  const radius = size / 2;

  return (
    <div className="grid gap-3 px-5 pb-5" data-testid="attack-globe">
      {/* A button, so that it can have focus and the arrow keys can turn it; the picture inside has its own text alternative. */}
      <button
        ref={frame}
        type="button"
        aria-label={label}
        aria-describedby={hintId}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onKeyDown={onKeyDown}
        onFocus={() => {
          focused.current = true;
        }}
        onBlur={() => {
          focused.current = false;
          kick.current();
        }}
        className={cn(
          "grid w-full cursor-grab touch-pan-y place-items-center overflow-hidden rounded-lg border bg-card select-none active:cursor-grabbing",
          "aspect-[5/4] max-h-[70vh] min-h-72 @wide:aspect-auto @wide:h-[min(74vh,56rem)]",
          "focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
        )}
      >
        {size > 0 ? (
          <svg
            ref={svg}
            width={size}
            height={size}
            viewBox={`0 0 ${size} ${size}`}
            role="img"
            aria-label={label}
            className="block"
            data-rotation=""
            data-turning={turning && !reducedMotion ? "on" : "off"}
            data-arcs={arcs.length}
          >
            <title>{label}</title>
            <circle
              cx={radius}
              cy={radius}
              r={radius - 2}
              className="fill-card stroke-border"
              strokeWidth={1}
            />
            <path
              ref={(el) => {
                parts.current.graticule = el;
              }}
              className="fill-none stroke-border"
              strokeWidth={0.5}
              opacity={0.7}
            />
            <g>
              {FEATURES.map((item) => {
                const data = item.code ? byCode.get(item.code) : undefined;
                const step = data ? shadeStep(data.alerts, max) : 0;
                const active = !!item.code && selected === item.code;
                return (
                  <path
                    key={item.key}
                    ref={(el) => {
                      if (el) parts.current.land.set(item.key, el);
                      else parts.current.land.delete(item.key);
                    }}
                    data-country={item.code ?? undefined}
                    data-step={item.code ? step : undefined}
                    className={cn(MAP_FILL[step], active ? "stroke-foreground" : "stroke-card")}
                    strokeWidth={active ? 1.2 : 0.4}
                    strokeLinejoin="round"
                  >
                    {data && item.code ? (
                      <title>
                        {t("attacks.mapTooltip", {
                          country: nameOf(item.code),
                          alerts: data.alerts,
                          sources: data.sources,
                        })}
                      </title>
                    ) : null}
                  </path>
                );
              })}
            </g>
            <g>
              {arcs.map((arc) => (
                <g key={arc.key} data-arc={arc.key} data-tone={arc.tone} data-width={arc.width}>
                  {hasHome ? (
                    <path
                      ref={(el) => {
                        if (el) parts.current.lines.set(arc.key, el);
                        else parts.current.lines.delete(arc.key);
                      }}
                      fill="none"
                      strokeLinecap="round"
                      strokeWidth={arc.width}
                      opacity={0.85}
                      {...(arc.tone === "blocked" ? { strokeDasharray: BLOCKED_DASH } : {})}
                      className={ARC_STROKE[arc.tone]}
                    />
                  ) : null}
                  {arc.dot ? (
                    <circle
                      ref={(el) => {
                        if (el) parts.current.dots.set(arc.key, el);
                        else parts.current.dots.delete(arc.key);
                      }}
                      r={arc.radius}
                      visibility="hidden"
                      className={cn(POINT_FILL[arc.tone], "stroke-card")}
                      strokeWidth={1}
                    />
                  ) : null}
                </g>
              ))}
            </g>
            <g>
              {liveArcs.map((arc) => (
                <g key={arc.id} data-live-arc={arc.id} data-tone={arc.tone}>
                  {hasHome ? (
                    <path
                      ref={(el) => {
                        if (el) parts.current.liveLines.set(arc.id, el);
                        else parts.current.liveLines.delete(arc.id);
                      }}
                      fill="none"
                      strokeLinecap="round"
                      strokeWidth={LIVE_ARC_WIDTH}
                      {...(arc.tone === "blocked" ? { strokeDasharray: BLOCKED_DASH } : {})}
                      className={ARC_STROKE[arc.tone]}
                    />
                  ) : null}
                  <circle
                    ref={(el) => {
                      if (el) parts.current.liveDots.set(arc.id, el);
                      else parts.current.liveDots.delete(arc.id);
                    }}
                    r={4}
                    visibility="hidden"
                    className={cn(POINT_FILL[arc.tone], "stroke-card")}
                    strokeWidth={1}
                  />
                </g>
              ))}
            </g>
            <g
              ref={(el) => {
                parts.current.home = el;
              }}
              visibility="hidden"
              data-home=""
            >
              <title>{t("attacks.globe.homeTitle")}</title>
              <circle r={9} className="fill-none stroke-foreground" strokeWidth={1.5} />
              <circle r={4} className="fill-foreground stroke-card" strokeWidth={1} />
            </g>
          </svg>
        ) : null}
      </button>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
        <ul className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {osintEnabled ? (
            <li className="flex items-center gap-1.5">
              <span aria-hidden="true" className="h-0.5 w-5 rounded-full bg-chart-critical" />
              {t("attacks.globe.legendHigh")}
            </li>
          ) : null}
          <li className="flex items-center gap-1.5">
            <span aria-hidden="true" className="h-0.5 w-5 rounded-full bg-chart-high" />
            {t("attacks.globe.legendObserved")}
          </li>
          {hasBlocked ? (
            <li className="flex items-center gap-1.5" data-testid="legend-blocked">
              <svg aria-hidden="true" viewBox="0 0 20 4" className="h-1 w-5 flex-none">
                <line
                  x1="0"
                  y1="2"
                  x2="20"
                  y2="2"
                  strokeWidth={2}
                  strokeDasharray="5 3"
                  className="stroke-info"
                />
              </svg>
              {t("attacks.globe.legendBlocked")}
            </li>
          ) : null}
          {hasHome ? (
            <li className="flex items-center gap-1.5">
              <span aria-hidden="true" className="size-3 rounded-full border-2 border-foreground bg-card" />
              {t("attacks.globe.legendHome")}
            </li>
          ) : null}
        </ul>
        {hasHome ? <span>{t("attacks.globe.legendWidth")}</span> : null}
        {reducedMotion ? null : (
          <button
            type="button"
            onClick={() => setTurning(!turning)}
            className="ml-auto inline-flex h-8 items-center gap-1.5 rounded-md border border-input bg-card px-2.5 shadow-xs hover:bg-accent"
          >
            {turning ? (
              <Pause aria-hidden="true" className="size-3.5" />
            ) : (
              <Play aria-hidden="true" className="size-3.5" />
            )}
            {turning ? t("attacks.globe.pause") : t("attacks.globe.resume")}
          </button>
        )}
      </div>
      <MapLegend max={max} />
      <p id={hintId} className="text-sm text-muted-foreground">
        {t("attacks.globe.keys")}
      </p>
    </div>
  );
}
