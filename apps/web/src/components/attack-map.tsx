import { shadeStep } from "@garnetops/core/attacks";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { countryName, legendSteps, MAP_FILL, MAP_SWATCH } from "../lib/attacks.ts";
import { cn } from "../lib/cn.ts";
import { formatNumber } from "../lib/format.ts";

type WorldMap = typeof import("../assets/world-map.ts");

export interface MapCountry {
  country: string;
  alerts: number;
  sources: number;
}

/**
 * The world map of the Attacks page: plain SVG paths from Natural Earth (public domain), vendored
 * in the app (no tiles, no map library, no request). A country is filled by its alerts on a
 * single-hue scale of five steps (never a severity colour); countries without alerts stay grey.
 * The shapes are loaded in a separate chunk. The map is a picture for the eyes: the country list
 * beside it carries the same numbers as a table and is the keyboard and screen reader route, and
 * choosing a country there filters the address table. The map itself is a picture with tooltips.
 */
export function AttackMap({
  countries,
  selected,
}: {
  countries: MapCountry[];
  selected: string | undefined;
}) {
  const { t, i18n } = useTranslation();
  const [world, setWorld] = useState<WorldMap | null>(null);
  useEffect(() => {
    let live = true;
    void import("../assets/world-map.ts").then((m) => {
      if (live) setWorld(m);
    });
    return () => {
      live = false;
    };
  }, []);

  const byCode = useMemo(() => new Map(countries.map((c) => [c.country, c])), [countries]);
  const max = Math.max(1, ...countries.map((c) => c.alerts));
  const drawn = useMemo(() => new Set(world?.WORLD_COUNTRIES.map((c) => c.code) ?? []), [world]);
  const hidden = world ? countries.filter((c) => !drawn.has(c.country)).length : 0;
  const legend = legendSteps(max);

  return (
    <div className="grid gap-3 px-5 pb-5">
      <div className="relative w-full overflow-hidden rounded-lg border bg-card" data-testid="attack-map">
        {world ? (
          <svg
            viewBox={`0 0 ${world.WORLD_WIDTH} ${world.WORLD_HEIGHT}`}
            role="img"
            aria-label={t("attacks.mapLabel")}
            className="block h-auto w-full"
          >
            <title>{t("attacks.mapLabel")}</title>
            {world.WORLD_COUNTRIES.map((shape) => {
              const data = byCode.get(shape.code);
              const step = data ? shadeStep(data.alerts, max) : 0;
              const name = countryName(shape.code, i18n.language);
              const active = selected === shape.code;
              return (
                <path
                  key={shape.code}
                  d={shape.d}
                  data-country={shape.code}
                  data-step={step}
                  className={cn(MAP_FILL[step], active ? "stroke-foreground" : "stroke-card")}
                  strokeWidth={active ? 1.4 : 0.5}
                  strokeLinejoin="round"
                >
                  <title>
                    {data
                      ? t("attacks.mapTooltip", { country: name, alerts: data.alerts, sources: data.sources })
                      : name}
                  </title>
                </path>
              );
            })}
          </svg>
        ) : (
          <p role="status" className="grid aspect-[960/418] place-items-center text-muted-foreground">
            {t("attacks.mapLoading")}
          </p>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm text-muted-foreground">
        <span className="font-medium text-foreground">{t("attacks.legendTitle")}</span>
        <ul className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <li className="flex items-center gap-1.5">
            <span aria-hidden="true" className="size-3.5 rounded-sm border bg-border" />
            {t("attacks.legendNone")}
          </li>
          {legend.map(({ step, upTo }) => (
            <li key={step} className="flex items-center gap-1.5">
              <span aria-hidden="true" className={cn("size-3.5 rounded-sm", MAP_SWATCH[step])} />
              {t("attacks.legendUpTo", { count: formatNumber(upTo) })}
            </li>
          ))}
        </ul>
      </div>
      {hidden > 0 ? (
        <p className="text-sm text-muted-foreground">{t("attacks.mapNoShape", { count: hidden })}</p>
      ) : null}
    </div>
  );
}
