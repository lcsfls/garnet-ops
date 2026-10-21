import { Link } from "@tanstack/react-router";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { formatCalendarDate, formatNumber } from "../lib/format.ts";
import { TREND_SEVERITIES, type TrendDay, type TrendSeverity } from "../lib/trend.ts";

const FILL: Record<TrendSeverity, string> = {
  critical: "fill-chart-critical",
  high: "fill-chart-high",
  medium: "fill-chart-medium",
  low: "fill-chart-low",
};
const SWATCH: Record<TrendSeverity, string> = {
  critical: "bg-chart-critical",
  high: "bg-chart-high",
  medium: "bg-chart-medium",
  low: "bg-chart-low",
};

const total = (d: TrendDay) => TREND_SEVERITIES.reduce((sum, s) => sum + d[s], 0);

/**
 * Stacked bars of open findings per day. Each bar names its day and counts
 * on hover; the legend links to the matching findings, so the chart leads
 * somewhere like every other figure on the overview.
 */
export function TrendChart({ days, repositoryId }: { days: TrendDay[]; repositoryId?: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const W = 600;
  const H = 160;
  const gap = 4;
  const barWidth = (W - gap * (days.length - 1)) / days.length;
  const max = Math.max(1, ...days.map(total));
  const first = days[0];
  const last = days[days.length - 1];

  return (
    <div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-labelledby={titleId}
        className="block h-44 w-full"
      >
        <title id={titleId}>
          {t("overview.trendSummary", {
            first: first ? formatCalendarDate(first.day) : "",
            firstCount: first ? total(first) : 0,
            last: last ? formatCalendarDate(last.day) : "",
            lastCount: last ? total(last) : 0,
          })}
        </title>
        {days.map((d, i) => {
          let y = H;
          return (
            <g key={d.day}>
              <title>
                {`${formatCalendarDate(d.day)}: ${TREND_SEVERITIES.map(
                  (s) => `${formatNumber(d[s])} ${t(`severity.${s}`)}`,
                ).join(", ")}`}
              </title>
              {/* An invisible full-height bar, so hovering a quiet day still shows its numbers. */}
              <rect x={i * (barWidth + gap)} y={0} width={barWidth} height={H} className="fill-transparent" />
              {[...TREND_SEVERITIES].reverse().map((s) => {
                const h = (d[s] / max) * (H - 4);
                y -= h;
                return h > 0 ? (
                  <rect
                    key={s}
                    x={i * (barWidth + gap)}
                    y={y}
                    width={barWidth}
                    height={Math.max(0, h - 1)}
                    rx={1.5}
                    className={FILL[s]}
                  />
                ) : null;
              })}
            </g>
          );
        })}
      </svg>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
        {TREND_SEVERITIES.map((s) => (
          <li key={s}>
            <Link
              to="/findings"
              search={{ severity: s, repositoryId }}
              className="inline-flex items-center gap-1.5 hover:text-foreground hover:underline"
            >
              <span aria-hidden="true" className={`size-2.5 rounded-sm ${SWATCH[s]}`} />
              {t(`severity.${s}`)}
              <span className="text-foreground">{last ? formatNumber(last[s]) : 0}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
