import { Link, type LinkProps } from "@tanstack/react-router";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { formatNumber } from "../lib/format.ts";

export interface BarSeries<K extends string> {
  key: K;
  label: string;
  /** Tailwind fill class of the bars, e.g. "fill-chart-critical". */
  fill: string;
  /** Tailwind background class of the legend swatch, e.g. "bg-chart-critical". */
  swatch: string;
  /** Where the legend entry leads: the list behind the series. */
  link?: Pick<LinkProps, "to" | "search">;
}

export interface BarBucket<K extends string> {
  key: string;
  /** The bucket in words: a day, or the days of a week. */
  label: string;
  values: Record<K, number>;
}

/**
 * Bars per day or week: stacked (parts of one whole, such as open findings by severity) or
 * grouped (two counts side by side, such as found and resolved). Each bucket names its days and
 * counts on hover, the legend names every series with its total (or last value) and links to
 * the list behind it, and the same numbers are available as a table, so nothing depends on
 * colour or on hovering alone.
 */
export function BarChart<K extends string>({
  buckets,
  series,
  mode,
  summary,
  legendValue = "total",
}: {
  buckets: BarBucket<K>[];
  series: BarSeries<K>[];
  mode: "stacked" | "grouped";
  /** One sentence for screen readers: what the chart shows and its main result. */
  summary: string;
  /** What the legend shows next to each series: the sum over all buckets or the last bucket's value. */
  legendValue?: "total" | "last";
}) {
  const { t } = useTranslation();
  const titleId = useId();
  const W = 600;
  const H = 160;
  const gap = buckets.length > 40 ? 2 : 4;
  const slot = (W - gap * (buckets.length - 1)) / Math.max(buckets.length, 1);
  const sumOf = (b: BarBucket<K>) => series.reduce((s, x) => s + b.values[x.key], 0);
  const max = Math.max(
    1,
    ...buckets.map((b) => (mode === "stacked" ? sumOf(b) : Math.max(...series.map((x) => b.values[x.key])))),
  );
  const legend = (key: K) =>
    legendValue === "last"
      ? (buckets.at(-1)?.values[key] ?? 0)
      : buckets.reduce((s, b) => s + b.values[key], 0);
  const first = buckets[0];
  const last = buckets.at(-1);

  return (
    <div>
      <div className="flex items-baseline justify-between text-xs text-muted-foreground tabular-nums">
        <span>{formatNumber(max)}</span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-labelledby={titleId}
        className="block h-44 w-full border-b border-border"
      >
        <title id={titleId}>{summary}</title>
        {buckets.map((b, i) => {
          const x0 = i * (slot + gap);
          let y = H;
          return (
            <g key={b.key}>
              <title>{`${b.label}: ${series.map((s) => `${formatNumber(b.values[s.key])} ${s.label}`).join(", ")}`}</title>
              {/* An invisible full-height bar, so hovering a quiet bucket still shows its numbers. */}
              <rect x={x0} y={0} width={slot} height={H} className="fill-transparent" />
              {mode === "stacked"
                ? [...series].reverse().map((s) => {
                    const h = (b.values[s.key] / max) * (H - 4);
                    y -= h;
                    return h > 0 ? (
                      <rect
                        key={s.key}
                        x={x0}
                        y={y}
                        width={slot}
                        height={Math.max(0, h - 1)}
                        rx={1.5}
                        className={s.fill}
                      />
                    ) : null;
                  })
                : series.map((s, j) => {
                    const w = (slot - 1) / series.length;
                    const h = (b.values[s.key] / max) * (H - 4);
                    return h > 0 ? (
                      <rect
                        key={s.key}
                        x={x0 + j * (w + 1)}
                        y={H - h}
                        width={w}
                        height={h}
                        rx={1.5}
                        className={s.fill}
                      />
                    ) : null;
                  })}
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex justify-between gap-4 text-xs text-muted-foreground">
        <span>{first?.label}</span>
        <span>{last?.label}</span>
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
        {series.map((s) => {
          const content = (
            <>
              <span aria-hidden="true" className={`size-2.5 rounded-sm ${s.swatch}`} />
              {s.label}
              <span className="text-foreground tabular-nums">{formatNumber(legend(s.key))}</span>
            </>
          );
          return (
            <li key={s.key}>
              {s.link ? (
                <Link
                  {...(s.link as LinkProps)}
                  className="inline-flex items-center gap-1.5 hover:text-foreground hover:underline"
                >
                  {content}
                </Link>
              ) : (
                <span className="inline-flex items-center gap-1.5">{content}</span>
              )}
            </li>
          );
        })}
      </ul>
      <details className="mt-2 text-sm">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
          {t("statistics.showTable")}
        </summary>
        <div className="mt-2 max-h-72 overflow-auto">
          <table className="w-full text-left tabular-nums">
            <thead className="text-muted-foreground">
              <tr>
                <th scope="col" className="py-1 pr-3 font-normal">
                  {t("statistics.period")}
                </th>
                {series.map((s) => (
                  <th key={s.key} scope="col" className="py-1 pr-3 text-right font-normal">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {buckets.map((b) => (
                <tr key={b.key} className="border-t">
                  <th scope="row" className="py-1 pr-3 font-normal">
                    {b.label}
                  </th>
                  {series.map((s) => (
                    <td key={s.key} className="py-1 pr-3 text-right">
                      {formatNumber(b.values[s.key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
