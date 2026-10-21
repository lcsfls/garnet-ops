/**
 * A small line of daily values (mockup: open findings over 14 days). Neutral colour:
 * it shows a direction, not a judgement. The numbers are in the accessible label.
 */
export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const width = 120;
  const height = 26;
  if (values.length < 2) return null;
  const max = Math.max(5, ...values);
  const points = values
    .map(
      (v, i) =>
        `${((i * width) / (values.length - 1)).toFixed(1)},${(height - 3 - (v / max) * (height - 6)).toFixed(1)}`,
    )
    .join(" ");
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${width} ${height}`} width={width} height={height}>
      <polyline
        points={points}
        fill="none"
        className="stroke-muted-foreground"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}
