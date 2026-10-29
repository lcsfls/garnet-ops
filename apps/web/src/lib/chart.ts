/** Geometry of the time charts (TimeChart.svelte): axis values and column outlines. */

/** Clean axis values from 0 up to at least `max`: steps of 1, 2 or 5 times a power of ten, whole numbers only. */
export function niceTicks(max: number): number[] {
  if (max <= 0) return [0, 1];
  const raw = max / 3;
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(1, [1, 2, 5, 10].map((m) => m * power).find((s) => s >= raw) ?? 10 * power);
  const ticks = [0];
  while ((ticks.at(-1) ?? 0) < max) ticks.push((ticks.at(-1) ?? 0) + step);
  return ticks;
}

/** A column with square corners at the baseline and 4px rounded corners at its data end. */
export function columnPath(
  x: number,
  top: number,
  bottom: number,
  w: number,
  round: "top" | "bottom" | null,
) {
  const h = bottom - top;
  const r = round ? Math.max(0, Math.min(4, w / 2, h)) : 0;
  if (round === "bottom") {
    return `M${x},${top}h${w}v${h - r}a${r},${r} 0 0 1 ${-r},${r}h${-(w - 2 * r)}a${r},${r} 0 0 1 ${-r},${-r}Z`;
  }
  return `M${x},${bottom}v${-(h - r)}a${r},${r} 0 0 1 ${r},${-r}h${w - 2 * r}a${r},${r} 0 0 1 ${r},${r}v${h - r}Z`;
}
