/**
 * The light-theme fill colours of the four severities (AGENTS.md rule 6: critical vermilion, high orange, medium amber, low
 * grey), as sRGB hex. They are the values of `--critical-fill` and its siblings in apps/web/src/app.css; the web app's
 * contrast test (apps/web/src/lib/contrast.test.ts) checks that both stay equal, so a PDF report and the app cannot drift.
 * The PDF draws its severity squares in these colours on white paper.
 */
export const SEVERITY_FILL_HEX = {
  critical: "#c1291b",
  high: "#ef852e",
  medium: "#f6c53c",
  low: "#8f8882",
} as const satisfies Record<"critical" | "high" | "medium" | "low", `#${string}`>;

/** A hex colour as the three 0 to 1 components a PDF colour operator takes, e.g. "0.76 0.16 0.11". */
export function pdfRgb(hex: string): string {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) throw new Error(`not a six-digit hex colour: ${hex}`);
  return m
    .slice(1)
    .map((c) => (Number.parseInt(c, 16) / 255).toFixed(3).replace(/0+$/, "").replace(/\.$/, ""))
    .join(" ");
}
