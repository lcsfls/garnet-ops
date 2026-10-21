import { encode } from "uqr";

/**
 * QR code rendered locally as SVG elements. The TOTP secret never leaves the
 * browser for a third-party QR service, and no raw SVG string is injected.
 */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { data, size } = encode(value, { ecc: "M", border: 2 });
  let d = "";
  data.forEach((row, y) => {
    row.forEach((on, x) => {
      if (on) d += `M${x} ${y}h1v1h-1z`;
    });
  });
  return (
    // Always dark on white: authenticator apps read inverted codes poorly.
    <svg
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={label}
      className="size-48 rounded-md bg-white"
    >
      <path d={d} fill="#000" shapeRendering="crispEdges" />
    </svg>
  );
}
