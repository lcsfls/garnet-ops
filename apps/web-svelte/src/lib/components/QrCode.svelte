<script lang="ts">
  import { encode } from "uqr";

  /**
   * QR code rendered locally as SVG elements. The TOTP secret never leaves the browser for a third-party QR service, and
   * no raw SVG string is injected.
   */
  let { value, label }: { value: string; label: string } = $props();
  const code = $derived(encode(value, { ecc: "M", border: 2 }));
  const d = $derived.by(() => {
    let path = "";
    code.data.forEach((row, y) => {
      row.forEach((on, x) => {
        if (on) path += `M${x} ${y}h1v1h-1z`;
      });
    });
    return path;
  });
</script>

<!-- Always dark on white: authenticator apps read inverted codes poorly. -->
<svg viewBox="0 0 {code.size} {code.size}" role="img" aria-label={label} class="size-48 rounded-md bg-white">
  <path {d} fill="#000" shape-rendering="crispEdges" />
</svg>
