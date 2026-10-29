<script lang="ts">
  /**
   * The shape of a figure over its range, as a 2px line under the number. Decorative: the numbers behind it
   * are in the charts and their tables. A gap (null) is a bucket without a value, such as a day without gate
   * runs.
   */
  let { values }: { values: (number | null)[] } = $props();

  const W = 100;
  const H = 24;
  const known = $derived(values.filter((v): v is number => v !== null));
  const min = $derived(Math.min(0, ...known));
  const max = $derived(Math.max(min + 1, ...known));
  const step = $derived(values.length > 1 ? W / (values.length - 1) : 0);

  /** One path with a move at every gap, so a missing value breaks the line instead of joining across it. */
  const d = $derived(
    values
      .map((v, i) => {
        if (v === null) return "";
        const at = `${i * step},${H - 1 - ((v - min) / (max - min)) * (H - 2)}`;
        return i === 0 || values[i - 1] === null ? `M${at}` : `L${at}`;
      })
      .join(""),
  );
</script>

{#if known.length > 1}
  <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true" class="mt-2 block h-6 w-full">
    <path
      {d}
      fill="none"
      class="stroke-muted-foreground/70"
      stroke-width="2"
      stroke-linejoin="round"
      stroke-linecap="round"
      vector-effect="non-scaling-stroke"
    />
  </svg>
{/if}
