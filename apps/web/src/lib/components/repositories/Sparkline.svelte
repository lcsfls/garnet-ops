<script lang="ts">
  /**
   * A small line of daily values (mockup: open findings over 14 days). Neutral colour:
   * it shows a direction, not a judgement. The numbers are in the accessible label.
   */
  let { values, label }: { values: number[]; label: string } = $props();
  const width = 120;
  const height = 26;
  const points = $derived.by(() => {
    const max = Math.max(5, ...values);
    return values
      .map(
        (v, i) =>
          `${((i * width) / (values.length - 1)).toFixed(1)},${(height - 3 - (v / max) * (height - 6)).toFixed(1)}`,
      )
      .join(" ");
  });
</script>

{#if values.length >= 2}
  <svg role="img" aria-label={label} viewBox="0 0 {width} {height}" {width} {height}>
    <polyline {points} fill="none" class="stroke-muted-foreground" stroke-width="1.5" stroke-linejoin="round" />
  </svg>
{/if}
