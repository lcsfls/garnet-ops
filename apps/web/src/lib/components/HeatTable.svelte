<script lang="ts" generics="R">
  import type { Snippet } from "svelte";
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { heatStep, SEVERITY_META } from "../severity-meta.ts";

  type Severity = "critical" | "high" | "medium" | "low";
  /**
   * A table whose cells are shaded by their value: the severity of the cell decides the colour, its share of the largest value
   * of the same severity in this table the strength (so two critical findings are not paler than twelve low ones). Every cell
   * writes its number, so colour is never the only signal; a cell can link to the matching list.
   */
  let {
    caption,
    rows,
    columns,
    rowHeader,
    rowLabel,
    value,
    severityOf,
    hrefOf,
    cellLabel,
  }: {
    caption: string;
    rows: R[];
    columns: { key: string; label: string }[];
    rowHeader: string;
    rowLabel: Snippet<[R]>;
    value: (row: R, column: string) => number;
    severityOf: (row: R, column: string) => Severity;
    hrefOf?: (row: R, column: string) => string | null;
    cellLabel: (row: R, column: string, value: number) => string;
  } = $props();

  /** The largest value per severity in this table. */
  const max = $derived.by(() => {
    const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of rows)
      for (const c of columns) {
        const s = severityOf(r, c.key);
        out[s] = Math.max(out[s], value(r, c.key));
      }
    return out;
  });
</script>

<table class="w-full border-separate border-spacing-1 text-sm">
  <caption class="sr-only">{caption}</caption>
  <thead>
    <tr>
      <th scope="col" class="px-2 py-1 text-left font-medium text-muted-foreground">{rowHeader}</th>
      {#each columns as column (column.key)}
        <th scope="col" class="px-2 py-1 text-right font-medium text-muted-foreground">{column.label}</th>
      {/each}
    </tr>
  </thead>
  <tbody>
    {#each rows as row, i (i)}
      <tr>
        <th scope="row" class="max-w-[16rem] truncate px-2 py-1 text-left font-medium">{@render rowLabel(row)}</th>
        {#each columns as column (column.key)}
          {@const n = value(row, column.key)}
          {@const step = heatStep(n, max[severityOf(row, column.key)])}
          {@const link = n > 0 ? (hrefOf?.(row, column.key) ?? null) : null}
          <td
            class={cn(
              "rounded-md px-2 py-1.5 text-right tabular-nums",
              step === null ? "text-muted-foreground" : cn("font-semibold", SEVERITY_META[severityOf(row, column.key)].heat[step]),
            )}
          >
            {#if link}
              <a href={link} class="block hover:underline" aria-label={cellLabel(row, column.key, n)}>{formatNumber(n)}</a>
            {:else}
              <span aria-label={cellLabel(row, column.key, n)}>{n === 0 ? "–" : formatNumber(n)}</span>
            {/if}
          </td>
        {/each}
      </tr>
    {/each}
  </tbody>
</table>
