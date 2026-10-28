<script lang="ts" generics="T extends string">
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";

  /**
   * A row of toggle buttons for one filter value (e.g. finding state). An option may carry a count: a number, or null
   * while it loads (a dash keeps the room for it, so the row does not jump when the numbers arrive).
   */
  let {
    label,
    value,
    options,
    onChange,
  }: {
    label: string;
    value: T;
    options: { value: T; label: string; count?: number | null }[];
    onChange: (value: T) => void;
  } = $props();
</script>

<!-- Wraps instead of running past the content area when there are many options (the audit log has 15). -->
<fieldset class="inline-flex max-w-full flex-wrap gap-0.5 rounded-lg bg-muted p-[3px]">
  <legend class="sr-only">{label}</legend>
  {#each options as o (o.value)}
    <button
      type="button"
      aria-pressed={o.value === value}
      onclick={() => onChange(o.value)}
      class={cn(
        "h-8 rounded-md px-3 text-sm whitespace-nowrap",
        o.value === value ? "bg-card font-medium text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
      )}
    >
      {o.label}
      {#if o.count !== undefined}
        <span class="ml-1.5 inline-block min-w-[2ch] text-left tabular-nums"
          >{o.count === null ? "–" : formatNumber(o.count)}</span
        >
      {/if}
    </button>
  {/each}
</fieldset>
