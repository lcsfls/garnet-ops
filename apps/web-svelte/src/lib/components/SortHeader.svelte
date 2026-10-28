<script lang="ts" module>
  export type SortDir = "asc" | "desc";
</script>

<script lang="ts">
  import { ArrowDown, ArrowUp, ArrowUpDown } from "@lucide/svelte";
  import type { Snippet } from "svelte";
  import { cn } from "../cn.ts";
  import { t } from "../i18n.svelte.ts";

  /**
   * A column header that sorts the list (aria-sort on the cell). The first click sorts in the column's natural direction
   * (scores and dates newest/highest first, names A–Z), the second click reverses it, the third returns to the list's
   * default order.
   */
  let {
    column,
    label,
    current,
    dir,
    natural,
    onSort,
    class: className,
    align = "left",
  }: {
    column: string;
    label: string | Snippet;
    current: string | undefined;
    dir: SortDir | undefined;
    natural: SortDir;
    onSort: (sort: string | undefined, dir: SortDir | undefined) => void;
    class?: string;
    align?: "left" | "right";
  } = $props();

  const active = $derived(current === column);
  const shown: SortDir = $derived(active ? (dir ?? natural) : natural);
  const Icon = $derived(active ? (shown === "asc" ? ArrowUp : ArrowDown) : ArrowUpDown);
  function next() {
    if (!active) return onSort(column, undefined);
    if ((dir ?? natural) === natural) return onSort(column, natural === "asc" ? "desc" : "asc");
    onSort(undefined, undefined);
  }
</script>

<th
  aria-sort={active ? (shown === "asc" ? "ascending" : "descending") : "none"}
  class={cn("py-2.5 font-medium", align === "right" && "text-right", className)}
>
  <button
    type="button"
    onclick={next}
    title={t("common.sortBy")}
    class={cn(
      "inline-flex items-center gap-1 rounded-sm hover:text-foreground",
      active && "text-foreground",
      align === "right" && "flex-row-reverse",
    )}
  >
    {#if typeof label === "string"}{label}{:else}{@render label()}{/if}
    <Icon aria-hidden="true" class={cn("size-3.5", !active && "opacity-50")} />
  </button>
</th>
