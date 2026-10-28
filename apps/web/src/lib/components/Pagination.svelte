<script lang="ts">
  import { ChevronLeft, ChevronRight } from "@lucide/svelte";
  import { t } from "../i18n.svelte.ts";
  import { PAGE_SIZES } from "../search.ts";
  import type { Page } from "../types.ts";
  import Select from "./ui/Select.svelte";

  /**
   * Cursor pagination (ROADMAP: clean pagination on every list): total count, page size, previous and next. The position
   * lives in the URL, so links and the back button keep it.
   */
  let {
    page,
    onCursor,
    onPageSize,
  }: {
    page: Pick<Page<unknown>, "total" | "pageSize" | "next" | "prev">;
    onCursor: (cursor: string | undefined) => void;
    onPageSize: (size: number) => void;
  } = $props();
  const sizeId = $props.id();
  const button =
    "grid size-9 place-items-center rounded-md border border-input bg-card shadow-xs hover:bg-accent disabled:pointer-events-none disabled:opacity-50";
</script>

<nav aria-label={t("pagination.label")} class="flex flex-wrap items-center gap-3 border-t px-5 py-3 text-sm">
  <span class="text-muted-foreground">{t("pagination.total", { count: page.total })}</span>
  <div class="ml-auto flex items-center gap-2 text-muted-foreground">
    <label for={sizeId}>{t("pagination.pageSize")}</label>
    <Select
      id={sizeId}
      value={page.pageSize}
      onchange={(e) => onPageSize(Number(e.currentTarget.value))}
      class="h-9 text-sm"
    >
      {#each PAGE_SIZES as size (size)}<option value={size}>{size}</option>{/each}
    </Select>
  </div>
  <button
    type="button"
    class={button}
    disabled={!page.prev}
    onclick={() => onCursor(page.prev ?? undefined)}
    aria-label={t("pagination.previous")}
  >
    <ChevronLeft aria-hidden="true" class="size-4" />
  </button>
  <button
    type="button"
    class={button}
    disabled={!page.next}
    onclick={() => onCursor(page.next ?? undefined)}
    aria-label={t("pagination.next")}
  >
    <ChevronRight aria-hidden="true" class="size-4" />
  </button>
</nav>
