import { ChevronLeft, ChevronRight } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { PAGE_SIZES } from "../lib/search.ts";
import type { Page } from "../lib/types.ts";
import { Select } from "./ui/select.tsx";

/**
 * Cursor pagination (ROADMAP: clean pagination on every list): total count,
 * page size, previous and next. The position lives in the URL, so links and
 * the back button keep it.
 */
export function Pagination({
  page,
  onCursor,
  onPageSize,
}: {
  page: Pick<Page<unknown>, "total" | "pageSize" | "next" | "prev">;
  onCursor: (cursor: string | undefined) => void;
  onPageSize: (size: number) => void;
}) {
  const { t } = useTranslation();
  const sizeId = useId();
  const button =
    "grid size-9 place-items-center rounded-md border border-input bg-card shadow-xs hover:bg-accent disabled:pointer-events-none disabled:opacity-50";
  return (
    <nav
      aria-label={t("pagination.label")}
      className="flex flex-wrap items-center gap-3 border-t px-5 py-3 text-sm"
    >
      <span className="text-muted-foreground">{t("pagination.total", { count: page.total })}</span>
      <div className="ml-auto flex items-center gap-2 text-muted-foreground">
        <label htmlFor={sizeId}>{t("pagination.pageSize")}</label>
        <Select
          id={sizeId}
          value={page.pageSize}
          onChange={(e) => onPageSize(Number(e.target.value))}
          className="h-9 text-sm"
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </Select>
      </div>
      <button
        type="button"
        className={button}
        disabled={!page.prev}
        onClick={() => onCursor(page.prev ?? undefined)}
        aria-label={t("pagination.previous")}
      >
        <ChevronLeft aria-hidden="true" className="size-4" />
      </button>
      <button
        type="button"
        className={button}
        disabled={!page.next}
        onClick={() => onCursor(page.next ?? undefined)}
        aria-label={t("pagination.next")}
      >
        <ChevronRight aria-hidden="true" className="size-4" />
      </button>
    </nav>
  );
}
