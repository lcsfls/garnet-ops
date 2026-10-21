import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";

export type SortDir = "asc" | "desc";

/**
 * A column header that sorts the list (aria-sort on the cell). The first click sorts
 * in the column's natural direction (scores and dates newest/highest first, names A–Z),
 * the second click reverses it, the third returns to the list's default order.
 */
export function SortHeader({
  column,
  label,
  current,
  dir,
  natural,
  onSort,
  className,
  align = "left",
}: {
  column: string;
  label: ReactNode;
  current: string | undefined;
  dir: SortDir | undefined;
  natural: SortDir;
  onSort: (sort: string | undefined, dir: SortDir | undefined) => void;
  className?: string;
  align?: "left" | "right";
}) {
  const { t } = useTranslation();
  const active = current === column;
  const shown: SortDir = active ? (dir ?? natural) : natural;
  const Icon = active ? (shown === "asc" ? ArrowUp : ArrowDown) : ArrowUpDown;
  const next = () => {
    if (!active) return onSort(column, undefined);
    if ((dir ?? natural) === natural) return onSort(column, natural === "asc" ? "desc" : "asc");
    onSort(undefined, undefined);
  };
  return (
    <th
      aria-sort={active ? (shown === "asc" ? "ascending" : "descending") : "none"}
      className={cn("py-2.5 font-medium", align === "right" && "text-right", className)}
    >
      <button
        type="button"
        onClick={next}
        title={t("common.sortBy")}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm hover:text-foreground",
          active && "text-foreground",
          align === "right" && "flex-row-reverse",
        )}
      >
        {label}
        <Icon aria-hidden="true" className={cn("size-3.5", !active && "opacity-50")} />
      </button>
    </th>
  );
}
