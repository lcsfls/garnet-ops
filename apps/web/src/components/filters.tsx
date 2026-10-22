import { Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cn } from "../lib/cn.ts";
import { formatNumber } from "../lib/format.ts";

/**
 * A row of toggle buttons for one filter value (e.g. finding state). An
 * option may carry a count: a number, or null while it loads (a dash keeps
 * the room for it, so the row does not jump when the numbers arrive).
 */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string; count?: number | null }[];
  onChange: (value: T) => void;
}) {
  return (
    // Wraps instead of running past the content area when there are many options (the audit log has 15).
    <fieldset className="inline-flex max-w-full flex-wrap gap-0.5 rounded-lg bg-muted p-[3px]">
      <legend className="sr-only">{label}</legend>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          onClick={() => onChange(o.value)}
          className={cn(
            "h-8 rounded-md px-3 text-sm whitespace-nowrap",
            o.value === value
              ? "bg-card font-medium text-foreground shadow-xs"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
          {o.count !== undefined ? (
            <span className="ml-1.5 inline-block min-w-[2ch] text-left tabular-nums">
              {o.count === null ? "–" : formatNumber(o.count)}
            </span>
          ) : null}
        </button>
      ))}
    </fieldset>
  );
}

/** Text filter that writes to the URL after a short pause, not on every keystroke. */
export function SearchInput({
  label,
  value,
  onChange,
  className,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  className?: string;
}) {
  const [draft, setDraft] = useState(value);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => setDraft(value), [value]);
  useEffect(() => {
    if (draft.trim() === value) return;
    const timer = setTimeout(() => onChangeRef.current(draft.trim()), 300);
    return () => clearTimeout(timer);
  }, [draft, value]);

  return (
    <div className={cn("relative w-full max-w-[280px]", className)}>
      <Search
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
      />
      <input
        type="search"
        aria-label={label}
        placeholder={label}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        className="h-10 w-full rounded-lg border border-input bg-card pr-3 pl-8 text-base shadow-xs placeholder:text-muted-foreground"
      />
    </div>
  );
}
