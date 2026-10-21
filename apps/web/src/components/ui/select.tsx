import { ChevronDown } from "lucide-react";
import type { SelectHTMLAttributes } from "react";
import { cn } from "../../lib/cn.ts";

/**
 * Native select with the look of the inputs and our own chevron. The open
 * option list stays the operating system's, which keeps keyboard, touch and
 * screen-reader behaviour reliable.
 */
export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <span className={cn("relative inline-flex h-10 text-base", className)}>
      <select
        className="h-full w-full appearance-none truncate rounded-md border border-input bg-card py-0 pr-9 pl-3 text-[length:inherit] shadow-xs hover:bg-accent"
        {...props}
      />
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted-foreground"
      />
    </span>
  );
}
