import { Link, type LinkProps } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { formatNumber } from "../lib/format.ts";

/**
 * A key figure that links to the list explaining it (mockup .kpi): label and icon,
 * the number, then at most a change and a hint in small muted text.
 */
export function Tile({
  label,
  icon,
  value,
  display,
  delta,
  hint,
  to,
  search,
}: {
  label: string;
  icon?: ReactNode;
  value: number;
  /** The value as text when a plain number does not fit, e.g. a percentage. */
  display?: string;
  delta?: ReactNode;
  hint?: ReactNode;
  to: "/findings" | "/repositories" | "/gates" | "/fixes";
  search: LinkProps["search"];
}) {
  return (
    <Link
      to={to}
      search={search}
      className="block rounded-xl border bg-card px-[18px] py-4 shadow-xs transition-colors hover:border-primary/40"
    >
      <div className="flex items-center justify-between gap-2 text-[15px] text-muted-foreground">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-1.5 text-[28px] leading-tight font-semibold tracking-[-0.02em]">
        {display ?? formatNumber(value)}
      </div>
      {delta ? <div className="text-[13px] text-muted-foreground">{delta}</div> : null}
      {hint ? <div className="mt-0.5 text-[13px] text-muted-foreground">{hint}</div> : null}
    </Link>
  );
}
