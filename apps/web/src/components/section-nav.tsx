import type { ReactNode } from "react";
import { cn } from "../lib/cn.ts";

/**
 * The list of sections of a page with sections (Settings, Account). Narrow content shows the
 * sections as a wrapping row above the form; from 48 rem of content width they are a column on
 * the left (AGENTS.md rule 5, measured on the content area).
 */
export function SectionNav({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <nav aria-label={label} className={cn("@3xl:sticky @3xl:top-0", className)}>
      <ul className="flex flex-wrap gap-1 @3xl:grid @3xl:gap-0.5">{children}</ul>
    </nav>
  );
}

/** Class of a section link; the current one is marked with `aria-current` by the caller. */
export const sectionLinkClass = (current: boolean) =>
  cn("flex h-9 items-center rounded-md px-2.5", current ? "bg-muted font-medium" : "hover:bg-accent");
