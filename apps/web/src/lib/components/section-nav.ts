import { cn } from "../cn.ts";

/** Class of a section link; the current one is marked with `aria-current` by the caller. */
export const sectionLinkClass = (current: boolean) =>
  cn("flex h-9 items-center rounded-md px-2.5", current ? "bg-muted font-medium" : "hover:bg-accent");
