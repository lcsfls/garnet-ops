import { useSyncExternalStore } from "react";

/** The layout steps of AGENTS.md rule 5, measured on the content area like the container queries. */
export type LayoutStep = "base" | "wide" | "xwide";
const WIDE = 1450;
const XWIDE = 1900;

function stepOf(width: number): LayoutStep {
  return width >= XWIDE ? "xwide" : width >= WIDE ? "wide" : "base";
}

function content(): Element | null {
  return typeof document === "undefined" ? null : document.querySelector("main[data-content]");
}

function subscribe(onChange: () => void): () => void {
  const element = content();
  if (!element || typeof ResizeObserver === "undefined") return () => {};
  const observer = new ResizeObserver(onChange);
  observer.observe(element);
  return () => observer.disconnect();
}

function snapshot(): LayoutStep {
  const element = content();
  return element ? stepOf(element.getBoundingClientRect().width) : "base";
}

/**
 * The current layout step of the content area, for decisions CSS cannot make alone
 * (e.g. which finding to show in the detail pane when there is room for it).
 */
export function useLayoutStep(): LayoutStep {
  return useSyncExternalStore(subscribe, snapshot, () => "base");
}
