import { createSubscriber } from "svelte/reactivity";

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

const subscribe = createSubscriber((update) => {
  if (typeof ResizeObserver === "undefined") return;
  // A page reads the step while it is being built, before the content area is in the document; wait for it, then
  // follow its size (the observer reports the first size right away).
  let observer: ResizeObserver | undefined;
  let frame = 0;
  const attach = () => {
    const element = content();
    if (!element) {
      frame = requestAnimationFrame(attach);
      return;
    }
    observer = new ResizeObserver(update);
    observer.observe(element);
  };
  attach();
  return () => {
    cancelAnimationFrame(frame);
    observer?.disconnect();
  };
});

/**
 * The current layout step of the content area, for decisions CSS cannot make alone (e.g. which finding to show in the
 * detail pane when there is room for it). Reading it inside an effect or template follows resizes.
 */
export function layoutStep(): LayoutStep {
  subscribe();
  const element = content();
  return element ? stepOf(element.getBoundingClientRect().width) : "base";
}
