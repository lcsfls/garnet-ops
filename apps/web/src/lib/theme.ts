import { useSyncExternalStore } from "react";

/**
 * Colour theme. "system" follows the operating system (the default); "light"
 * and "dark" are an explicit choice remembered in this browser. The choice is
 * applied as `data-theme` on <html>; styles.css holds the tokens for both.
 * No inline script runs before first paint (strict CSP), so a stored choice
 * that differs from the system takes effect when this module loads.
 */
export const THEMES = ["system", "light", "dark"] as const;
export type Theme = (typeof THEMES)[number];

const STORAGE_KEY = "garnetops.theme";
const media = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;
const listeners = new Set<() => void>();

function stored(): Theme {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return THEMES.find((t) => t === value) ?? "system";
  } catch {
    return "system";
  }
}

let current: Theme = stored();

function apply() {
  const root = document.documentElement;
  if (current === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", current);
}

export function getTheme(): Theme {
  return current;
}

/** The theme actually shown: the explicit choice, or what the system prefers. */
export function resolvedTheme(): "light" | "dark" {
  if (current !== "system") return current;
  return media?.matches ? "dark" : "light";
}

export function setTheme(theme: Theme): void {
  current = theme;
  try {
    if (theme === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Not persisted; the choice still applies until the page is reloaded.
  }
  apply();
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  media?.addEventListener("change", listener);
  return () => {
    listeners.delete(listener);
    media?.removeEventListener("change", listener);
  };
}

/** The chosen theme and the one shown, re-rendering when either changes. */
export function useTheme(): { theme: Theme; resolved: "light" | "dark" } {
  const theme = useSyncExternalStore(subscribe, getTheme);
  const resolved = useSyncExternalStore(subscribe, resolvedTheme);
  return { theme, resolved };
}

apply();
