/**
 * Colour theme. "system" follows the operating system (the default); "light" and "dark" are an explicit choice
 * remembered in this browser. The choice is applied as `data-theme` on <html>; app.css holds the tokens for both.
 * No inline script runs before first paint (strict CSP), so a stored choice that differs from the system takes effect
 * when this module loads.
 */
export const THEMES = ["system", "light", "dark"] as const;
export type Theme = (typeof THEMES)[number];

const STORAGE_KEY = "garnetops.theme";
const media = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;

function stored(): Theme {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return THEMES.find((t) => t === value) ?? "system";
  } catch {
    return "system";
  }
}

let current = $state<Theme>(stored());
let systemDark = $state(media?.matches ?? false);
media?.addEventListener("change", (event) => {
  systemDark = event.matches;
});

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
  return systemDark ? "dark" : "light";
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
}

apply();
