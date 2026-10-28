import { type Language, type Messages, resolveLanguage, resources } from "@garnetops/i18n";
import i18next from "i18next";
import ICU from "i18next-icu";

type Leaves<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${P}${K}` : Leaves<T[K], `${P}${K}.`>;
}[keyof T & string];

/** Every translation key, e.g. "errors.generic". */
export type MessageKey = Leaves<Messages>;

const STORAGE_KEY = "garnetops.language";

/**
 * English unless the user picked another language in this browser. The browser's own language setting is deliberately
 * not used (AGENTS.md: English is the primary language). Storage can be unavailable (private mode, blocked site data);
 * then English is used.
 */
function storedLanguage(): Language {
  try {
    return resolveLanguage(localStorage.getItem(STORAGE_KEY));
  } catch {
    return resolveLanguage(null);
  }
}

const initial = storedLanguage();
document.documentElement.lang = initial;

export const i18n = i18next.createInstance();
i18n.use(ICU).init({
  resources,
  lng: initial,
  fallbackLng: "en",
  // The resources are in the bundle, so initialisation finishes synchronously.
  initAsync: false,
  // Svelte escapes everything it renders; double escaping would show entities.
  interpolation: { escapeValue: false },
});

/** The language shown; reading it inside a component makes the component follow a change. */
let current = $state<Language>(initial);

export function language(): Language {
  return current;
}

export async function setLanguage(next: Language): Promise<void> {
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Not persisted; the choice still applies until the page is reloaded.
  }
  document.documentElement.lang = next;
  await i18n.changeLanguage(next);
  current = next;
}

/**
 * Translates a key with ICU parameters. Reading `current` ties every text on screen to the language, so a language
 * change re-renders exactly the texts, as `useTranslation` did in the React app.
 */
export function t(key: MessageKey, params?: Record<string, unknown>): string {
  void current;
  return i18n.t(key as never, params as never) as unknown as string;
}

/** Whether a key exists, for texts chosen at run time (e.g. a server's error code). */
export function hasKey(key: string): boolean {
  void current;
  return i18n.exists(key);
}
