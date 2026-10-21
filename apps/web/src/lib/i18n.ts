import { type Language, type Messages, resolveLanguage, resources } from "@garnetops/i18n";
import i18n from "i18next";
import ICU from "i18next-icu";
import { initReactI18next } from "react-i18next";

declare module "i18next" {
  interface CustomTypeOptions {
    resources: { translation: Messages };
  }
}

type Leaves<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${P}${K}` : Leaves<T[K], `${P}${K}.`>;
}[keyof T & string];

/** Every translation key, e.g. "errors.generic". */
export type MessageKey = Leaves<Messages>;

const STORAGE_KEY = "garnetops.language";

/**
 * English unless the user picked another language in this browser. The
 * browser's own language setting is deliberately not used (AGENTS.md:
 * English is the primary language). Storage can be unavailable (private
 * mode, blocked site data); then English is used.
 */
function storedLanguage(): Language {
  try {
    return resolveLanguage(localStorage.getItem(STORAGE_KEY));
  } catch {
    return resolveLanguage(null);
  }
}

export async function setLanguage(language: Language): Promise<void> {
  try {
    localStorage.setItem(STORAGE_KEY, language);
  } catch {
    // Not persisted; the choice still applies until the page is reloaded.
  }
  document.documentElement.lang = language;
  await i18n.changeLanguage(language);
}

const language = storedLanguage();
document.documentElement.lang = language;

await i18n
  .use(ICU)
  .use(initReactI18next)
  .init({
    resources,
    lng: language,
    fallbackLng: "en",
    // React escapes everything it renders; double escaping would show entities.
    interpolation: { escapeValue: false },
  });

export { i18n };
