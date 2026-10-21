import { de } from "./de.ts";
import { en, type Messages } from "./en.ts";

export type { Messages };
export const LANGUAGES = ["en", "de"] as const;
export type Language = (typeof LANGUAGES)[number];

/**
 * English is the product's primary language (AGENTS.md). It is the default for
 * everyone, whatever the browser is set to; other languages are an explicit
 * choice of the user.
 */
export const DEFAULT_LANGUAGE: Language = "en";

/** Each language's own name, shown in the language picker untranslated. */
export const LANGUAGE_NAMES: Record<Language, string> = { en: "English", de: "Deutsch" };

export const resources: Record<Language, { translation: Messages }> = {
  en: { translation: en },
  de: { translation: de },
};

/** The user's explicit choice if it is a supported language, otherwise English. */
export function resolveLanguage(chosen: string | null | undefined): Language {
  return LANGUAGES.find((l) => l === chosen) ?? DEFAULT_LANGUAGE;
}
