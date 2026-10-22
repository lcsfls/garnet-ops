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

const fill = (text: string, values: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (match, key: string) => (key in values ? String(values[key]) : match));

/**
 * The title and text of a personal notification in a language (ADR 0019): the web app's bell and
 * the personal mails both come through here. A notification stores only a key and short facts, so
 * the words are always the reader's own. Unknown keys (a newer server than this client) give a
 * neutral text. Parameter values are inserted as plain text, in a single pass.
 */
export function renderNotificationItem(
  language: Language,
  titleKey: string,
  params: Record<string, string | number>,
): { title: string; text: string } {
  const { items, roles, unknown } = resources[language].translation.inapp;
  const item = Object.hasOwn(items, titleKey) ? items[titleKey as keyof typeof items] : unknown;
  const role = typeof params.role === "string" && Object.hasOwn(roles, params.role) ? params.role : null;
  const values = { ...params, ...(role ? { role: roles[role as keyof typeof roles] } : {}) };
  return { title: fill(item.title, values), text: fill(item.text, values) };
}
