import { resolveLanguage } from "@garnetops/i18n";
import { i18n, setLanguage } from "./i18n.ts";
import { setPreferredTimeZone } from "./time-zone.ts";

let localeApplied = false;

/**
 * Applies the preferences stored on the user's account (ADR 0017). The time zone follows the
 * account at all times. The language is taken from the account once per page load, so a change
 * made in the menu is not undone by a navigation; the menu and the account page save every
 * change they make.
 */
export async function applyPreferences(preferences: { locale: string | null; timeZone: string | null }) {
  setPreferredTimeZone(preferences.timeZone);
  if (localeApplied) return;
  localeApplied = true;
  if (preferences.locale && resolveLanguage(preferences.locale) !== i18n.language) {
    await setLanguage(resolveLanguage(preferences.locale));
  }
}
