/**
 * Pure rules of the account page (ADR 0017): which second factors may go, the shape of the
 * preferences, and a short description of a browser for the list of sessions.
 */

/**
 * A second factor is mandatory for every account (AGENTS.md rule 1), so the last one can never
 * be removed. The authenticator app is a factor only while it is enrolled; every passkey is one.
 * (A passkey registered with user verification counts as a full second factor on its own.)
 */
export function mayRemovePasskey(factors: { totpEnrolled: boolean; passkeys: number }): boolean {
  const remaining = (factors.totpEnrolled ? 1 : 0) + Math.max(0, factors.passkeys - 1);
  return factors.passkeys > 0 && remaining >= 1;
}

/** Languages a user can prefer; the same list the web app ships. */
export const PREFERRED_LANGUAGES = ["en", "de"] as const;
export type PreferredLanguage = (typeof PREFERRED_LANGUAGES)[number];

/** Whether `zone` is an IANA time zone this runtime knows (e.g. "Europe/Berlin", "UTC"). */
export function isTimeZone(zone: string): boolean {
  if (zone.length === 0 || zone.length > 64 || !/^[A-Za-z0-9_+\-/]+$/.test(zone)) return false;
  try {
    new Intl.DateTimeFormat("en", { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

/** The shortest display name of a browser and system from a user agent, e.g. "Firefox on Linux". */
export function describeUserAgent(userAgent: string | null | undefined): { browser: string; os: string } {
  const ua = (userAgent ?? "").slice(0, 512);
  const browser = /\bEdg(?:e|A|iOS)?\//.test(ua)
    ? "Edge"
    : /\bOPR\//.test(ua)
      ? "Opera"
      : /\b(?:Firefox|FxiOS)\//.test(ua)
        ? "Firefox"
        : /\b(?:Chrome|CriOS|Chromium)\//.test(ua)
          ? "Chrome"
          : /\bSafari\//.test(ua) && /\bVersion\//.test(ua)
            ? "Safari"
            : /\bcurl\//.test(ua)
              ? "curl"
              : "";
  const os = /\bWindows\b/.test(ua)
    ? "Windows"
    : /\b(?:iPhone|iPad|iPod)\b/.test(ua)
      ? "iOS"
      : /\bAndroid\b/.test(ua)
        ? "Android"
        : /\bMac OS X\b|\bMacintosh\b/.test(ua)
          ? "macOS"
          : /\bCrOS\b/.test(ua)
            ? "ChromeOS"
            : /\bLinux\b|\bX11\b/.test(ua)
              ? "Linux"
              : "";
  return { browser, os };
}
