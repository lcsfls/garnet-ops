import { t } from "../../../i18n.svelte.ts";

const KNOWN = ["denied", "expired", "no-public-url", "unknown"] as const;

/** A sign-in's problem code (ADR 0031) in words; codes from the forge client fall back to a general text. */
export function signInProblem(code: string | null): string {
  const known = KNOWN.find((k) => k === code);
  return known
    ? t(`connections.signIn.problems.${known}`)
    : t("connections.signIn.problemOther", { code: code ?? "" });
}
