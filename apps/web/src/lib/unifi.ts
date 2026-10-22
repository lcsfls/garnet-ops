/**
 * Helpers of the UniFi screens (ADR 0022): the stored error texts in the user's language, the tones of the device
 * flags and the commands that show a console's certificate. Colour is never the only signal: every flag has its
 * word and an icon, and "update available" is a maintenance hint, never a vulnerability.
 */
import { parseUnifiError } from "@garnetops/core";
import { useTranslation } from "react-i18next";
import type { BadgeTone } from "../components/ui/badge.tsx";
import type { UnifiDeviceFlag } from "./types.ts";

/**
 * Translates a failure the worker stored in English (packages/core unifi-errors.ts). A text this version does not
 * know is shown unchanged.
 */
export function useUnifiErrorText(): (message: string) => string {
  const { t } = useTranslation();
  return (message) => {
    const parsed = parseUnifiError(message);
    return parsed ? t(`unifiError.${parsed.code}`, parsed.params) : message;
  };
}

/** Offline is amber, update available is neutral: a maintenance hint is not a severity. */
export const FLAG_TONE: Record<UnifiDeviceFlag, BadgeTone> = {
  offline: "medium",
  updateAvailable: "neutral",
};

/** Order of the flags in a row. */
export const FLAG_ORDER: UnifiDeviceFlag[] = ["offline", "updateAvailable"];

/**
 * The command that shows the certificate of a UniFi OS console on the console itself (SSH is not needed to read it
 * in the web interface; this is the shell variant), for comparing its fingerprint.
 */
export const UNIFI_CERT_COMMAND =
  "openssl x509 -in /data/unifi-core/config/unifi-core.crt -noout -fingerprint -sha256";
