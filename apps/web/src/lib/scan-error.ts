import { parseScanError } from "@garnetops/core";
import { useTranslation } from "react-i18next";

/**
 * Translates a scan error the worker stored in English (packages/core
 * scan-errors.ts). A text this version does not know is shown unchanged.
 */
export function useScanErrorText(): (message: string) => string {
  const { t } = useTranslation();
  return (message) => {
    const parsed = parseScanError(message);
    return parsed ? t(`scanError.${parsed.code}`, parsed.params) : message;
  };
}
