import { parseHostError } from "@garnetops/core";
import { useTranslation } from "react-i18next";

/**
 * Translates a failure the worker stored in English (packages/core host-errors.ts). A text
 * this version does not know is shown unchanged.
 */
export function useHostErrorText(): (message: string) => string {
  const { t } = useTranslation();
  return (message) => {
    const parsed = parseHostError(message);
    return parsed ? t(`hostError.${parsed.code}`, parsed.params) : message;
  };
}
