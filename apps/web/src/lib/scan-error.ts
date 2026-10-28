import { parseScanError } from "@garnetops/core";
import { t } from "./i18n.svelte.ts";

/**
 * Translates a scan error the worker stored in English (packages/core
 * scan-errors.ts). A text this version does not know is shown unchanged.
 */
export function scanErrorText(message: string): string {
  const parsed = parseScanError(message);
  return parsed ? t(`scanError.${parsed.code}` as never, parsed.params) : message;
}
