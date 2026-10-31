import type { Reason } from "@garnetops/core/system-status-view";
import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";

const camel = (code: string) => code.replace(/[-_](\w)/g, (_, c: string) => c.toUpperCase());

/** One text for every reason family the page shows. Unknown values appear as they are. */
export function reasonText(reason: Reason | null): string | null {
  if (!reason) return null;
  const { family, value } = reason;
  switch (family) {
    case "ai": {
      const key = `ai.error.${camel(value)}`;
      return hasKey(key) ? t(key as MessageKey) : value;
    }
    case "vulndb-update": {
      const key = `systemStatus.vulnDb.updateReason.${camel(value)}`;
      return hasKey(key) ? t(key as MessageKey) : value;
    }
    case "status": {
      const key = `systemStatus.reason.${value}`;
      return hasKey(key) ? t(key as MessageKey) : value;
    }
    default:
      return value;
  }
}
