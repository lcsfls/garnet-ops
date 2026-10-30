import { hasKey, type MessageKey, t } from "./i18n.svelte.ts";
import type { ExposureFindingRow } from "./websites.ts";

/** The title and sentence of a website finding. A rule this version does not know shows as its id. */
export function ruleText(f: Pick<ExposureFindingRow, "rule" | "params">): { title: string; text: string } {
  const titleKey = `websites.rules.${f.rule}.title`;
  if (!hasKey(titleKey)) return { title: f.rule, text: "" };
  const service = typeof f.params.service === "string" ? f.params.service : "";
  const category = typeof f.params.category === "string" ? f.params.category : "";
  const values = {
    ...f.params,
    service: hasKey(`websites.service.${service}`) ? t(`websites.service.${service}` as MessageKey) : service,
    category: hasKey(`websites.category.${category}`)
      ? t(`websites.category.${category}` as MessageKey)
      : category,
  };
  return {
    title: t(titleKey as MessageKey, values),
    text: t(`websites.rules.${f.rule}.text` as MessageKey, values),
  };
}
