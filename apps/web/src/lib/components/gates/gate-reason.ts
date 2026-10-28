import { t } from "../../i18n.svelte.ts";
import type { GateMatches, GateRuleState } from "../../types.ts";

/** "2 × Critical vulnerability with a fix (blocks)" for each matching rule. */
export function gateReason(matches: GateMatches): string {
  const parts = Object.entries(matches).map(
    ([rule, m]) =>
      `${t("gates.reasonPart", { count: m.count, rule: t(`gates.rule.${rule as GateRuleState["rule"]}`) })}${m.mode === "block" ? ` (${t("gates.blocks")})` : ""}`,
  );
  return parts.length ? parts.join(", ") : t("gates.reasonNone");
}
