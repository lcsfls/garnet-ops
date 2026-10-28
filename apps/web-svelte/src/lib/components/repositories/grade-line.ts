import { t } from "../../i18n.svelte.ts";
import type { GradeFields } from "../../types.ts";
import { REASON_KEYS } from "./grade-badge.ts";

/** "D: 2 high vulnerabilities with a fix (lodash)", the reason in plain words. */
export function gradeLine({ grade, gradeReason }: GradeFields): string | null {
  if (!grade || !gradeReason) return null;
  const reason = t(REASON_KEYS[gradeReason.rule], { count: gradeReason.count });
  return gradeReason.example
    ? t("grades.lineExample", { grade, reason, example: gradeReason.example })
    : t("grades.line", { grade, reason });
}
