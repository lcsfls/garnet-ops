import { CircleAlert, CircleCheck, CircleX } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { GateResult } from "../lib/types.ts";
import { Badge, type BadgeTone } from "./ui/badge.tsx";

/** Green means proof (AGENTS.md rule 6): only a gate that passed is green. */
const LOOK: Record<GateResult, { tone: BadgeTone; icon: typeof CircleCheck }> = {
  passed: { tone: "success", icon: CircleCheck },
  notes: { tone: "medium", icon: CircleAlert },
  blocked: { tone: "critical", icon: CircleX },
};

export function GateBadge({ result }: { result: GateResult }) {
  const { t } = useTranslation();
  const { tone, icon: Icon } = LOOK[result];
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {t(`gates.result.${result}`)}
    </Badge>
  );
}
