import { Flame } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../../lib/cn.ts";
import type { ScanState, Severity } from "../../lib/types.ts";

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-destructive/15 text-destructive-text",
  high: "bg-high/15 text-high-text",
  medium: "bg-warning/20 text-warning-text",
  low: "bg-muted text-muted-foreground",
  negligible: "bg-muted text-muted-foreground",
  unknown: "bg-muted text-muted-foreground",
};

export function Badge({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1 rounded-md px-2 text-sm font-medium whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Severity always carries its word, and critical an icon too, so colour is never the only signal. */
export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  const { t } = useTranslation();
  return (
    <Badge className={SEVERITY_CLASS[severity]}>
      {severity === "critical" ? <Flame aria-hidden="true" className="size-3.5" /> : null}
      {count === undefined ? t(`severity.${severity}`) : `${count} ${t(`severity.${severity}`)}`}
    </Badge>
  );
}

/** Scan state is neutral or informational: a finished scan is not proof of anything, so never green. */
export function ScanStateBadge({ state }: { state: ScanState | null }) {
  const { t } = useTranslation();
  if (!state) return <Badge className="bg-muted text-muted-foreground">{t("scanState.never")}</Badge>;
  const tone =
    state === "failed"
      ? "bg-destructive/15 text-destructive-text"
      : state === "succeeded"
        ? "bg-muted text-muted-foreground"
        : "bg-info/15 text-info-text";
  return <Badge className={tone}>{t(`scanState.${state}`)}</Badge>;
}
