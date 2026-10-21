import { Flame } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../../lib/cn.ts";
import type { ScanState, Severity } from "../../lib/types.ts";

/**
 * Badge tones (mockup). Severity tones only ever mean severity, success only ever means
 * proof (a gate that passed, a fix whose tests passed), never "online" or "finished".
 */
export const BADGE_TONE = {
  critical: "bg-destructive/15 text-destructive-text",
  high: "bg-high/16 text-high-text",
  medium: "bg-warning/18 text-warning-text",
  low: "bg-muted text-muted-foreground",
  neutral: "bg-muted text-muted-foreground",
  success: "bg-success/16 text-success-text",
  info: "bg-info/14 text-info-text",
  outline: "border-border text-foreground",
} as const;
export type BadgeTone = keyof typeof BADGE_TONE;

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  negligible: "low",
  unknown: "low",
};

export function Badge({
  tone,
  className,
  children,
}: {
  tone?: BadgeTone;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex h-[22px] items-center gap-[5px] rounded-md border border-transparent px-2 text-[12.5px] font-medium whitespace-nowrap [&_svg]:size-3",
        tone ? BADGE_TONE[tone] : null,
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
    <Badge tone={SEVERITY_TONE[severity]}>
      {severity === "critical" ? <Flame aria-hidden="true" /> : null}
      {count === undefined ? t(`severity.${severity}`) : `${count} ${t(`severity.${severity}`)}`}
    </Badge>
  );
}

const DOT: Record<Severity, string> = {
  critical: "bg-destructive",
  high: "bg-high",
  medium: "bg-warning",
  low: "bg-muted-foreground/50",
  negligible: "bg-muted-foreground/50",
  unknown: "bg-muted-foreground/50",
};

/** A small severity marker next to a title; the word is always in the same row or its label. */
export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn("inline-block size-2 flex-none rounded-full", DOT[severity], className)}
    />
  );
}

/** Scan state is neutral or informational: a finished scan is not proof of anything, so never green. */
export function ScanStateBadge({ state }: { state: ScanState | null }) {
  const { t } = useTranslation();
  if (!state) return <Badge tone="neutral">{t("scanState.never")}</Badge>;
  const tone: BadgeTone = state === "failed" ? "critical" : state === "succeeded" ? "neutral" : "info";
  return <Badge tone={tone}>{t(`scanState.${state}`)}</Badge>;
}
