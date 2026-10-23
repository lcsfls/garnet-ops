import { TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import {
  daysUntil,
  type ExposureAsset,
  type ExposureSeverity,
  knownError,
  stage1Key,
  stage1Tone,
  stage2Key,
  stage2Tone,
  VERIFICATION_TONE,
  verificationKey,
} from "../lib/exposure.ts";
import { formatNumber } from "../lib/format.ts";
import { BADGE_TONE, Badge } from "./ui/badge.tsx";
import { CopyButton } from "./ui/copy-button.tsx";

export const COUNT_PILL =
  "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold";

/** Verification state of an asset: a word, never a colour alone. Blue and grey, never green: a proof of control is no security result. */
export function VerificationBadge({ asset }: { asset: Pick<ExposureAsset, "verification"> }) {
  const { t } = useTranslation();
  const key = verificationKey(asset);
  return (
    <Badge tone={VERIFICATION_TONE[key]}>
      {key === "lost" ? <TriangleAlert aria-hidden="true" /> : null}
      {t(`exposure.verification.${key}`)}
    </Badge>
  );
}

export function Stage1Badge({ asset }: { asset: Pick<ExposureAsset, "stage1"> }) {
  const { t } = useTranslation();
  const key = stage1Key(asset);
  return <Badge tone={stage1Tone(key)}>{t(`exposure.stage1State.${key}`)}</Badge>;
}

export function Stage2Badge({ asset }: { asset: Pick<ExposureAsset, "stage2"> }) {
  const { t } = useTranslation();
  const key = stage2Key(asset);
  return <Badge tone={stage2Tone(key)}>{t(`exposure.stage2State.${key}`)}</Badge>;
}

/** One number of open findings of a severity, in the fixed severity colour when it is above zero. */
export function CountPill({ severity, n }: { severity: ExposureSeverity; n: number }) {
  const { t } = useTranslation();
  return (
    <span
      title={t("exposure.openOfSeverity", { count: n, severity: t(`severity.${severity}`) })}
      className={cn(COUNT_PILL, n > 0 ? BADGE_TONE[severity] : "font-normal text-muted-foreground")}
    >
      {formatNumber(n)}
    </span>
  );
}

const EXPIRY_TEXT: Record<"expired" | "week" | "fortnight" | "month", string> = {
  expired: "text-high-text font-medium",
  week: "text-high-text font-medium",
  fortnight: "text-warning-text",
  month: "text-muted-foreground",
};

/** When a certificate ends: the days left, in the colour of the warning step. A valid certificate is plain text, not green. */
export function CertificateExpiry({ expires }: { expires: string | null }) {
  const { t } = useTranslation();
  const days = daysUntil(expires);
  if (days === null) return <span className="text-muted-foreground">–</span>;
  const step = days < 0 ? "expired" : days <= 7 ? "week" : days <= 14 ? "fortnight" : "month";
  return (
    <span className={days <= 30 ? EXPIRY_TEXT[step] : undefined} title={expires ?? undefined}>
      {days < 0 ? t("exposure.expiredDaysAgo", { days: -days }) : t("exposure.expiresInDays", { days })}
    </span>
  );
}

/** A stored error code as a sentence in the user's language; unknown codes (a newer server) show as they are. */
export function useExposureError(): (code: string | null | undefined) => string {
  const { t } = useTranslation();
  return (code) => {
    if (!code) return "";
    const known = knownError(code);
    return known ? t(`exposure.error.${known}`) : code;
  };
}

/** The name of a region in the UI language ("DE" -> "Germany"); the code itself if the browser does not know it. */
export function countryName(code: string | null, language: string): string {
  if (!code) return "";
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

/** A short warning with an icon: amber like the page-level banner, for things that need a decision before an action. */
export function Notice({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div
      role="note"
      className="flex gap-2.5 rounded-md border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-3 py-2.5 text-sm"
    >
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 flex-none text-warning-text" />
      <div className="min-w-0">
        <b className="block font-semibold">{title}</b>
        {children ? <div className="text-muted-foreground">{children}</div> : null}
      </div>
    </div>
  );
}

/** A label, a value in a monospace box and a copy button: what an admin pastes into a DNS panel or a file. */
export function CopyRow({ label, value, id }: { label: string; value: string; id: string }) {
  return (
    <fieldset className="m-0 grid min-w-0 gap-1.5 border-0 p-0">
      <legend className="mb-1.5 p-0 text-sm font-medium">{label}</legend>
      <div className="flex min-w-0 items-center gap-2">
        <code
          data-testid={id}
          className="min-w-0 flex-1 rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all select-all"
        >
          {value}
        </code>
        <CopyButton text={value} />
      </div>
    </fieldset>
  );
}
