import { GRADE_FILTER_VALUES, GRADES } from "@garnetops/core/grades";
import { Link } from "@tanstack/react-router";
import { Clock } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Grade, GradeFields, GradeRule, Severity } from "../lib/types.ts";
import { BADGE_TONE, type BadgeTone } from "./ui/badge.tsx";
import { Select } from "./ui/select.tsx";

/**
 * Grade colours come from the fixed severity scale (AGENTS.md rule 6): F and E vermilion,
 * D orange, C amber, B grey, A neutral. Never green: a repository without open findings is
 * not proof of anything. The letter is always shown, so colour is never the only signal.
 */
const TONE: Record<Grade, BadgeTone> = {
  F: "critical",
  E: "critical",
  D: "high",
  C: "medium",
  B: "low",
  A: "neutral",
};

const REASON_KEYS = {
  "known-exploited-with-fix": "grades.reason.knownExploitedWithFix",
  "critical-with-fix": "grades.reason.criticalWithFix",
  "high-with-fix": "grades.reason.highWithFix",
  "critical-without-fix": "grades.reason.criticalWithoutFix",
  "medium-with-fix": "grades.reason.mediumWithFix",
  "high-without-fix": "grades.reason.highWithoutFix",
  "other-open": "grades.reason.otherOpen",
  none: "grades.reason.none",
} as const satisfies Record<GradeRule, MessageKey>;

/**
 * The open findings a rule is about, as the filters of the findings list. A rule that is
 * "without a fix" needs no filter for that: a worse rule would have decided if a fix existed.
 */
export function gradeFindingFilter(rule: GradeRule): {
  severity?: Severity;
  fixable?: "1";
  kev?: "1";
} | null {
  switch (rule) {
    case "known-exploited-with-fix":
      return { kev: "1", fixable: "1" };
    case "critical-with-fix":
      return { severity: "critical", fixable: "1" };
    case "high-with-fix":
      return { severity: "high", fixable: "1" };
    case "critical-without-fix":
      return { severity: "critical" };
    case "medium-with-fix":
      return { severity: "medium", fixable: "1" };
    case "high-without-fix":
      return { severity: "high" };
    case "other-open":
      return {};
    case "none":
      return null;
  }
}

/** "D: 2 high vulnerabilities with a fix (lodash)", the reason in plain words. */
export function useGradeLine() {
  const { t } = useTranslation();
  return ({ grade, gradeReason }: GradeFields): string | null => {
    if (!grade || !gradeReason) return null;
    const reason = t(REASON_KEYS[gradeReason.rule], { count: gradeReason.count });
    return gradeReason.example
      ? t("grades.lineExample", { grade, reason, example: gradeReason.example })
      : t("grades.line", { grade, reason });
  };
}

/** The letter in its colour, with a clock when the grade is from an earlier run. */
export function GradeLetter({
  grade,
  stale = false,
  large = false,
  className,
}: {
  grade: Grade;
  stale?: boolean;
  large?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex min-w-7 items-center justify-center gap-1 rounded-md border border-transparent px-1.5 font-semibold",
        large ? "h-9 min-w-9 text-lg" : "h-7 text-[15px]",
        BADGE_TONE[TONE[grade]],
        className,
      )}
    >
      {grade}
      {stale ? <Clock aria-hidden="true" className={large ? "size-4" : "size-3"} /> : null}
    </span>
  );
}

/** Where the findings behind a grade are listed. */
function GradeLink({
  id,
  reason,
  className,
  children,
  label,
}: {
  id: string;
  reason: NonNullable<GradeFields["gradeReason"]>;
  className?: string;
  children: ReactNode;
  label?: string;
}) {
  const filter = gradeFindingFilter(reason.rule);
  if (!filter) return <span className={className}>{children}</span>;
  return (
    <Link to="/findings" search={{ repositoryId: id, ...filter }} aria-label={label} className={className}>
      {children}
    </Link>
  );
}

/**
 * The grade of a repository in a list: the letter, and on hover or keyboard focus
 * the reason in plain words with a link to the findings behind it. Escape closes the note.
 * The grade is display only; the note says so. The note opens beside the letter, not under or
 * over it, so it never covers the column header or the letters of the other rows.
 */
export function GradeBadge({ row, id }: { row: GradeFields; id: string }) {
  const { t } = useTranslation();
  const line = useGradeLine();
  const [open, setOpen] = useState(false);
  // Escape closes the note wherever the focus is, and it opens again on the next visit of the pointer or focus.
  useEffect(() => {
    if (!open) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [open]);
  const text = line(row);
  const notGraded = t("grades.notGradedRepository");
  const stale = row.gradeStale ? t("grades.staleRepository") : null;
  const name = text ? [text, stale].filter(Boolean).join(". ") : notGraded;

  // A grade with findings behind it is a link to them; A and "not scanned" have nothing to link to.
  const trigger =
    row.grade && row.gradeReason && gradeFindingFilter(row.gradeReason.rule) ? (
      <GradeLink id={id} reason={row.gradeReason} label={name} className="inline-flex rounded-md">
        <GradeLetter grade={row.grade} stale={row.gradeStale} />
      </GradeLink>
    ) : null;

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: the wrapper only listens to hover and focus for its note; the control inside is the link or the focusable placeholder.
    <span
      className="relative inline-block"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false);
      }}
    >
      {trigger ?? (
        // A grade without findings behind it (A), or no grade yet, has nothing to open. It is a
        // button so that keyboard and touch can show its note too.
        <button
          type="button"
          aria-label={name}
          onClick={() => setOpen((on) => !on)}
          className="inline-flex rounded-md"
        >
          {row.grade ? (
            <GradeLetter grade={row.grade} stale={row.gradeStale} />
          ) : (
            <span className="inline-flex h-7 min-w-7 items-center justify-center rounded-md text-muted-foreground">
              <span aria-hidden="true">–</span>
              <span className="sr-only">{t("grades.notGradedShort")}</span>
            </span>
          )}
        </button>
      )}
      {open ? (
        // biome-ignore lint/a11y/useKeyWithClickEvents: the click only keeps the row behind the note from opening.
        <span
          role="tooltip"
          className="absolute top-0 left-full z-30 pl-2"
          onClick={(event) => event.stopPropagation()}
        >
          <span className="block w-72 max-w-[min(18rem,80vw)] rounded-lg border bg-card p-3 text-sm font-normal text-card-foreground shadow-md">
            <span className="block font-medium break-words">{text ?? notGraded}</span>
            {stale ? <span className="mt-1 block text-muted-foreground">{stale}</span> : null}
            {row.gradeReason && gradeFindingFilter(row.gradeReason.rule) ? (
              <GradeLink
                id={id}
                reason={row.gradeReason}
                className="mt-1.5 inline-block text-primary-text underline-offset-2 hover:underline"
              >
                {t("grades.show")}
              </GradeLink>
            ) : null}
            <span className="mt-1.5 block text-muted-foreground">{t("grades.displayOnly")}</span>
          </span>
        </span>
      ) : null}
    </span>
  );
}

/** The grade under the title of a repository page: letter, reason and link. */
export function GradeSummary({ row, id }: { row: GradeFields; id: string }) {
  const { t } = useTranslation();
  const line = useGradeLine();
  const text = line(row);
  const notGraded = t("grades.notGradedRepository");
  const stale = row.gradeStale ? t("grades.staleRepository") : null;
  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1" data-testid="grade-summary">
      <span className="text-sm text-muted-foreground">{t("grades.detailLabel")}</span>
      {row.grade && row.gradeReason ? (
        <>
          <GradeLetter grade={row.grade} stale={row.gradeStale} large />
          <span className="min-w-0 break-words">{text}</span>
          {gradeFindingFilter(row.gradeReason.rule) ? (
            <GradeLink
              id={id}
              reason={row.gradeReason}
              className="text-sm text-primary-text underline-offset-2 hover:underline"
            >
              {t("grades.show")}
            </GradeLink>
          ) : null}
        </>
      ) : (
        <span className="text-muted-foreground">{notGraded}</span>
      )}
      {stale ? <span className="basis-full text-sm text-muted-foreground">{stale}</span> : null}
    </div>
  );
}

/** What the grades mean, one click away; the same on the repositories list. */
export function GradeHelp() {
  const { t } = useTranslation();
  return (
    <details className="group mb-4 text-sm text-muted-foreground">
      <summary className="cursor-pointer rounded-sm hover:text-foreground">{t("grades.helpSummary")}</summary>
      <div className="mt-2 max-w-3xl rounded-lg border bg-card p-4 text-card-foreground">
        <p>{t("grades.helpIntro")}</p>
        <ul className="mt-3 grid gap-1.5">
          {[...GRADES].reverse().map((grade) => (
            <li key={grade} className="flex items-center gap-3">
              <GradeLetter grade={grade} />
              <span>{t(`grades.helpRule.${grade}`)}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-muted-foreground">{t("grades.helpOutro")}</p>
      </div>
    </details>
  );
}

/** A grade filter for a list header; the counts are those of the whole list. */
export function GradeFilter({
  value,
  counts,
  onChange,
}: {
  value: Grade | "none" | undefined;
  counts: Record<Grade | "none", number> | undefined;
  onChange: (value: Grade | "none" | undefined) => void;
}) {
  const { t } = useTranslation();
  const count = (key: Grade | "none") => (counts ? String(counts[key]) : "–");
  return (
    <Select
      className="min-w-44"
      aria-label={t("grades.filterLabel")}
      value={value ?? ""}
      onChange={(event) => {
        const next = event.target.value;
        onChange(
          (GRADE_FILTER_VALUES as readonly string[]).includes(next) ? (next as Grade | "none") : undefined,
        );
      }}
    >
      <option value="">{t("grades.filterAll")}</option>
      {[...GRADES].reverse().map((grade) => (
        <option key={grade} value={grade}>
          {t("grades.filterOption", { grade, count: count(grade) })}
        </option>
      ))}
      <option value="none">{t("grades.filterNone", { count: count("none") })}</option>
    </Select>
  );
}
