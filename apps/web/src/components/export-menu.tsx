import { Download, FileSpreadsheet, FileText, FileType } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toQuery } from "../lib/search.ts";

const FORMATS = [
  { format: "csv", icon: FileSpreadsheet },
  { format: "xlsx", icon: FileSpreadsheet },
  { format: "pdf", icon: FileType },
  { format: "txt", icon: FileText },
] as const;

/** The browser's zone: dates in the file are the user's own calendar days (ADR 0005). */
const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

/**
 * Downloads the findings list as CSV, Excel, PDF or text, with exactly the filters that
 * are set (and only one repository on a repository's page). The server builds the file;
 * the link carries the filters, so the download matches what the user sees.
 */
export function ExportMenu({ filters }: { filters: Record<string, string | number | undefined> }) {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const href = (format: string) =>
    `/api/v1/findings/export${toQuery({ ...filters, format, tz: timeZone, lang: i18n.language })}`;

  return (
    <div ref={root} className="relative">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
      >
        <Download aria-hidden="true" className="size-4" />
        {t("export.button")}
      </button>
      {open ? (
        <div
          id={panelId}
          className="absolute top-full right-0 z-30 mt-2 w-64 rounded-lg border bg-card p-2 text-card-foreground shadow-xs"
        >
          <p className="px-2 pt-1 pb-2 text-sm text-muted-foreground">{t("export.hint")}</p>
          <ul aria-label={t("export.menu")} className="grid gap-0.5">
            {FORMATS.map(({ format, icon: Icon }) => (
              <li key={format}>
                <a
                  href={href(format)}
                  download
                  onClick={() => setOpen(false)}
                  className="flex h-9 items-center gap-2.5 rounded-md px-2 hover:bg-accent"
                >
                  <Icon aria-hidden="true" className="size-4 text-muted-foreground" />
                  {t(`export.${format}`)}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
