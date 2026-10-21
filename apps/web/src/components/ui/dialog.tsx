import { X } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";

/**
 * Modal dialog on the native <dialog> element: focus trapping, Escape and the
 * inert background come from the browser.
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);
  // Several dialogs can be mounted at once (e.g. one per table row), so ids must be unique.
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      className="m-auto max-h-[calc(100vh-3rem)] w-[min(40rem,calc(100vw-3rem))] overflow-y-auto rounded-[14px] border bg-card px-[22px] pt-5 pb-[18px] text-card-foreground shadow-[0_20px_50px_oklch(0_0_0/30%)] backdrop:bg-[oklch(0.12_0.02_15/60%)]"
    >
      {open ? (
        <>
          <div className="mb-[18px] flex items-start gap-3">
            <div className="flex-1">
              <h2 id={titleId} className="text-lg font-semibold">
                {title}
              </h2>
              {description ? (
                <p id={descriptionId} className="mt-0.5 text-sm text-muted-foreground">
                  {description}
                </p>
              ) : null}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label={t("common.close")}
              className="grid size-8 place-items-center rounded-md hover:bg-accent"
            >
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>
          {children}
        </>
      ) : null}
    </dialog>
  );
}

/** The action row of a dialog, separated by a rule (mockup .dialog-foot). */
export function DialogFooter({ children }: { children: ReactNode }) {
  return (
    <div className="-mx-[22px] mt-3 flex flex-wrap justify-end gap-2 border-t px-[22px] pt-3.5">
      {children}
    </div>
  );
}
