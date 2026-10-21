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
      className="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-lg border bg-card p-6 text-card-foreground shadow-xs backdrop:bg-black/40"
    >
      {open ? (
        <>
          <div className="mb-5 flex items-start gap-4">
            <div className="flex-1">
              <h2 id={titleId} className="text-lg font-semibold">
                {title}
              </h2>
              {description ? (
                <p id={descriptionId} className="mt-1 text-muted-foreground">
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
