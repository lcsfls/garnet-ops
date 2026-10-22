import { X } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";

/**
 * A panel that slides in from the right edge, on the native <dialog> element: focus is
 * trapped, Escape closes it and the page behind is inert, like {@link Dialog}.
 */
export function Drawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

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
      className="fixed inset-y-0 right-0 left-auto m-0 h-dvh max-h-dvh w-[min(36rem,100vw)] max-w-none overflow-hidden border-l bg-background p-0 text-foreground shadow-[0_0_40px_oklch(0_0_0/25%)] backdrop:bg-[oklch(0.12_0.02_15/50%)]"
    >
      {open ? (
        <div className="flex h-full min-h-0 flex-col">
          <div className="flex items-center gap-3 border-b bg-card px-5 py-3">
            <h2 id={titleId} className="min-w-0 flex-1 font-semibold">
              {title}
            </h2>
            <button
              type="button"
              onClick={onClose}
              aria-label={t("common.close")}
              className="grid size-8 place-items-center rounded-md hover:bg-accent"
            >
              <X aria-hidden="true" className="size-4" />
            </button>
          </div>
          <div className="min-h-0 flex-1 p-4">{children}</div>
        </div>
      ) : null}
    </dialog>
  );
}
