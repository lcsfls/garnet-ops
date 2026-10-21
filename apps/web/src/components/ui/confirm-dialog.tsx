import { useTranslation } from "react-i18next";
import { Alert } from "./alert.tsx";
import { Button } from "./button.tsx";
import { Dialog, DialogFooter } from "./dialog.tsx";

/**
 * Asks before an action that cannot be undone, in the app's own dialog rather
 * than the browser's unstyled `confirm()`. The dialog's close button gets the
 * focus first, so pressing Enter by accident does nothing harmful.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  pending,
  error,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  pending?: boolean;
  /** Shown when the action failed; the dialog stays open so the user can retry or cancel. */
  error?: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onClose={onClose} title={title} description={description}>
      <div className="grid gap-4">
        {error ? <Alert tone="error">{error}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button variant="destructive" disabled={pending} onClick={onConfirm}>
            {pending ? t("common.loading") : confirmLabel}
          </Button>
        </DialogFooter>
      </div>
    </Dialog>
  );
}
