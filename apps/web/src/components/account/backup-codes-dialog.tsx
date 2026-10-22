import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "../ui/button.tsx";
import { Checkbox } from "../ui/checkbox.tsx";
import { CopyButton } from "../ui/copy-button.tsx";
import { Dialog, DialogFooter } from "../ui/dialog.tsx";

/** New backup codes, shown once; "Done" waits for the confirmation that they are saved. */
export function BackupCodesDialog({ codes, onClose }: { codes: string[] | null; onClose: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const close = () => {
    setSaved(false);
    onClose();
  };
  return (
    <Dialog
      open={codes !== null}
      onClose={close}
      title={t("account.authenticator.codesShownTitle")}
      description={t("account.authenticator.codesShownText")}
    >
      <div className="grid gap-4">
        <ul
          aria-label={t("account.authenticator.codesTitle")}
          className="grid grid-cols-2 gap-2 rounded-md bg-muted p-4 font-mono text-sm"
        >
          {(codes ?? []).map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ul>
        <div className="flex justify-end">
          <CopyButton text={(codes ?? []).join("\n")} />
        </div>
        <label className="flex items-start gap-2.5 text-sm">
          <Checkbox className="mt-0.5" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          {t("account.authenticator.codesSaved")}
        </label>
        <DialogFooter>
          <Button disabled={!saved} onClick={close}>
            {t("account.authenticator.codesDone")}
          </Button>
        </DialogFooter>
      </div>
    </Dialog>
  );
}
