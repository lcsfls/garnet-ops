import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import type { Me } from "../lib/session.ts";
import type { FixProposalRow } from "../lib/types.ts";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { useStepUp } from "./use-step-up.tsx";

/**
 * Asks before GarnetOps opens a pull request (ADR 0014): what will change, on which branch, and
 * what it will not do. The request names only the repository and the proposal; the API works out
 * the version and the file again. A recent sign-in is needed.
 */
export function CreatePrDialog({
  proposal,
  me,
  onClose,
  onCreated,
}: {
  proposal: FixProposalRow;
  me: Me;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api("/fixes/prs", { method: "POST", body: { repositoryId: proposal.repositoryId, key: proposal.key } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["fixes"] });
      onCreated();
    },
    onError: async (e) => {
      if (stepUp.handled(e, () => create.mutate())) return;
      const code = e instanceof ApiError ? e.code : null;
      if (code === "already-open") setError(t("fixes.create.alreadyOpen"));
      else if (code === "write-access-off") setError(t("fixes.create.writeOff"));
      else if (code === "write-access-failed") setError(t("fixes.create.writeFailed"));
      else if (code === "not-editable") setError(t("fixes.create.notEditable"));
      else if (e instanceof ApiError && e.status === 404) setError(t("fixes.create.gone"));
      else if (e instanceof ApiError && e.status === 429) setError(t("fixes.create.rateLimited"));
      else setError(t("fixes.create.failed"));
      if (code === "not-editable" || (e instanceof ApiError && e.status === 404)) {
        await queryClient.invalidateQueries({ queryKey: ["fixes"] });
      }
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t("fixes.create.title")}
        description={t("fixes.create.description", { repository: proposal.repositoryName })}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <ul className="grid gap-2 text-sm">
            <li>
              {t("fixes.create.change", {
                file: proposal.manifestPath ?? "",
                from: proposal.currentSpec ?? proposal.installedVersion,
                to: proposal.newSpec ?? proposal.targetVersion ?? "",
              })}
            </li>
            <li>
              {t("fixes.create.branch", {
                branch: proposal.branch ?? "",
                base: t("fixes.create.defaultBranch"),
              })}
            </li>
            {proposal.majorUpgrade ? <li className="font-medium">{t("fixes.majorHint")}</li> : null}
            <li className="text-muted-foreground">{t("fixes.create.lockfile")}</li>
            <li className="text-muted-foreground">{t("fixes.create.never")}</li>
          </ul>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button disabled={create.isPending || create.isSuccess} onClick={() => create.mutate()}>
              {create.isPending ? t("fixes.create.working") : t("fixes.create.confirm")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {/* Next to the dialog, not inside it: closing the confirmation must not close this one. */}
      {stepUp.dialog}
    </>
  );
}
