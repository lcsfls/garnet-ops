import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import type { HostRow } from "../lib/types.ts";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { useStepUp } from "./use-step-up.tsx";

/** The file on the server that holds the host key of this type, for the comparison command. */
export function hostKeyFile(type: string | null): string {
  if (type?.startsWith("ecdsa")) return "/etc/ssh/ssh_host_ecdsa_key.pub";
  if (type === "ssh-rsa") return "/etc/ssh/ssh_host_rsa_key.pub";
  return "/etc/ssh/ssh_host_ed25519_key.pub";
}

/** A host key as an admin compares it: type, then the fingerprint ssh shows. */
export function KeyFingerprint({
  type,
  fingerprint,
  label,
}: {
  type: string | null;
  fingerprint: string;
  label: string;
}) {
  return (
    <div className="grid gap-1">
      <span className="text-sm font-medium">{label}</span>
      <code className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all">
        {type ? `${type} ` : ""}
        {fingerprint}
      </code>
    </div>
  );
}

/**
 * Confirming a host key (ADR 0011): the admin compares the fingerprint GarnetOps read with the
 * one on the server, and the API pins exactly the fingerprint that was shown. If the server
 * presented another key in the meantime, the API refuses and the new fingerprint is shown.
 * A key change is a security event, so the dialog says so and shows both keys.
 */
export function HostKeyDialog({
  host,
  email,
  open,
  onClose,
  onConfirmed,
}: {
  host: HostRow;
  email: string;
  open: boolean;
  onClose: () => void;
  onConfirmed?: (runId: string) => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(email);
  const [error, setError] = useState<string | null>(null);
  const candidate = host.hostKey.candidate;
  const changed = host.hostKey.status === "changed";

  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api<{ runId: string }>(`/hosts/${host.id}/host-key/confirm`, { method: "POST", body: { fingerprint } }),
    onMutate: () => setError(null),
    onSuccess: async (result) => {
      await queryClient.invalidateQueries();
      onClose();
      onConfirmed?.(result.runId);
    },
    onError: async (e, fingerprint) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await queryClient.invalidateQueries();
        return setError(t("servers.keyMismatch"));
      }
      if (e instanceof ApiError && e.code === "no-host-key") return setError(t("servers.noKeyToConfirm"));
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={t(changed ? "servers.hostKeyChangedDialogTitle" : "servers.hostKeyTitle", { name: host.name })}
        description={t(changed ? "servers.keyChangedText" : "servers.keyIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          {changed && host.hostKey.fingerprint ? (
            <KeyFingerprint
              type={host.hostKey.type}
              fingerprint={host.hostKey.fingerprint}
              label={t("servers.pinnedKey")}
            />
          ) : null}
          {candidate ? (
            <KeyFingerprint
              type={candidate.type}
              fingerprint={candidate.fingerprint}
              label={changed ? t("servers.offeredKey") : t("servers.keyFingerprintLabel")}
            />
          ) : null}
          <div className="grid gap-1 text-sm text-muted-foreground">
            <span>{t("servers.keyCompare")}</span>
            <code className="font-mono break-all text-foreground">
              ssh-keygen -lf {hostKeyFile(candidate?.type ?? host.hostKey.type)}
            </code>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              disabled={!candidate || confirm.isPending}
              onClick={() => candidate && confirm.mutate(candidate.fingerprint)}
            >
              {confirm.isPending
                ? t("common.loading")
                : t(changed ? "servers.confirmChange" : "servers.confirmAndRead")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
