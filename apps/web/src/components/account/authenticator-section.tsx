import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, RefreshCw } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { accountQuery } from "../../lib/account.ts";
import { ApiError, api } from "../../lib/api.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { QrCode } from "../qr-code.tsx";
import { QueryStatus } from "../query-state.tsx";
import { Alert } from "../ui/alert.tsx";
import { Badge } from "../ui/badge.tsx";
import { Button } from "../ui/button.tsx";
import { ConfirmDialog } from "../ui/confirm-dialog.tsx";
import { CopyButton } from "../ui/copy-button.tsx";
import { Dialog, DialogFooter } from "../ui/dialog.tsx";
import { Field } from "../ui/field.tsx";
import { useStepUp } from "../use-step-up.tsx";
import { BackupCodesDialog } from "./backup-codes-dialog.tsx";

/** Account → Authenticator app: replace it (never switch it off) and renew the backup codes. */
export function AuthenticatorSection({ email }: { email: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const query = useQuery(accountQuery);
  const stepUp = useStepUp(email);
  const [replacing, setReplacing] = useState(false);
  const [confirmingCodes, setConfirmingCodes] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const renew = useMutation({
    mutationFn: () => api<{ codes: string[] }>("/account/backup-codes", { method: "POST" }),
    onSuccess: async (result) => {
      setConfirmingCodes(false);
      setCodes(result.codes);
      setNotice(null);
      await queryClient.invalidateQueries({ queryKey: ["account"] });
    },
    onError: (e) => {
      if (stepUp.handled(e, () => renew.mutate())) return;
      setError(t("errors.generic"));
    },
  });

  if (!query.data) {
    return (
      <Card>
        <QueryStatus query={query} />
      </Card>
    );
  }
  const { totp } = query.data.secondFactor;

  return (
    <>
      <Card>
        <CardHeader
          title={t("account.authenticator.title")}
          description={t("account.authenticator.description")}
        />
        <div className="grid gap-4 px-5 py-5">
          {notice ? <Alert tone="info">{notice}</Alert> : null}
          {error ? <Alert tone="error">{error}</Alert> : null}
          <div className="flex flex-wrap items-center gap-3">
            <Badge tone={totp.enrolled ? "neutral" : "critical"}>
              {totp.enrolled ? t("account.authenticator.statusOn") : t("account.authenticator.statusOff")}
            </Badge>
            <Button variant="outline" onClick={() => setReplacing(true)}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("account.authenticator.replace")}
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">{t("account.authenticator.required")}</p>
        </div>
      </Card>
      <Card>
        <CardHeader
          title={t("account.authenticator.codesTitle")}
          description={t("account.authenticator.codesDescription")}
        />
        <div className="flex flex-wrap items-center gap-3 px-5 py-5">
          <span data-testid="codes-left">
            {t("account.authenticator.codesLeft", { count: totp.backupCodesRemaining })}
          </span>
          <Button
            variant="outline"
            className="ml-auto"
            onClick={() => {
              setError(null);
              setConfirmingCodes(true);
            }}
          >
            <KeyRound aria-hidden="true" className="size-4" />
            {t("account.authenticator.codesCreate")}
          </Button>
        </div>
      </Card>

      <ReplaceDialog
        open={replacing}
        stepUp={stepUp}
        onClose={() => setReplacing(false)}
        onReplaced={async () => {
          setReplacing(false);
          setNotice(t("account.authenticator.replaced"));
          await queryClient.invalidateQueries({ queryKey: ["account"] });
        }}
      />
      <ConfirmDialog
        open={confirmingCodes}
        title={t("account.authenticator.codesConfirmTitle")}
        description={t("account.authenticator.codesConfirmText")}
        confirmLabel={t("account.authenticator.codesConfirm")}
        pending={renew.isPending}
        onConfirm={() => renew.mutate()}
        onClose={() => setConfirmingCodes(false)}
      />
      <BackupCodesDialog codes={codes} onClose={() => setCodes(null)} />
      {stepUp.dialog}
    </>
  );
}

function ReplaceDialog({
  open,
  stepUp,
  onClose,
  onReplaced,
}: {
  open: boolean;
  stepUp: ReturnType<typeof useStepUp>;
  onClose: () => void;
  onReplaced: () => void;
}) {
  const { t } = useTranslation();
  const [uri, setUri] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setUri(null);
    setError(null);
  };
  const close = () => {
    reset();
    onClose();
  };

  const begin = useMutation({
    mutationFn: (password: string) =>
      api<{ uri: string }>("/account/totp/begin", { method: "POST", body: { password } }),
    onSuccess: (result) => setUri(result.uri),
    onError: (e, password) => {
      if (stepUp.handled(e, () => begin.mutate(password))) return;
      setError(
        e instanceof ApiError && e.code === "invalid-password"
          ? t("account.authenticator.errorPassword")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : t("errors.generic"),
      );
    },
  });
  const confirm = useMutation({
    mutationFn: (code: string) => api("/account/totp/confirm", { method: "POST", body: { code } }),
    onSuccess: () => {
      reset();
      onReplaced();
    },
    onError: (e, code) => {
      if (stepUp.handled(e, () => confirm.mutate(code))) return;
      if (e instanceof ApiError && e.code === "no-pending-enrolment") {
        setUri(null);
        return setError(t("account.authenticator.errorExpired"));
      }
      setError(
        e instanceof ApiError && e.code === "invalid-code"
          ? t("account.authenticator.errorCode")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : t("errors.generic"),
      );
    },
  });

  function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    begin.mutate(String(new FormData(event.currentTarget).get("password")));
  }
  function submitCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    confirm.mutate(String(new FormData(event.currentTarget).get("code")).replace(/\s+/g, ""));
  }
  const secret = uri ? (new URL(uri).searchParams.get("secret") ?? "") : "";

  return (
    <Dialog
      open={open}
      onClose={close}
      title={t("account.authenticator.replaceTitle")}
      description={
        uri ? t("account.authenticator.scanDescription") : t("account.authenticator.replaceDescription")
      }
    >
      {uri ? (
        <form className="grid gap-5" onSubmit={submitCode}>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <div className="flex justify-center">
            <QrCode value={uri} label={t("enroll.qrLabel")} />
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t("enroll.manualKey")}</span>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">
                {secret.replace(/(.{4})/g, "$1 ").trim()}
              </code>
              <CopyButton text={secret} />
            </div>
          </div>
          <Field
            label={t("twoFactor.code")}
            name="code"
            required
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 ]{6,7}"
            maxLength={7}
            className="font-mono tracking-widest"
          />
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={confirm.isPending}>
              {confirm.isPending ? t("common.loading") : t("account.authenticator.confirm")}
            </Button>
          </DialogFooter>
        </form>
      ) : (
        <form className="grid gap-4" onSubmit={submitPassword}>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Field
            label={t("common.password")}
            name="password"
            type="password"
            required
            autoComplete="current-password"
          />
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={begin.isPending}>
              {begin.isPending ? t("common.loading") : t("account.authenticator.start")}
            </Button>
          </DialogFooter>
        </form>
      )}
    </Dialog>
  );
}
