import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { authClient, authErrorKey } from "../lib/auth-client.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field } from "./ui/field.tsx";

/**
 * "Confirm it is you" before a sensitive action (scheduling an update). It is a real
 * sign-in with password and TOTP, so the API sees a fresh session and the audit log
 * records both steps. Once the password is accepted the old session has ended; closing
 * the dialog before the code is confirmed therefore leads to the sign-in page.
 */
export function StepUpDialog({
  open,
  email,
  onConfirmed,
  onClose,
}: {
  open: boolean;
  email: string;
  onConfirmed: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [stage, setStage] = useState<"password" | "code">("password");
  const [error, setError] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  async function close() {
    const signedOut = stage === "code";
    setStage("password");
    setError(null);
    onClose();
    if (signedOut) {
      queryClient.clear();
      await navigate({ to: "/sign-in" });
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const code = String(form.get("code") ?? "").replace(/\s+/g, "");
    setBusy(true);
    setError(null);
    try {
      if (stage === "password") {
        const { data, error } = await authClient.signIn.email({
          email,
          password: String(form.get("password")),
        });
        if (error) return setError(authErrorKey(error));
        if (!(data && "twoFactorRedirect" in data && data.twoFactorRedirect))
          return setError("errors.generic");
        setStage("code");
      }
      const { error } = await authClient.twoFactor.verifyTotp({ code });
      if (error) return setError(authErrorKey(error));
      setStage("password");
      await queryClient.invalidateQueries();
      onConfirmed();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={() => void close()}
      title={t("stepUp.title")}
      description={t("stepUp.description")}
    >
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        {stage === "code" ? <Alert tone="info">{t("stepUp.passwordAccepted")}</Alert> : null}
        {stage === "password" ? (
          <Field
            label={t("common.password")}
            name="password"
            type="password"
            required
            autoComplete="current-password"
          />
        ) : null}
        <Field
          label={t("twoFactor.code")}
          name="code"
          required
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9 ]{6,7}"
        />
        <DialogFooter>
          <Button variant="outline" onClick={() => void close()}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {busy ? t("common.loading") : t("stepUp.confirm")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
