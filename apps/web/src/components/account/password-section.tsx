import { useMutation } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../../lib/api.ts";
import { toast } from "../../lib/toast.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { Alert } from "../ui/alert.tsx";
import { Button } from "../ui/button.tsx";
import { Checkbox } from "../ui/checkbox.tsx";
import { Field } from "../ui/field.tsx";
import { useStepUp } from "../use-step-up.tsx";

const MIN_LENGTH = 12;

/** Account → Password: current and new password, and whether the other sessions end. */
export function PasswordSection({ email }: { email: string }) {
  const { t } = useTranslation();
  const stepUp = useStepUp(email);
  const formRef = useRef<HTMLFormElement>(null);
  const [revoke, setRevoke] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mismatch, setMismatch] = useState(false);
  const change = useMutation({
    mutationFn: (body: { currentPassword: string; newPassword: string; revokeOtherSessions: boolean }) =>
      api<{ revokedSessions: number }>("/account/password", { method: "POST", body }),
    onSuccess: (result) => {
      toast.success(
        `${t("account.password.done")} ${t("account.password.doneRevoked", { count: result.revokedSessions })}`,
      );
      formRef.current?.reset();
    },
    onError: (e, body) => {
      // A sign-in older than ten minutes: confirm it is you, then the change runs again.
      if (stepUp.handled(e, () => change.mutate(body))) return;
      if (e instanceof ApiError && e.code === "invalid-password")
        setError(t("account.password.errorCurrent"));
      else if (e instanceof ApiError && e.code === "same-password") setError(t("account.password.errorSame"));
      else if (e instanceof ApiError && e.status === 422) setError(t("account.password.errorShort"));
      else if (e instanceof ApiError && e.status === 429) setError(t("errors.tooManyAttempts"));
      else setError(t("errors.generic"));
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const next = String(data.get("newPassword"));
    setError(null);
    setMismatch(false);
    if (next !== String(data.get("repeat"))) return setMismatch(true);
    change.mutate({
      currentPassword: String(data.get("currentPassword")),
      newPassword: next,
      revokeOtherSessions: revoke,
    });
  }

  return (
    <Card>
      <CardHeader title={t("account.password.title")} description={t("account.password.description")} />
      <form ref={formRef} className="grid gap-5 px-5 py-5" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        {/* Lets a password manager attach the new password to the right account. */}
        <input type="email" name="username" value={email} autoComplete="username" readOnly hidden />
        <Field
          label={t("account.password.current")}
          name="currentPassword"
          type="password"
          required
          autoComplete="current-password"
        />
        <Field
          label={t("account.password.new")}
          hint={t("account.password.newHint")}
          name="newPassword"
          type="password"
          required
          minLength={MIN_LENGTH}
          maxLength={256}
          autoComplete="new-password"
        />
        <Field
          label={t("account.password.repeat")}
          name="repeat"
          type="password"
          required
          minLength={MIN_LENGTH}
          maxLength={256}
          autoComplete="new-password"
          error={mismatch ? t("account.password.mismatch") : null}
        />
        <label className="flex items-start gap-2.5">
          <Checkbox className="mt-1" checked={revoke} onChange={(e) => setRevoke(e.target.checked)} />
          <span>
            {t("account.password.revoke")}
            <span className="block text-sm text-muted-foreground">{t("account.password.revokeHint")}</span>
          </span>
        </label>
        <div>
          <Button type="submit" disabled={change.isPending}>
            {change.isPending ? t("common.loading") : t("account.password.submit")}
          </Button>
        </div>
      </form>
      {stepUp.dialog}
    </Card>
  );
}
