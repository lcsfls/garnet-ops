import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";
import { Field } from "../components/ui/field.tsx";
import { authClient, authErrorKey } from "../lib/auth-client.ts";
import { guard } from "../lib/guard.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { PASSKEY_FAILURE_KEYS, passkeysSupported, signInWithPasskey } from "../lib/passkeys.ts";

/** Second step of sign-in. Only reachable while signed out; the pending sign-in lives in a short-lived cookie. */
export const Route = createFileRoute("/two-factor")({
  beforeLoad: ({ context }) => guard(context.queryClient, ["signed-out"]),
  component: TwoFactor,
});

function TwoFactor() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<"totp" | "backup">("totp");
  const [error, setError] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code")).replace(/\s+/g, "");
    setBusy(true);
    setError(null);
    const { error } =
      mode === "totp"
        ? await authClient.twoFactor.verifyTotp({ code })
        : await authClient.twoFactor.verifyBackupCode({ code });
    setBusy(false);
    if (error) return setError(authErrorKey(error));
    await queryClient.invalidateQueries();
    await navigate({ to: "/" });
  }

  /** A passkey is a second factor on its own (user verification is required), so it completes the sign-in. */
  async function withPasskey() {
    setBusy(true);
    setError(null);
    const result = await signInWithPasskey();
    setBusy(false);
    if (!result.ok) {
      if (result.reason !== "cancelled") setError(PASSKEY_FAILURE_KEYS[result.reason]);
      return;
    }
    await queryClient.invalidateQueries();
    await navigate({ to: "/" });
  }

  return (
    <AuthLayout
      title={t("twoFactor.title")}
      description={mode === "totp" ? t("twoFactor.description") : t("twoFactor.backupDescription")}
      footer={
        <Link to="/sign-in" className="underline-offset-4 hover:underline">
          {t("common.back")}
        </Link>
      }
    >
      <form className="grid gap-4" onSubmit={submit} key={mode}>
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        {mode === "totp" ? (
          <Field
            label={t("twoFactor.code")}
            name="code"
            required
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9 ]{6,7}"
            maxLength={7}
            autoFocus
            className="font-mono tracking-widest"
          />
        ) : (
          <Field
            label={t("twoFactor.backupCode")}
            name="code"
            required
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            autoFocus
            className="font-mono"
          />
        )}
        <Button type="submit" disabled={busy}>
          {busy ? t("common.loading") : t("twoFactor.submit")}
        </Button>
        <Button
          variant="link"
          onClick={() => {
            setError(null);
            setMode(mode === "totp" ? "backup" : "totp");
          }}
        >
          {mode === "totp" ? t("twoFactor.useBackupCode") : t("twoFactor.useAuthenticator")}
        </Button>
        {passkeysSupported() ? (
          <Button variant="link" disabled={busy} onClick={() => void withPasskey()}>
            {t("twoFactor.usePasskey")}
          </Button>
        ) : null}
      </form>
    </AuthLayout>
  );
}
