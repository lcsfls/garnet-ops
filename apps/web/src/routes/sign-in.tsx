import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Fingerprint } from "lucide-react";
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

export const Route = createFileRoute("/sign-in")({
  validateSearch: (search: Record<string, unknown>): { setup?: "done" } =>
    search.setup === "done" ? { setup: "done" } : {},
  beforeLoad: ({ context }) => guard(context.queryClient, ["signed-out"]),
  component: SignIn,
});

function SignIn() {
  const { t } = useTranslation();
  const { setup } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [error, setError] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    const { data, error } = await authClient.signIn.email({
      email: String(form.get("email")),
      password: String(form.get("password")),
    });
    setBusy(false);
    if (error) return setError(authErrorKey(error));
    if (data && "twoFactorRedirect" in data && data.twoFactorRedirect) {
      return navigate({ to: "/two-factor" });
    }
    // No second factor yet: the guards send the user on to enrolment.
    await queryClient.invalidateQueries();
    await navigate({ to: "/" });
  }

  async function withPasskey() {
    setBusy(true);
    setError(null);
    const result = await signInWithPasskey();
    setBusy(false);
    if (!result.ok) {
      // Closing the prompt is a choice, not an error.
      if (result.reason !== "cancelled") setError(PASSKEY_FAILURE_KEYS[result.reason]);
      return;
    }
    await queryClient.invalidateQueries();
    await navigate({ to: "/" });
  }

  return (
    <AuthLayout title={t("signIn.title")} description={t("signIn.description")}>
      <form className="grid gap-4" onSubmit={submit}>
        {setup ? <Alert tone="info">{t("setup.done")}</Alert> : null}
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        <Field label={t("common.email")} name="email" type="email" required autoComplete="username" />
        <Field
          label={t("common.password")}
          name="password"
          type="password"
          required
          autoComplete="current-password"
        />
        <Button type="submit" disabled={busy}>
          {busy ? t("common.loading") : t("signIn.submit")}
        </Button>
      </form>
      {passkeysSupported() ? (
        <div className="mt-5 grid gap-3 border-t pt-5">
          <Button variant="outline" disabled={busy} onClick={() => void withPasskey()}>
            <Fingerprint aria-hidden="true" className="size-4" />
            {t("signIn.passkey")}
          </Button>
          <p className="text-center text-sm text-muted-foreground">{t("signIn.passkeyHint")}</p>
        </div>
      ) : null}
    </AuthLayout>
  );
}
