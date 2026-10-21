import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";
import { Field } from "../components/ui/field.tsx";
import { ApiError, api } from "../lib/api.ts";
import { guard } from "../lib/guard.ts";
import type { MessageKey } from "../lib/i18n.ts";

export const Route = createFileRoute("/setup")({
  beforeLoad: ({ context }) => guard(context.queryClient, ["setup"]),
  component: Setup,
});

function Setup() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [error, setError] = useState<MessageKey | null>(null);
  const [alreadyDone, setAlreadyDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api("/setup", {
        method: "POST",
        body: {
          token: String(form.get("token")).trim(),
          organizationName: String(form.get("organizationName")),
          name: String(form.get("name")),
          email: String(form.get("email")),
          password: String(form.get("password")),
          // Nightly scans run at 04:00 in the owner's zone; changeable later.
          timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        },
      });
      await queryClient.invalidateQueries();
      await navigate({ to: "/sign-in", search: { setup: "done" } });
    } catch (e) {
      if (e instanceof ApiError && e.code === "invalid-setup-token") setError("setup.invalidToken");
      else if (e instanceof ApiError && e.code === "already-set-up") setAlreadyDone(true);
      else setError(e instanceof ApiError ? "errors.generic" : "errors.network");
    } finally {
      setBusy(false);
    }
  }

  if (alreadyDone) {
    return (
      <AuthLayout title={t("setup.title")}>
        <div className="grid gap-4">
          <Alert tone="info">{t("setup.alreadyDone")}</Alert>
          <Link to="/sign-in" className="font-medium text-primary-text underline-offset-4 hover:underline">
            {t("signIn.title")}
          </Link>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title={t("setup.title")} description={t("setup.description")}>
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        <Field
          label={t("setup.token")}
          hint={t("setup.tokenHint")}
          name="token"
          required
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
        <Field
          label={t("setup.organization")}
          name="organizationName"
          required
          minLength={2}
          maxLength={100}
        />
        <Field label={t("common.name")} name="name" required autoComplete="name" maxLength={100} />
        <Field label={t("common.email")} name="email" type="email" required autoComplete="email" />
        <Field
          label={t("common.password")}
          hint={t("errors.passwordTooShort")}
          name="password"
          type="password"
          required
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
        />
        <Button type="submit" disabled={busy}>
          {busy ? t("common.loading") : t("setup.submit")}
        </Button>
      </form>
    </AuthLayout>
  );
}
