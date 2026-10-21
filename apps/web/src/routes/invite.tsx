import { useMutation, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";
import { Field } from "../components/ui/field.tsx";
import { ApiError, api } from "../lib/api.ts";

export const Route = createFileRoute("/invite")({ component: InvitePage });

interface Lookup {
  organizationName: string;
  email: string;
  role: "owner" | "admin" | "member" | "viewer";
  invitedBy: string | null;
  hasAccount: boolean;
}

/**
 * Accepting an invitation (ADR 0009). The token is in the URL fragment, which the browser
 * never sends to a server; this page posts it to the API itself.
 */
function InvitePage() {
  const { t } = useTranslation();
  const [token] = useState(() => (typeof window === "undefined" ? "" : window.location.hash.slice(1)));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const lookup = useQuery({
    queryKey: ["invitation", token],
    queryFn: () => api<Lookup>("/invitations/lookup", { method: "POST", body: { token } }),
    enabled: /^[A-Za-z0-9_-]{43}$/.test(token),
    retry: false,
  });
  const accept = useMutation({
    mutationFn: (body: { token: string; name?: string; password?: string }) =>
      api<{ email: string }>("/invitations/accept", { method: "POST", body }),
    onError: (e) => {
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
      }
    },
  });

  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    return (
      <AuthLayout title={t("invite.signIn")}>
        <Alert tone="error">{t("invite.missing")}</Alert>
      </AuthLayout>
    );
  }
  if (lookup.isError || (accept.error instanceof ApiError && accept.error.status === 410)) {
    return (
      <AuthLayout title={t("invite.signIn")}>
        <Alert tone="error">{t("invite.invalid")}</Alert>
      </AuthLayout>
    );
  }
  if (!lookup.data) {
    return (
      <AuthLayout title={t("common.loading")}>
        <p className="text-muted-foreground">{t("common.loading")}</p>
      </AuthLayout>
    );
  }
  const info = lookup.data;
  const role = t(`team.roles.${info.role}`);
  const title = t("invite.title", { organization: info.organizationName });

  if (accept.isSuccess) {
    return (
      <AuthLayout title={title}>
        <div className="grid gap-4">
          <Alert tone="info">{t("invite.done", { organization: info.organizationName })}</Alert>
          <Link
            to="/sign-in"
            className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
          >
            {t("invite.signIn")}
          </Link>
        </div>
      </AuthLayout>
    );
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setFieldErrors({});
    accept.mutate(
      info.hasAccount
        ? { token }
        : {
            token,
            name: String(form.get("name") ?? "").trim(),
            password: String(form.get("password") ?? ""),
          },
    );
  }

  return (
    <AuthLayout
      title={title}
      description={
        info.invitedBy
          ? t("invite.description", { inviter: info.invitedBy, email: info.email, role })
          : t("invite.descriptionNoInviter", { email: info.email, role })
      }
    >
      <form className="grid gap-4" onSubmit={submit}>
        {accept.isError && !(accept.error instanceof ApiError && accept.error.status === 422) ? (
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        ) : null}
        {info.hasAccount ? (
          <Alert tone="info">{t("invite.existingAccount")}</Alert>
        ) : (
          <>
            <Field
              label={t("invite.name")}
              name="name"
              required
              maxLength={100}
              autoComplete="name"
              error={fieldErrors.name}
            />
            <Field
              label={t("invite.password")}
              hint={t("invite.passwordHint")}
              name="password"
              type="password"
              required
              minLength={12}
              maxLength={256}
              autoComplete="new-password"
              error={fieldErrors.password}
            />
            <input type="email" name="username" value={info.email} autoComplete="username" readOnly hidden />
          </>
        )}
        <Button type="submit" disabled={accept.isPending}>
          {accept.isPending ? t("common.loading") : t("invite.submit")}
        </Button>
      </form>
    </AuthLayout>
  );
}
