import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { QrCode } from "../components/qr-code.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";
import { Checkbox } from "../components/ui/checkbox.tsx";
import { CopyButton } from "../components/ui/copy-button.tsx";
import { Field } from "../components/ui/field.tsx";
import { authClient, authErrorKey, directoryMe } from "../lib/auth-client.ts";
import { guard } from "../lib/guard.ts";
import type { MessageKey } from "../lib/i18n.ts";

/**
 * Mandatory TOTP enrolment (AGENTS.md rule 1): a signed-in user without a
 * second factor lands here and cannot reach anything else except signing out.
 */
export const Route = createFileRoute("/enroll")({
  beforeLoad: ({ context }) => guard(context.queryClient, ["enroll"]),
  component: Enroll,
});

type Step =
  | { kind: "password" }
  | { kind: "scan"; uri: string; backupCodes: string[] }
  | { kind: "backup"; backupCodes: string[] };

function Enroll() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState<Step>({ kind: "password" });
  // A directory account has no local password to ask for (ADR 0020).
  const account = useQuery({
    queryKey: ["directory-me"],
    queryFn: async () => (await directoryMe()).data?.managed === true,
  });
  const managed = account.data === true;
  const [error, setError] = useState<MessageKey | null>(null);
  const [busy, setBusy] = useState(false);

  async function signOut() {
    await authClient.signOut();
    await queryClient.invalidateQueries();
    await navigate({ to: "/sign-in" });
  }
  const footer = (
    <Button variant="link" onClick={signOut}>
      {t("common.signOut")}
    </Button>
  );

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = managed ? "" : String(new FormData(event.currentTarget).get("password"));
    setBusy(true);
    setError(null);
    const { data, error } = await authClient.twoFactor.enable({ password });
    setBusy(false);
    if (error || data?.method !== "totp") return setError(authErrorKey(error));
    setStep({ kind: "scan", uri: data.totpURI, backupCodes: data.backupCodes });
  }

  async function confirm(event: FormEvent<HTMLFormElement>, backupCodes: string[]) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code")).replace(/\s+/g, "");
    setBusy(true);
    setError(null);
    const { error } = await authClient.twoFactor.verifyTotp({ code });
    setBusy(false);
    if (error) return setError(authErrorKey(error));
    setStep({ kind: "backup", backupCodes });
  }

  async function finish() {
    await queryClient.invalidateQueries();
    await navigate({ to: "/" });
  }

  if (step.kind === "password") {
    return (
      <AuthLayout
        title={t("enroll.title")}
        description={managed ? t("enroll.descriptionDirectory") : t("enroll.description")}
        footer={footer}
      >
        <form className="grid gap-4" onSubmit={start}>
          {error ? <Alert tone="error">{t(error)}</Alert> : null}
          {managed ? null : (
            <Field
              label={t("common.password")}
              name="password"
              type="password"
              required
              autoComplete="current-password"
            />
          )}
          <Button type="submit" disabled={busy || account.isLoading}>
            {busy ? t("common.loading") : t("enroll.start")}
          </Button>
        </form>
      </AuthLayout>
    );
  }

  if (step.kind === "scan") {
    const secret = new URL(step.uri).searchParams.get("secret") ?? "";
    return (
      <AuthLayout title={t("enroll.scanTitle")} description={t("enroll.scanDescription")} footer={footer}>
        <form className="grid gap-5" onSubmit={(e) => confirm(e, step.backupCodes)}>
          {error ? <Alert tone="error">{t(error)}</Alert> : null}
          <div className="flex justify-center">
            <QrCode value={step.uri} label={t("enroll.qrLabel")} />
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
          <Button type="submit" disabled={busy}>
            {busy ? t("common.loading") : t("enroll.confirm")}
          </Button>
        </form>
      </AuthLayout>
    );
  }

  return <BackupCodes codes={step.backupCodes} onFinish={finish} />;
}

function BackupCodes({ codes, onFinish }: { codes: string[]; onFinish: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout title={t("enroll.backupTitle")} description={t("enroll.backupDescription")}>
      <div className="grid gap-5">
        <ul className="grid grid-cols-2 gap-2 rounded-md bg-muted p-4 font-mono text-sm">
          {codes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ul>
        <div className="flex justify-end">
          <CopyButton text={codes.join("\n")} />
        </div>
        <label className="flex items-start gap-2.5 text-sm">
          <Checkbox className="mt-0.5" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          {t("enroll.backupConfirm")}
        </label>
        <Button disabled={!saved} onClick={onFinish}>
          {t("enroll.finish")}
        </Button>
      </div>
    </AuthLayout>
  );
}
