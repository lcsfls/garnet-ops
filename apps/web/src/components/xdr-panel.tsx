import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Fingerprint, Pencil, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { formatDate, formatDateTime, formatRelative } from "../lib/format.ts";
import type { Me } from "../lib/session.ts";
import type { XdrConnection, XdrConnectionResponse, XdrEndpoint } from "../lib/types.ts";
import { useWazuhErrorText } from "../lib/xdr.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge, type BadgeTone } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field, TextAreaField } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";

const refreshAll = (queryClient: ReturnType<typeof useQueryClient>) =>
  queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("xdr-") });

/** The commands that show the fingerprint of the certificate, on the Wazuh server (default paths of a Wazuh installation). */
const FINGERPRINT_COMMANDS = {
  manager: "openssl x509 -in /var/ossec/api/configuration/ssl/server.crt -noout -fingerprint -sha256",
  indexer: "openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -fingerprint -sha256",
} as const;

/** Pinned is the normal state and neutral: a pinned certificate proves nothing (AGENTS.md rule 6). */
function CertificateBadge({ endpoint }: { endpoint: XdrEndpoint }) {
  const { t } = useTranslation();
  const status = endpoint.certificate.status;
  const tone: BadgeTone = status === "changed" ? "critical" : status === "pending" ? "info" : "neutral";
  const Icon = status === "changed" ? ShieldAlert : ShieldCheck;
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {endpoint.trust === "ca" && status === "confirmed"
        ? t("xdr.certificate.authority")
        : t(`xdr.certificate.${status}`)}
    </Badge>
  );
}

/** Settings, XDR / Wazuh (owners and admins): the connection to a customer-run Wazuh, strictly read-only (ADR 0015). */
export function XdrPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useWazuhErrorText();
  const response = useQuery({
    queryKey: ["xdr-connection"],
    queryFn: () => api<XdrConnectionResponse>("/xdr/connection"),
    // The worker reads the certificates and runs the first sync a moment after it is asked to.
    refetchInterval: (q) => {
      const c = q.state.data?.connection;
      if (!c) return 30_000;
      const waiting =
        c.run?.state === "queued" ||
        c.run?.state === "running" ||
        c.endpoints.some(
          (e) =>
            e.certificate.status === "pending" &&
            !e.certificate.candidate &&
            !e.lastError &&
            e.trust === "pin",
        );
      return waiting ? 2000 : 30_000;
    },
  });
  const [editing, setEditing] = useState<XdrConnection | "new" | null>(null);
  const [certificate, setCertificate] = useState<"manager" | "indexer" | null>(null);
  const [privileges, setPrivileges] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [removeFailed, setRemoveFailed] = useState(false);
  const stepUp = useStepUp(me.user.email);
  const connection = response.data?.connection ?? null;

  const sync = useMutation({
    mutationFn: () => api("/xdr/sync", { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const look = useMutation({
    mutationFn: (kind: "manager" | "indexer") =>
      api(`/xdr/endpoints/${kind}/certificate/scan`, { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api("/xdr/connection", { method: "PATCH", body: { enabled } }),
    onSuccess: () => refreshAll(queryClient),
  });
  const remove = useMutation({
    mutationFn: () => api("/xdr/connection", { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(false);
      await refreshAll(queryClient);
    },
    onError: (e) => {
      if (stepUp.handled(e, () => remove.mutate())) return setRemoving(false);
      setRemoveFailed(true);
    },
  });

  const busy = connection?.run?.state === "queued" || connection?.run?.state === "running";
  const failed = connection
    ? (connection.lastError ?? (connection.run?.state === "failed" ? connection.run.error : null))
    : null;
  const allConfirmed = connection?.endpoints.every((e) => e.certificate.status === "confirmed") ?? false;
  const privilegesOpen = connection
    ? connection.privileges.extra.length > 0 && !connection.privileges.acknowledged
    : false;

  return (
    <Card>
      <CardHeader
        title={t("xdr.settings.title")}
        description={t("xdr.settings.description")}
        actions={
          connection ? null : (
            <Button variant="outline" onClick={() => setEditing("new")}>
              <Plus aria-hidden="true" className="size-4" />
              {t("xdr.settings.connect")}
            </Button>
          )
        }
      />
      <QueryStatus query={response} />
      {sync.isError || look.isError || toggle.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      {response.data && !connection ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("xdr.settings.empty")}</p>
      ) : null}
      {connection ? (
        <div className="grid gap-2 border-t px-5 py-3" data-testid={`xdr-${connection.name}`}>
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-[1_1_18rem]">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{connection.name}</span>
                {connection.adapter ? (
                  <Badge tone="neutral">{t(`xdr.adapterName.${connection.adapter.id}`)}</Badge>
                ) : null}
                {connection.adapter?.preview ? <Badge tone="info">{t("xdr.preview")}</Badge> : null}
                {privilegesOpen ? (
                  <Badge tone="critical">
                    <ShieldAlert aria-hidden="true" />
                    {t("xdr.privilegesBadge")}
                  </Badge>
                ) : null}
                {!connection.enabled ? <Badge tone="neutral">{t("xdr.settings.disabled")}</Badge> : null}
              </div>
              <div className="mt-1 text-[13px] text-muted-foreground">
                {connection.lastSyncAt
                  ? t("xdr.settings.lastSync", { when: formatRelative(connection.lastSyncAt) })
                  : busy
                    ? t("xdr.settings.syncingNow")
                    : !allConfirmed
                      ? t("xdr.settings.waitingForCertificate")
                      : t("xdr.settings.neverSynced")}
                {connection.managerVersion ? ` · Wazuh ${connection.managerVersion}` : ""}
              </div>
              {failed ? <div className="mt-1 text-sm text-destructive-text">{errorText(failed)}</div> : null}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {privilegesOpen ? (
                <Button className="h-9" onClick={() => setPrivileges(true)}>
                  <ShieldAlert aria-hidden="true" className="size-4" />
                  {t("xdr.settings.reviewPrivileges")}
                </Button>
              ) : null}
              {allConfirmed ? (
                <Button
                  variant="outline"
                  className="h-9"
                  disabled={busy || sync.isPending}
                  onClick={() => sync.mutate()}
                >
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {busy
                    ? t("xdr.settings.syncingNow")
                    : t(privilegesOpen ? "xdr.settings.checkAgain" : "xdr.settings.syncNow")}
                </Button>
              ) : null}
              <Button
                variant="ghost"
                className="h-9 px-2.5"
                aria-label={`${t("xdr.settings.edit")}: ${connection.name}`}
                onClick={() => setEditing(connection)}
              >
                <Pencil aria-hidden="true" className="size-4" />
              </Button>
              <Button
                variant="ghost"
                className="h-9 px-2.5"
                aria-label={`${t("xdr.settings.remove")}: ${connection.name}`}
                onClick={() => {
                  setRemoveFailed(false);
                  setRemoving(true);
                }}
              >
                <Trash2 aria-hidden="true" className="size-4" />
              </Button>
            </div>
          </div>

          <ul className="grid gap-2 @xl:grid-cols-2">
            {connection.endpoints.map((endpoint) => (
              <li
                key={endpoint.kind}
                className="rounded-lg border px-3.5 py-3"
                data-testid={`xdr-endpoint-${endpoint.kind}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {endpoint.kind === "manager"
                      ? t("xdr.settings.endpointManager")
                      : t("xdr.settings.endpointIndexer")}
                  </span>
                  <CertificateBadge endpoint={endpoint} />
                </div>
                <div className="font-mono text-sm break-all text-muted-foreground">{endpoint.apiUrl}</div>
                <div className="font-mono text-[13px] break-all text-muted-foreground">
                  {t("xdr.settings.user")}: {endpoint.username}
                </div>
                <div className="text-[13px] text-muted-foreground">
                  {endpoint.trust === "ca"
                    ? `${t("xdr.settings.trustAuthority")}${endpoint.ca?.subjects.length ? ` · ${endpoint.ca.subjects.join("; ")}` : ""}`
                    : t("xdr.settings.trustPin")}
                </div>
                {endpoint.lastError && endpoint.certificate.status !== "confirmed" ? (
                  <div className="mt-1 text-sm text-destructive-text">{errorText(endpoint.lastError)}</div>
                ) : null}
                <div className="mt-2 flex flex-wrap gap-2">
                  {endpoint.certificate.candidate && endpoint.trust === "pin" ? (
                    <Button className="h-8 px-3 text-sm" onClick={() => setCertificate(endpoint.kind)}>
                      <Fingerprint aria-hidden="true" className="size-3.5" />
                      {t(
                        endpoint.certificate.status === "changed"
                          ? "xdr.settings.reviewChange"
                          : "xdr.settings.reviewCertificate",
                      )}
                    </Button>
                  ) : null}
                  {endpoint.certificate.status !== "confirmed" || endpoint.trust === "ca" ? (
                    <Button
                      variant="outline"
                      className="h-8 px-3 text-sm"
                      disabled={look.isPending}
                      onClick={() => look.mutate(endpoint.kind)}
                    >
                      <Fingerprint aria-hidden="true" className="size-3.5" />
                      {t("xdr.settings.lookAgain")}
                    </Button>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>

          <div className="grid gap-0.5 text-[13px] text-muted-foreground">
            {connection.dashboardUrl ? (
              <span className="break-all">
                {t("xdr.settings.dashboardLine", { url: connection.dashboardUrl })}
              </span>
            ) : null}
            {connection.enrollmentHost ? (
              <span className="break-all">
                {t("xdr.settings.enrollmentLine", { host: connection.enrollmentHost })}
              </span>
            ) : null}
          </div>

          <label className="flex w-fit items-center gap-2 text-sm">
            <Checkbox
              checked={connection.enabled}
              onChange={(e) => toggle.mutate(e.target.checked)}
              aria-label={`${t("xdr.settings.syncEnabled")}: ${connection.name}`}
            />
            {t("xdr.settings.syncEnabledHint", { minutes: response.data?.syncIntervalMinutes ?? 15 })}
          </label>
        </div>
      ) : null}
      {connection ? (
        <div className="border-t px-5 py-3 text-sm text-muted-foreground">
          {t("xdr.settings.footer")}{" "}
          <Link to="/xdr" className="text-primary-text underline-offset-4 hover:underline">
            {t("xdr.settings.openPage")}
          </Link>
        </div>
      ) : null}

      <ConnectionDialog me={me} connection={editing} onClose={() => setEditing(null)} />
      {connection && certificate ? (
        <CertificateDialog
          me={me}
          endpoint={connection.endpoints.find((e) => e.kind === certificate) as XdrEndpoint}
          onClose={() => setCertificate(null)}
        />
      ) : null}
      {connection && privileges ? (
        <PrivilegesDialog me={me} connection={connection} onClose={() => setPrivileges(false)} />
      ) : null}
      <ConfirmDialog
        open={removing}
        title={t("xdr.settings.removeTitle", { name: connection?.name ?? "" })}
        description={t("xdr.settings.removeDescription")}
        confirmLabel={t("xdr.settings.remove")}
        pending={remove.isPending}
        error={removeFailed ? t("errors.actionFailed") : null}
        onConfirm={() => remove.mutate()}
        onClose={() => setRemoving(false)}
      />
      {stepUp.dialog}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Connect and edit                                                            */
/* -------------------------------------------------------------------------- */

function ConnectionDialog({
  me,
  connection,
  onClose,
}: {
  me: Me;
  connection: XdrConnection | "new" | null;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [removeCa, setRemoveCa] = useState<{ manager: boolean; indexer: boolean }>({
    manager: false,
    indexer: false,
  });
  const existing = connection && connection !== "new" ? connection : null;
  const endpointOf = (kind: "manager" | "indexer") => existing?.endpoints.find((e) => e.kind === kind);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      existing
        ? api("/xdr/connection", { method: "PATCH", body })
        : api("/xdr/connection", { method: "POST", body }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async () => {
      await refreshAll(queryClient);
      await queryClient.invalidateQueries({ queryKey: ["xdr-status"] });
      close();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => save.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
        return setError(t("xdr.settings.errorInvalid"));
      }
      if (e instanceof ApiError && e.code === "duplicate") return setError(t("xdr.settings.errorDuplicate"));
      if (e instanceof ApiError && e.code === "limit-reached") return setError(t("xdr.settings.errorLimit"));
      setError(t("errors.actionFailed"));
    },
  });
  function close() {
    setError(null);
    setFieldErrors({});
    setRemoveCa({ manager: false, indexer: false });
    onClose();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    const s = (k: string) => String(f.get(k) ?? "").trim();
    const raw = (k: string) => String(f.get(k) ?? "");
    if (!existing) {
      return save.mutate({
        name: s("name"),
        dashboardUrl: s("dashboardUrl") || undefined,
        enrollmentHost: s("enrollmentHost") || undefined,
        managerApiUrl: s("managerApiUrl"),
        managerUsername: s("managerUsername"),
        managerPassword: raw("managerPassword"),
        managerCaPem: s("managerCaPem") || undefined,
        indexerApiUrl: s("indexerApiUrl"),
        indexerUsername: s("indexerUsername"),
        indexerPassword: raw("indexerPassword"),
        indexerCaPem: s("indexerCaPem") || undefined,
      });
    }
    const body: Record<string, unknown> = {};
    if (s("name") !== existing.name) body.name = s("name");
    if (s("dashboardUrl") !== (existing.dashboardUrl ?? "")) body.dashboardUrl = s("dashboardUrl") || null;
    if (s("enrollmentHost") !== (existing.enrollmentHost ?? ""))
      body.enrollmentHost = s("enrollmentHost") || null;
    for (const kind of ["manager", "indexer"] as const) {
      const endpoint = endpointOf(kind);
      if (s(`${kind}ApiUrl`) !== (endpoint?.apiUrl ?? "")) body[`${kind}ApiUrl`] = s(`${kind}ApiUrl`);
      const password = raw(`${kind}Password`);
      if (password) {
        body[`${kind}Username`] = s(`${kind}Username`);
        body[`${kind}Password`] = password;
      } else if (s(`${kind}Username`) !== (endpoint?.username ?? "")) {
        body[`${kind}Username`] = s(`${kind}Username`);
      }
      if (s(`${kind}CaPem`)) body[`${kind}CaPem`] = s(`${kind}CaPem`);
      else if (removeCa[kind]) body[`${kind}CaPem`] = null;
    }
    if (Object.keys(body).length === 0) return close();
    save.mutate(body);
  }
  const fieldError = (name: string) => {
    const code = fieldErrors[name];
    if (!code) return null;
    const key = `xdr.settings.fieldError.${code}`;
    return i18n.exists(key) ? t(key as never) : t("xdr.settings.errorInvalid");
  };

  const endpointFields = (kind: "manager" | "indexer") => {
    const endpoint = endpointOf(kind);
    const section = kind === "manager" ? "managerSection" : "indexerSection";
    return (
      <fieldset className="grid gap-4 rounded-lg border px-3.5 pt-2 pb-4">
        <legend className="px-1.5 text-sm font-medium">{t(`xdr.settings.${section}`)}</legend>
        <Field
          label={t(kind === "manager" ? "xdr.settings.managerUrl" : "xdr.settings.indexerUrl")}
          hint={t(kind === "manager" ? "xdr.settings.managerUrlHint" : "xdr.settings.indexerUrlHint")}
          name={`${kind}ApiUrl`}
          required
          defaultValue={endpoint?.apiUrl ?? ""}
          placeholder={
            kind === "manager" ? "https://wazuh.example.lan:55000" : "https://wazuh-indexer.example.lan:9200"
          }
          error={fieldError(`${kind}ApiUrl`)}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          className="font-mono text-sm"
        />
        <div className="grid gap-4 @xl:grid-cols-2">
          <Field
            label={t("xdr.settings.username")}
            name={`${kind}Username`}
            required
            defaultValue={endpoint?.username ?? ""}
            placeholder={kind === "manager" ? "garnetops-api" : "garnetops-indexer"}
            error={fieldError(`${kind}Username`)}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("xdr.settings.password")}
            hint={existing ? t("xdr.settings.passwordKeep") : t("xdr.settings.passwordHint")}
            name={`${kind}Password`}
            type="password"
            required={!existing}
            error={fieldError(`${kind}Password`)}
            autoComplete="new-password"
            spellCheck={false}
            className="font-mono text-sm"
          />
        </div>
        <TextAreaField
          label={t("xdr.settings.certificateAuthority")}
          hint={
            endpoint?.trust === "ca"
              ? t("xdr.settings.certificateAuthorityKeep")
              : t("xdr.settings.certificateAuthorityHint")
          }
          name={`${kind}CaPem`}
          rows={4}
          error={fieldError(`${kind}CaPem`)}
          autoComplete="off"
          spellCheck={false}
          className="font-mono text-[13px]"
          placeholder="-----BEGIN CERTIFICATE-----"
        />
        {endpoint?.trust === "ca" ? (
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={removeCa[kind]}
              onChange={(e) => setRemoveCa((prev) => ({ ...prev, [kind]: e.target.checked }))}
            />
            {t("xdr.settings.removeAuthority")}
          </label>
        ) : null}
      </fieldset>
    );
  };

  return (
    <>
      <Dialog
        open={connection !== null}
        onClose={close}
        title={existing ? t("xdr.settings.editTitle", { name: existing.name }) : t("xdr.settings.addTitle")}
        description={t("xdr.settings.addDescription")}
      >
        <form className="grid gap-4" onSubmit={submit} noValidate>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <details open={!existing} className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">{t("xdr.settings.howToTitle")}</summary>
            <div className="mt-3 grid gap-2 text-sm text-muted-foreground">
              <p>{t("xdr.settings.howToManager")}</p>
              <p>{t("xdr.settings.howToIndexer")}</p>
              <p>{t("xdr.settings.howToDocs")}</p>
              <Alert tone="info">{t("xdr.settings.howToNever")}</Alert>
            </div>
          </details>
          <Field
            label={t("xdr.settings.name")}
            hint={t("xdr.settings.nameHint")}
            name="name"
            required
            maxLength={80}
            defaultValue={existing?.name ?? ""}
            error={fieldError("name")}
            autoComplete="off"
          />
          {endpointFields("manager")}
          {endpointFields("indexer")}
          <Field
            label={t("xdr.settings.dashboardUrl")}
            hint={t("xdr.settings.dashboardUrlHint")}
            name="dashboardUrl"
            defaultValue={existing?.dashboardUrl ?? ""}
            placeholder="https://wazuh-dashboard.example.lan"
            error={fieldError("dashboardUrl")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("xdr.settings.enrollmentHost")}
            hint={t("xdr.settings.enrollmentHostHint")}
            name="enrollmentHost"
            defaultValue={existing?.enrollmentHost ?? ""}
            placeholder="wazuh.example.lan"
            error={fieldError("enrollmentHost")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending
                ? t("common.loading")
                : existing
                  ? t("xdr.settings.saveChanges")
                  : t("xdr.settings.saveAndRead")}
            </Button>
          </DialogFooter>
        </form>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Certificate                                                                 */
/* -------------------------------------------------------------------------- */

function CertificateFacts({
  label,
  fingerprint,
  subject,
  issuer,
  validFrom,
  validTo,
}: {
  label: string;
  fingerprint: string;
  subject: string | null | undefined;
  issuer: string | null | undefined;
  validFrom: string | null | undefined;
  validTo: string | null | undefined;
}) {
  const { t } = useTranslation();
  return (
    <section aria-label={label} className="grid gap-2 rounded-md border px-3 py-3">
      <h3 className="text-sm font-medium">{label}</h3>
      <code
        className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all"
        data-testid="fingerprint"
      >
        {fingerprint}
      </code>
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("xdr.settings.certSubject")}</dt>
        <dd className="font-mono break-all">{subject ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("xdr.settings.certIssuer")}</dt>
        <dd className="font-mono break-all">{issuer ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("xdr.settings.certValid")}</dt>
        <dd>
          {validFrom ? formatDate(validFrom) : "–"} – {validTo ? formatDate(validTo) : "–"}
          {validTo && new Date(validTo) < new Date() ? (
            <span className="ml-2 text-destructive-text">{t("xdr.settings.certExpired")}</span>
          ) : null}
        </dd>
      </dl>
    </section>
  );
}

/**
 * Confirming a certificate (ADR 0015): the admin compares the fingerprint GarnetOps read with the
 * one the Wazuh server shows, and the API pins exactly the fingerprint that was shown. A change is
 * a security event, so the dialog says so and shows both certificates.
 */
function CertificateDialog({
  me,
  endpoint,
  onClose,
}: {
  me: Me;
  endpoint: XdrEndpoint;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const candidate = endpoint.certificate.candidate;
  const changed = endpoint.certificate.status === "changed";
  const name = t(`xdr.endpointName.${endpoint.kind}`);

  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api(`/xdr/endpoints/${endpoint.kind}/certificate/confirm`, { method: "POST", body: { fingerprint } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: async (e, fingerprint) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await refreshAll(queryClient);
        return setError(t("xdr.settings.certMismatch"));
      }
      if (e instanceof ApiError && e.code === "no-certificate")
        return setError(t("xdr.settings.noCertificate"));
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t(changed ? "xdr.settings.certChangedTitle" : "xdr.settings.certTitle", { endpoint: name })}
        description={t(changed ? "xdr.settings.certChangedText" : "xdr.settings.certIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          {changed && endpoint.certificate.fingerprint ? (
            <CertificateFacts
              label={t("xdr.settings.certPinned")}
              fingerprint={endpoint.certificate.fingerprint}
              subject={endpoint.certificate.subject}
              issuer={endpoint.certificate.issuer}
              validFrom={endpoint.certificate.validFrom}
              validTo={endpoint.certificate.validTo}
            />
          ) : null}
          {candidate ? (
            <CertificateFacts
              label={changed ? t("xdr.settings.certOffered") : t("xdr.settings.certPresented")}
              fingerprint={candidate.fingerprint}
              subject={candidate.subject}
              issuer={candidate.issuer}
              validFrom={candidate.validFrom}
              validTo={candidate.validTo}
            />
          ) : null}
          {candidate ? (
            <p className="text-sm text-muted-foreground">
              {candidate.caTrusted ? t("xdr.settings.certCaTrusted") : t("xdr.settings.certSelfSigned")}
              {candidate.seenAt
                ? ` ${t("xdr.settings.certSeen", { when: formatDateTime(candidate.seenAt) })}`
                : ""}
            </p>
          ) : null}
          <div className="grid gap-1 text-sm text-muted-foreground">
            <span>{t("xdr.settings.certCompare")}</span>
            <code className="font-mono break-all text-foreground">{FINGERPRINT_COMMANDS[endpoint.kind]}</code>
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
                : t(changed ? "xdr.settings.certConfirmChange" : "xdr.settings.certConfirm")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Privileges                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Users that can do more than read (ADR 0015). GarnetOps still only ever sends read requests,
 * but a stolen password would not be limited to that. Nothing is read until an admin has seen
 * exactly which privileges these are and says so.
 */
function PrivilegesDialog({
  me,
  connection,
  onClose,
}: {
  me: Me;
  connection: XdrConnection;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const extra = connection.privileges.extra;

  const acknowledge = useMutation({
    mutationFn: (list: string[]) =>
      api("/xdr/privileges/acknowledge", { method: "POST", body: { privileges: list } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: async (e, list) => {
      if (stepUp.handled(e, () => acknowledge.mutate(list))) return;
      if (e instanceof ApiError && e.code === "privileges-changed") {
        await refreshAll(queryClient);
        return setError(t("xdr.settings.privilegesChanged"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t("xdr.settings.privilegesTitle")}
        description={t("xdr.settings.privilegesIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Alert tone="error">{t("xdr.settings.privilegesWarning")}</Alert>
          <ul aria-label={t("xdr.settings.privilegesList")} className="flex flex-wrap gap-1.5">
            {extra.map((p) => (
              <li key={p}>
                <code className="rounded-md border bg-muted px-2 py-1 font-mono text-sm">{p}</code>
              </li>
            ))}
          </ul>
          <label className="flex items-start gap-2.5">
            <Checkbox
              className="mt-1"
              checked={understood}
              onChange={(e) => setUnderstood(e.target.checked)}
            />
            <span>{t("xdr.settings.privilegesUnderstood")}</span>
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button disabled={!understood || acknowledge.isPending} onClick={() => acknowledge.mutate(extra)}>
              {acknowledge.isPending ? t("common.loading") : t("xdr.settings.privilegesAcknowledge")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
