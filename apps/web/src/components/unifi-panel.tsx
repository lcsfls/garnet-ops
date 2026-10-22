import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Fingerprint, FlaskConical, Pencil, Plus, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { formatDate, formatDateTime, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";
import type { UnifiConnection, UnifiConnections } from "../lib/types.ts";
import { UNIFI_CERT_COMMAND, useUnifiErrorText } from "../lib/unifi.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field, FormField } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { UnifiCertificateBadge } from "./unifi-view.tsx";
import { useStepUp } from "./use-step-up.tsx";

const refreshAll = (queryClient: ReturnType<typeof useQueryClient>) =>
  queryClient.invalidateQueries({
    predicate: (q) => String(q.queryKey[0]).startsWith("uf-") || String(q.queryKey[0]).startsWith("attack"),
  });

/** Settings → UniFi (owners and admins): consoles, strictly read-only, and the optional IPS preview (ADR 0022). */
export function UnifiPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useUnifiErrorText();
  const connections = useQuery({
    queryKey: ["uf-connections"],
    queryFn: () => api<UnifiConnections>("/unifi/connections"),
    // The worker reads the certificate and runs the first sync a moment after it is asked to.
    refetchInterval: (q) =>
      q.state.data?.items.some(
        (c) =>
          c.run?.state === "queued" ||
          c.run?.state === "running" ||
          (c.certificate.status === "pending" && !c.certificate.candidate && !c.lastError),
      )
        ? 2000
        : 30_000,
  });
  const [editing, setEditing] = useState<UnifiConnection | "new" | null>(null);
  const [certificate, setCertificate] = useState<string | null>(null);
  const [ips, setIps] = useState<string | null>(null);
  const [rights, setRights] = useState<string | null>(null);
  const [removing, setRemoving] = useState<UnifiConnection | null>(null);
  const [removeFailed, setRemoveFailed] = useState(false);
  const stepUp = useStepUp(me.user.email);

  const sync = useMutation({
    mutationFn: (id: string) => api(`/unifi/connections/${id}/sync`, { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const look = useMutation({
    mutationFn: (id: string) => api(`/unifi/connections/${id}/certificate/scan`, { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const toggle = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) =>
      api(`/unifi/connections/${input.id}`, { method: "PATCH", body: { enabled: input.enabled } }),
    onSuccess: () => refreshAll(queryClient),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/unifi/connections/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(null);
      await refreshAll(queryClient);
    },
    onError: (e, id) => {
      if (stepUp.handled(e, () => remove.mutate(id))) return setRemoving(null);
      setRemoveFailed(true);
    },
  });

  const items = connections.data?.items ?? [];
  const certConnection = items.find((c) => c.id === certificate) ?? null;
  const ipsConnection = items.find((c) => c.id === ips) ?? null;
  const rightsConnection = items.find((c) => c.id === rights) ?? null;

  return (
    <Card>
      <CardHeader
        title={t("unifi.panelTitle")}
        description={t("unifi.panelDescription")}
        actions={
          <Button variant="outline" onClick={() => setEditing("new")}>
            <Plus aria-hidden="true" className="size-4" />
            {t("unifi.addConnection")}
          </Button>
        }
      />
      <QueryStatus query={connections} />
      {sync.isError || look.isError || toggle.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      {connections.data && items.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("unifi.panelEmpty")}</p>
      ) : null}
      <ul>
        {items.map((connection) => {
          const busy = connection.run?.state === "queued" || connection.run?.state === "running";
          const failed =
            connection.lastError ?? (connection.run?.state === "failed" ? connection.run.error : null);
          const unreadCertificate =
            connection.certificate.status === "pending" && !connection.certificate.candidate;
          return (
            <li
              key={connection.id}
              className="grid gap-2 border-t px-5 py-3"
              data-testid={`uf-${connection.name}`}
            >
              <div className="flex flex-wrap items-start gap-3">
                <div className="min-w-0 flex-[1_1_18rem]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{connection.name}</span>
                    <UnifiCertificateBadge status={connection.certificate.status} />
                    {connection.ips.enabled ? (
                      <Badge tone="info">
                        <FlaskConical aria-hidden="true" />
                        {t("unifi.previewBadge")}
                      </Badge>
                    ) : null}
                    {connection.ips.rights.reported.length > 0 ? (
                      <Badge tone={connection.ips.rights.acknowledged ? "neutral" : "critical"}>
                        <ShieldAlert aria-hidden="true" />
                        {t(
                          connection.ips.rights.acknowledged
                            ? "unifi.rightsAcknowledgedBadge"
                            : "unifi.rightsBadge",
                        )}
                      </Badge>
                    ) : null}
                    {!connection.enabled ? <Badge tone="neutral">{t("unifi.disabled")}</Badge> : null}
                  </div>
                  <div className="font-mono text-sm break-all text-muted-foreground">{connection.apiUrl}</div>
                  <div className="mt-1 text-[13px] text-muted-foreground">
                    {connection.lastSyncAt
                      ? t("unifi.lastSync", { when: formatRelative(connection.lastSyncAt) })
                      : unreadCertificate
                        ? t("unifi.readingCertificate")
                        : connection.certificate.status === "pending"
                          ? t("unifi.waitingForCertificate")
                          : busy
                            ? t("unifi.syncing")
                            : t("unifi.neverSynced")}
                    {connection.version
                      ? ` · ${t("unifi.consoleVersion", { version: connection.version })}`
                      : ""}
                  </div>
                  {failed ? (
                    <div className="mt-1 text-sm text-destructive-text">{errorText(failed)}</div>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {connection.certificate.candidate ? (
                    <Button className="h-9" onClick={() => setCertificate(connection.id)}>
                      <Fingerprint aria-hidden="true" className="size-4" />
                      {t(
                        connection.certificate.status === "changed"
                          ? "unifi.reviewChange"
                          : "unifi.confirmCertificate",
                      )}
                    </Button>
                  ) : null}
                  {connection.certificate.status === "confirmed" ? (
                    <Button
                      variant="outline"
                      className="h-9"
                      disabled={busy || sync.isPending}
                      onClick={() => sync.mutate(connection.id)}
                    >
                      <RefreshCw aria-hidden="true" className="size-4" />
                      {busy ? t("unifi.syncing") : t("unifi.syncNow")}
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      className="h-9"
                      disabled={look.isPending || unreadCertificate}
                      onClick={() => look.mutate(connection.id)}
                    >
                      <Fingerprint aria-hidden="true" className="size-4" />
                      {t("unifi.lookAgain")}
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    className="h-9 px-2.5"
                    aria-label={`${t("unifi.editConnection")}: ${connection.name}`}
                    onClick={() => setEditing(connection)}
                  >
                    <Pencil aria-hidden="true" className="size-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    className="h-9 px-2.5"
                    aria-label={`${t("unifi.removeConnection")}: ${connection.name}`}
                    onClick={() => {
                      setRemoveFailed(false);
                      setRemoving(connection);
                    }}
                  >
                    <Trash2 aria-hidden="true" className="size-4" />
                  </Button>
                </div>
              </div>
              <label className="flex w-fit items-center gap-2 text-sm">
                <Checkbox
                  checked={connection.enabled}
                  onChange={(e) => toggle.mutate({ id: connection.id, enabled: e.target.checked })}
                  aria-label={`${t("unifi.syncEnabledHint", { minutes: connections.data?.syncIntervalMinutes ?? 15 })}: ${connection.name}`}
                />
                {t("unifi.syncEnabledHint", { minutes: connections.data?.syncIntervalMinutes ?? 15 })}
              </label>
              <IpsRow
                connection={connection}
                onOpen={() => setIps(connection.id)}
                onReviewRights={() => setRights(connection.id)}
              />
            </li>
          );
        })}
      </ul>
      <div className="border-t px-5 py-3 text-sm text-muted-foreground">
        {t("unifi.panelFooter")}{" "}
        <Link
          to="/servers"
          search={{ view: "unifi" }}
          className="text-primary-text underline-offset-4 hover:underline"
        >
          {t("unifi.openOverview")}
        </Link>
      </div>
      <ConnectionDialog me={me} connection={editing} onClose={() => setEditing(null)} />
      {certConnection ? (
        <CertificateDialog me={me} connection={certConnection} onClose={() => setCertificate(null)} />
      ) : null}
      {ipsConnection ? (
        <IpsDialog
          me={me}
          connection={ipsConnection}
          interval={connections.data?.ips.intervalSeconds ?? { min: 30, max: 600, default: 60 }}
          onClose={() => setIps(null)}
        />
      ) : null}
      {rightsConnection ? (
        <RightsDialog me={me} connection={rightsConnection} onClose={() => setRights(null)} />
      ) : null}
      <ConfirmDialog
        open={removing !== null}
        title={t("unifi.removeTitle", { name: removing?.name ?? "" })}
        description={t("unifi.removeDescription")}
        confirmLabel={t("unifi.removeConnection")}
        pending={remove.isPending}
        error={removeFailed ? t("errors.actionFailed") : null}
        onConfirm={() => removing && remove.mutate(removing.id)}
        onClose={() => setRemoving(null)}
      />
      {stepUp.dialog}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* The IPS preview of one console                                              */
/* -------------------------------------------------------------------------- */

function IpsRow({
  connection,
  onOpen,
  onReviewRights,
}: {
  connection: UnifiConnection;
  onOpen: () => void;
  onReviewRights: () => void;
}) {
  const { t } = useTranslation();
  const errorText = useUnifiErrorText();
  const queryClient = useQueryClient();
  const ips = connection.ips;
  const off = useMutation({
    mutationFn: () =>
      api(`/unifi/connections/${connection.id}/ips`, { method: "PUT", body: { enabled: false } }),
    onSuccess: () => refreshAll(queryClient),
  });
  return (
    <div className="mt-1 grid gap-1.5 rounded-md border px-3 py-2.5" data-testid="uf-ips">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{t("unifi.ipsSectionTitle")}</span>
        <Badge tone="outline">
          <FlaskConical aria-hidden="true" />
          {t("unifi.ipsPreview")}
        </Badge>
        <span className="text-sm text-muted-foreground" data-testid="uf-ips-state" data-state={ips.state}>
          {t("unifi.ipsStatusLine")}: {t(`unifi.ipsState.${ips.state}`)}
          {ips.state === "paused" && ips.reason
            ? ` · ${t(`unifi.ipsPaused.${ips.reason}` as MessageKey)}`
            : ""}
          {ips.state === "live" || ips.state === "waiting"
            ? ` · ${ips.lastEventAt ? t("unifi.ipsLastEvent", { when: formatRelative(ips.lastEventAt) }) : t("unifi.ipsNoEvents")}`
            : ""}
        </span>
      </div>
      {!ips.enabled ? <p className="text-sm text-muted-foreground">{t("unifi.ipsSectionText")}</p> : null}
      {ips.error ? <p className="text-sm text-destructive-text">{errorText(ips.error)}</p> : null}
      {ips.rights.reported.length > 0 ? (
        ips.rights.acknowledged ? (
          <p className="text-sm text-muted-foreground" data-testid="uf-rights-acknowledged">
            {t("unifi.rightsAcknowledgedText", {
              when: ips.rights.acknowledgedAt ? formatRelative(ips.rights.acknowledgedAt) : "",
            })}
          </p>
        ) : (
          <Alert tone="error">
            <span data-testid="uf-rights-blocked">{t("unifi.rightsBlocked")}</span>
          </Alert>
        )
      ) : null}
      {ips.username ? <p className="font-mono text-sm text-muted-foreground">{ips.username}</p> : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" className="h-9" onClick={onOpen}>
          {ips.enabled ? t("unifi.ipsChange") : t("unifi.ipsSetup")}
        </Button>
        {ips.rights.reported.length > 0 ? (
          <Button
            variant={ips.rights.acknowledged ? "outline" : "primary"}
            className="h-9"
            onClick={onReviewRights}
          >
            {t("unifi.rightsReview")}
          </Button>
        ) : null}
        {ips.enabled ? (
          <Button variant="ghost" className="h-9" disabled={off.isPending} onClick={() => off.mutate()}>
            {t("unifi.ipsDisable")}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function IpsDialog({
  me,
  connection,
  interval,
  onClose,
}: {
  me: Me;
  connection: UnifiConnection;
  interval: { min: number; max: number; default: number };
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [acknowledged, setAcknowledged] = useState(false);
  const [removing, setRemoving] = useState(false);
  const ips = connection.ips;

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api(`/unifi/connections/${connection.id}/ips`, { method: "PUT", body }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => save.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
        return setError(t("unifi.errorInvalid"));
      }
      setError(t("errors.actionFailed"));
    },
  });
  const removeUser = useMutation({
    mutationFn: () => api(`/unifi/connections/${connection.id}/ips`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(false);
      await refreshAll(queryClient);
      onClose();
    },
    onError: () => setError(t("errors.actionFailed")),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    const text = (k: string) => String(f.get(k) ?? "").trim();
    const password = String(f.get("password") ?? "");
    const body: Record<string, unknown> = { intervalSeconds: Number(text("intervalSeconds")) };
    if (text("username") !== (ips.username ?? "")) body.username = text("username");
    else if (!ips.enabled) body.username = text("username");
    if (password) body.password = password;
    if (!ips.enabled) {
      body.enabled = true;
      body.acknowledgePreview = acknowledged;
    }
    save.mutate(body);
  }
  const fieldError = (name: string) => {
    const code = fieldErrors[name];
    if (!code) return null;
    const key = `unifi.ipsFieldError.${code}`;
    return i18n.exists(key) ? t(key as MessageKey) : t("unifi.errorInvalid");
  };

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t("unifi.ipsTitle", { name: connection.name })}
        description={t("unifi.ipsIntro")}
      >
        <form className="grid gap-4" onSubmit={submit} noValidate>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Alert tone="info">{t("unifi.ipsWarning")}</Alert>
          <details open={!ips.enabled} className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">{t("unifi.ipsHowTitle")}</summary>
            <ol className="mt-3 grid list-decimal gap-1 pl-5 text-sm text-muted-foreground">
              <li>{t("unifi.ipsHowStep1")}</li>
              <li>{t("unifi.ipsHowStep2")}</li>
              <li>{t("unifi.ipsHowStep3")}</li>
            </ol>
          </details>
          <Field
            label={t("unifi.ipsUsername")}
            hint={t("unifi.ipsUsernameHint")}
            name="username"
            defaultValue={ips.username ?? ""}
            error={fieldError("username")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("unifi.ipsPassword")}
            hint={ips.hasPassword ? t("unifi.ipsPasswordKeep") : undefined}
            name="password"
            type="password"
            error={fieldError("password")}
            autoComplete="new-password"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("unifi.ipsInterval")}
            hint={t("unifi.ipsIntervalHint", { min: interval.min, max: interval.max })}
            name="intervalSeconds"
            type="number"
            min={interval.min}
            max={interval.max}
            step={1}
            defaultValue={ips.intervalSeconds}
            error={fieldError("intervalSeconds")}
          />
          {!ips.enabled ? (
            <div className="grid gap-1">
              <label className="flex items-start gap-2.5">
                <Checkbox
                  className="mt-1"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                  aria-invalid={fieldErrors.acknowledgePreview ? true : undefined}
                />
                <span>{t("unifi.ipsAcknowledge")}</span>
              </label>
              {fieldError("acknowledgePreview") ? (
                <p className="text-sm text-destructive-text">{fieldError("acknowledgePreview")}</p>
              ) : null}
            </div>
          ) : null}
          <DialogFooter>
            {ips.hasPassword ? (
              <Button variant="ghost" className="mr-auto" onClick={() => setRemoving(true)}>
                {t("unifi.ipsRemove")}
              </Button>
            ) : null}
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? t("common.loading") : ips.enabled ? t("unifi.ipsSave") : t("unifi.ipsEnable")}
            </Button>
          </DialogFooter>
        </form>
      </Dialog>
      <ConfirmDialog
        open={removing}
        title={t("unifi.ipsRemoveTitle")}
        description={t("unifi.ipsRemoveDescription")}
        confirmLabel={t("unifi.ipsRemove")}
        pending={removeUser.isPending}
        error={null}
        onConfirm={() => removeUser.mutate()}
        onClose={() => setRemoving(false)}
      />
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Add and edit                                                                */
/* -------------------------------------------------------------------------- */

function ConnectionDialog({
  me,
  connection,
  onClose,
}: {
  me: Me;
  connection: UnifiConnection | "new" | null;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const existing = connection && connection !== "new" ? connection : null;

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      existing
        ? api(`/unifi/connections/${existing.id}`, { method: "PATCH", body })
        : api("/unifi/connections", { method: "POST", body }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async () => {
      await refreshAll(queryClient);
      close();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => save.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
        return setError(t("unifi.errorInvalid"));
      }
      if (e instanceof ApiError && e.code === "duplicate") return setError(t("unifi.errorDuplicate"));
      if (e instanceof ApiError && e.code === "limit-reached") return setError(t("unifi.errorLimit"));
      setError(t("errors.actionFailed"));
    },
  });
  function close() {
    setError(null);
    setFieldErrors({});
    onClose();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    const s = (k: string) => String(f.get(k) ?? "").trim();
    const key = String(f.get("apiKey") ?? "").trim();
    if (!existing) {
      return save.mutate({ name: s("name"), apiUrl: s("apiUrl"), apiKey: key, apiBase: s("apiBase") });
    }
    const body: Record<string, unknown> = {};
    if (s("name") !== existing.name) body.name = s("name");
    if (s("apiUrl") !== existing.apiUrl) body.apiUrl = s("apiUrl");
    if (s("apiBase") !== existing.apiBase) body.apiBase = s("apiBase");
    if (key) body.apiKey = key;
    if (Object.keys(body).length === 0) return close();
    save.mutate(body);
  }
  const fieldError = (name: string) => {
    const code = fieldErrors[name];
    if (!code) return null;
    const key = `unifi.fieldError.${code}`;
    return i18n.exists(key) ? t(key as MessageKey) : t("unifi.errorInvalid");
  };

  return (
    <>
      <Dialog
        open={connection !== null}
        onClose={close}
        title={existing ? t("unifi.editTitle", { name: existing.name }) : t("unifi.addTitle")}
        description={t("unifi.addDescription")}
      >
        <form className="grid gap-4" onSubmit={submit} noValidate>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <details open={!existing} className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">{t("unifi.howToTitle")}</summary>
            <div className="mt-3 grid gap-3 text-sm">
              <ol className="grid list-decimal gap-1 pl-5 text-muted-foreground">
                <li>{t("unifi.howToStep1")}</li>
                <li>{t("unifi.howToStep2")}</li>
                <li>{t("unifi.howToStep3")}</li>
              </ol>
              <Alert tone="info">{t("unifi.howToCloud")}</Alert>
              <p className="text-muted-foreground">{t("unifi.howToScope")}</p>
            </div>
          </details>
          <Field
            label={t("unifi.name")}
            name="name"
            required
            maxLength={80}
            defaultValue={existing?.name ?? ""}
            error={fieldError("name")}
            autoComplete="off"
          />
          <Field
            label={t("unifi.apiUrl")}
            hint={t("unifi.apiUrlHint")}
            name="apiUrl"
            required
            defaultValue={existing?.apiUrl ?? ""}
            placeholder="https://udm.example.lan"
            error={fieldError("apiUrl")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("unifi.apiKey")}
            hint={existing ? t("unifi.apiKeyKeep") : t("unifi.apiKeyHint")}
            name="apiKey"
            type="password"
            required={!existing}
            error={fieldError("apiKey")}
            autoComplete="new-password"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <FormField label={t("unifi.apiBase")} hint={t("unifi.apiBaseHint")}>
            {(control) => (
              <Select name="apiBase" defaultValue={existing?.apiBase ?? "auto"} {...control}>
                {(["auto", "unifi-os", "network-app"] as const).map((v) => (
                  <option key={v} value={v}>
                    {t(`unifi.apiBaseOption.${v}`)}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending
                ? t("common.loading")
                : existing
                  ? t("unifi.saveChanges")
                  : t("unifi.saveAndRead")}
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
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
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
        <dt className="text-muted-foreground">{t("unifi.certSubject")}</dt>
        <dd className="font-mono break-all">{subject ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("unifi.certIssuer")}</dt>
        <dd className="font-mono break-all">{issuer ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("unifi.certValid")}</dt>
        <dd>
          {validFrom ? formatDate(validFrom) : "–"} – {validTo ? formatDate(validTo) : "–"}
          {validTo && new Date(validTo) < new Date() ? (
            <span className="ml-2 text-destructive-text">{t("unifi.certExpired")}</span>
          ) : null}
        </dd>
      </dl>
    </section>
  );
}

/**
 * Confirming a certificate (ADR 0022): the admin compares the fingerprint GarnetOps read with the one the console
 * shows, and the API pins exactly the fingerprint that was shown. A change is a security event, so the dialog says so
 * and shows both certificates.
 */
function CertificateDialog({
  me,
  connection,
  onClose,
}: {
  me: Me;
  connection: UnifiConnection;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const candidate = connection.certificate.candidate;
  const changed = connection.certificate.status === "changed";

  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api<{ runId: string }>(`/unifi/connections/${connection.id}/certificate/confirm`, {
        method: "POST",
        body: { fingerprint },
      }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: async (e, fingerprint) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await refreshAll(queryClient);
        return setError(t("unifi.certMismatch"));
      }
      if (e instanceof ApiError && e.code === "no-certificate") return setError(t("unifi.noCertificate"));
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t(changed ? "unifi.certChangedTitle" : "unifi.certTitle", { name: connection.name })}
        description={t(changed ? "unifi.certChangedText" : "unifi.certIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          {changed && connection.certificate.fingerprint ? (
            <CertificateFacts
              label={t("unifi.certPinned")}
              fingerprint={connection.certificate.fingerprint}
              subject={connection.certificate.subject}
              issuer={connection.certificate.issuer}
              validFrom={connection.certificate.validFrom}
              validTo={connection.certificate.validTo}
            />
          ) : null}
          {candidate ? (
            <CertificateFacts
              label={changed ? t("unifi.certOffered") : t("unifi.certPresented")}
              fingerprint={candidate.fingerprint}
              subject={candidate.subject}
              issuer={candidate.issuer}
              validFrom={candidate.validFrom}
              validTo={candidate.validTo}
            />
          ) : null}
          {candidate ? (
            <p className="text-sm text-muted-foreground">
              {candidate.caTrusted ? t("unifi.certCaTrusted") : t("unifi.certSelfSigned")}
              {candidate.seenAt ? ` ${t("unifi.certSeen", { when: formatDateTime(candidate.seenAt) })}` : ""}
            </p>
          ) : null}
          <div className="grid gap-1 text-sm text-muted-foreground">
            <span>{t("unifi.certCompare")}</span>
            <code className="font-mono break-all text-foreground">{UNIFI_CERT_COMMAND}</code>
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
                : t(changed ? "unifi.certConfirmChange" : "unifi.certConfirm")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Rights beyond viewing                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The IPS user can do more than view, as far as the console says. The admin sees exactly the list and acknowledges
 * exactly that list (step-up, audited). If the console reports other rights later, the acknowledgement is void.
 */
function RightsDialog({
  me,
  connection,
  onClose,
}: {
  me: Me;
  connection: UnifiConnection;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reported = connection.ips.rights.reported;

  const acknowledge = useMutation({
    mutationFn: (rights: string[]) =>
      api(`/unifi/connections/${connection.id}/ips/rights/acknowledge`, { method: "POST", body: { rights } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: async (e, rights) => {
      if (stepUp.handled(e, () => acknowledge.mutate(rights))) return;
      if (e instanceof ApiError && (e.code === "rights-changed" || e.code === "no-extra-rights")) {
        await refreshAll(queryClient);
        return setError(t("unifi.rightsChanged"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t("unifi.rightsTitle", { name: connection.name })}
        description={t("unifi.rightsIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Alert tone="error">{t("unifi.rightsWarning")}</Alert>
          <ul
            aria-label={t("unifi.rightsList")}
            className="flex flex-wrap gap-1.5"
            data-testid="uf-rights-list"
          >
            {reported.map((p) => (
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
            <span>{t("unifi.rightsUnderstood")}</span>
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              disabled={!understood || reported.length === 0 || acknowledge.isPending}
              onClick={() => acknowledge.mutate(reported)}
            >
              {acknowledge.isPending ? t("common.loading") : t("unifi.rightsAcknowledge")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
