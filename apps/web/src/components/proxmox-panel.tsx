import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Fingerprint, Pencil, Plus, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { formatDate, formatDateTime, formatRelative } from "../lib/format.ts";
import { PVENODE_CERT_COMMAND, PVEUM_COMMANDS, useProxmoxErrorText } from "../lib/proxmox.ts";
import type { Me } from "../lib/session.ts";
import type { ProxmoxCluster, ProxmoxClusters } from "../lib/types.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { CertificateBadge } from "./proxmox-view.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { CopyButton } from "./ui/copy-button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";

const refreshAll = (queryClient: ReturnType<typeof useQueryClient>) =>
  queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("px-") });

/** Settings → Proxmox (owners and admins): connections to Proxmox VE clusters, strictly read-only (ADR 0012). */
export function ProxmoxPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useProxmoxErrorText();
  const clusters = useQuery({
    queryKey: ["px-clusters"],
    queryFn: () => api<ProxmoxClusters>("/proxmox/clusters"),
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
  const [editing, setEditing] = useState<ProxmoxCluster | "new" | null>(null);
  const [certificate, setCertificate] = useState<string | null>(null);
  const [privileges, setPrivileges] = useState<string | null>(null);
  const [removing, setRemoving] = useState<ProxmoxCluster | null>(null);
  const [removeFailed, setRemoveFailed] = useState(false);
  const stepUp = useStepUp(me.user.email);

  const sync = useMutation({
    mutationFn: (id: string) => api(`/proxmox/clusters/${id}/sync`, { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const look = useMutation({
    mutationFn: (id: string) => api(`/proxmox/clusters/${id}/certificate/scan`, { method: "POST" }),
    onSuccess: () => refreshAll(queryClient),
  });
  const toggle = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) =>
      api(`/proxmox/clusters/${input.id}`, { method: "PATCH", body: { enabled: input.enabled } }),
    onSuccess: () => refreshAll(queryClient),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/proxmox/clusters/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(null);
      await refreshAll(queryClient);
    },
    onError: (e, id) => {
      if (stepUp.handled(e, () => remove.mutate(id))) return setRemoving(null);
      setRemoveFailed(true);
    },
  });

  const items = clusters.data?.items ?? [];
  const certCluster = items.find((c) => c.id === certificate) ?? null;
  const privCluster = items.find((c) => c.id === privileges) ?? null;

  return (
    <Card>
      <CardHeader
        title={t("proxmox.panelTitle")}
        description={t("proxmox.panelDescription")}
        actions={
          <Button variant="outline" onClick={() => setEditing("new")}>
            <Plus aria-hidden="true" className="size-4" />
            {t("proxmox.addConnection")}
          </Button>
        }
      />
      <QueryStatus query={clusters} />
      {sync.isError || look.isError || toggle.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      {clusters.data && items.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("proxmox.panelEmpty")}</p>
      ) : null}
      <ul>
        {items.map((cluster) => {
          const busy = cluster.run?.state === "queued" || cluster.run?.state === "running";
          const failed = cluster.lastError ?? (cluster.run?.state === "failed" ? cluster.run.error : null);
          const unreadCertificate =
            cluster.certificate.status === "pending" && !cluster.certificate.candidate;
          return (
            <li key={cluster.id} className="grid gap-2 border-t px-5 py-3" data-testid={`px-${cluster.name}`}>
              <div className="flex flex-wrap items-start gap-3">
                <div className="min-w-0 flex-[1_1_18rem]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{cluster.name}</span>
                    <CertificateBadge status={cluster.certificate.status} />
                    {cluster.privileges.extra.length > 0 && !cluster.privileges.acknowledged ? (
                      <Badge tone="critical">
                        <ShieldAlert aria-hidden="true" />
                        {t("proxmox.privilegesBadge")}
                      </Badge>
                    ) : null}
                    {!cluster.enabled ? <Badge tone="neutral">{t("proxmox.disabled")}</Badge> : null}
                  </div>
                  <div className="font-mono text-sm break-all text-muted-foreground">{cluster.apiUrl}</div>
                  <div className="font-mono text-[13px] break-all text-muted-foreground">
                    {cluster.tokenId}
                  </div>
                  <div className="mt-1 text-[13px] text-muted-foreground">
                    {cluster.lastSyncAt
                      ? t("proxmox.lastSync", { when: formatRelative(cluster.lastSyncAt) })
                      : unreadCertificate
                        ? t("proxmox.readingCertificate")
                        : cluster.certificate.status === "pending"
                          ? t("proxmox.waitingForCertificate")
                          : busy
                            ? t("proxmox.syncing")
                            : t("proxmox.neverSynced")}
                    {cluster.version ? ` · Proxmox VE ${cluster.version}` : ""}
                  </div>
                  {failed ? (
                    <div className="mt-1 text-sm text-destructive-text">{errorText(failed)}</div>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {cluster.certificate.candidate ? (
                    <Button className="h-9" onClick={() => setCertificate(cluster.id)}>
                      <Fingerprint aria-hidden="true" className="size-4" />
                      {t(
                        cluster.certificate.status === "changed"
                          ? "proxmox.reviewChange"
                          : "proxmox.confirmCertificate",
                      )}
                    </Button>
                  ) : null}
                  {cluster.privileges.extra.length > 0 && !cluster.privileges.acknowledged ? (
                    <Button className="h-9" onClick={() => setPrivileges(cluster.id)}>
                      <ShieldAlert aria-hidden="true" className="size-4" />
                      {t("proxmox.reviewPrivileges")}
                    </Button>
                  ) : null}
                  {cluster.certificate.status === "confirmed" ? (
                    <Button
                      variant="outline"
                      className="h-9"
                      disabled={busy || sync.isPending}
                      onClick={() => sync.mutate(cluster.id)}
                    >
                      <RefreshCw aria-hidden="true" className="size-4" />
                      {busy
                        ? t("proxmox.syncing")
                        : t(cluster.privileges.acknowledged ? "proxmox.syncNow" : "proxmox.checkAgain")}
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      className="h-9"
                      disabled={look.isPending || unreadCertificate}
                      onClick={() => look.mutate(cluster.id)}
                    >
                      <Fingerprint aria-hidden="true" className="size-4" />
                      {t("proxmox.lookAgain")}
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    className="h-9 px-2.5"
                    aria-label={`${t("proxmox.editConnection")}: ${cluster.name}`}
                    onClick={() => setEditing(cluster)}
                  >
                    <Pencil aria-hidden="true" className="size-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    className="h-9 px-2.5"
                    aria-label={`${t("proxmox.removeConnection")}: ${cluster.name}`}
                    onClick={() => {
                      setRemoveFailed(false);
                      setRemoving(cluster);
                    }}
                  >
                    <Trash2 aria-hidden="true" className="size-4" />
                  </Button>
                </div>
              </div>
              <label className="flex w-fit items-center gap-2 text-sm">
                <Checkbox
                  checked={cluster.enabled}
                  onChange={(e) => toggle.mutate({ id: cluster.id, enabled: e.target.checked })}
                  aria-label={`${t("proxmox.syncEnabled")}: ${cluster.name}`}
                />
                {t("proxmox.syncEnabledHint", { minutes: clusters.data?.syncIntervalMinutes ?? 15 })}
              </label>
            </li>
          );
        })}
      </ul>
      <div className="border-t px-5 py-3 text-sm text-muted-foreground">
        {t("proxmox.panelFooter")}{" "}
        <Link
          to="/servers"
          search={{ view: "proxmox" }}
          className="text-primary-text underline-offset-4 hover:underline"
        >
          {t("proxmox.openOverview")}
        </Link>
      </div>
      <ConnectionDialog me={me} cluster={editing} onClose={() => setEditing(null)} />
      {certCluster ? (
        <CertificateDialog me={me} cluster={certCluster} onClose={() => setCertificate(null)} />
      ) : null}
      {privCluster ? (
        <PrivilegesDialog me={me} cluster={privCluster} onClose={() => setPrivileges(null)} />
      ) : null}
      <ConfirmDialog
        open={removing !== null}
        title={t("proxmox.removeTitle", { name: removing?.name ?? "" })}
        description={t("proxmox.removeDescription")}
        confirmLabel={t("proxmox.removeConnection")}
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
/* Add and edit                                                                */
/* -------------------------------------------------------------------------- */

function CommandBlock({ label, text }: { label: string; text: string }) {
  return (
    <div className="grid gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      <pre className="overflow-x-auto rounded-md border bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed">
        {text}
      </pre>
      <div>
        <CopyButton text={text} />
      </div>
    </div>
  );
}

function ConnectionDialog({
  me,
  cluster,
  onClose,
}: {
  me: Me;
  cluster: ProxmoxCluster | "new" | null;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const existing = cluster && cluster !== "new" ? cluster : null;

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      existing
        ? api(`/proxmox/clusters/${existing.id}`, { method: "PATCH", body })
        : api("/proxmox/clusters", { method: "POST", body }),
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
        return setError(t("proxmox.errorInvalid"));
      }
      if (e instanceof ApiError && e.code === "duplicate") return setError(t("proxmox.errorDuplicate"));
      if (e instanceof ApiError && e.code === "limit-reached") return setError(t("proxmox.errorLimit"));
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
    const secret = String(f.get("tokenSecret") ?? "");
    if (!existing) {
      return save.mutate({
        name: s("name"),
        apiUrl: s("apiUrl"),
        tokenId: s("tokenId"),
        tokenSecret: secret,
      });
    }
    const body: Record<string, unknown> = {};
    if (s("name") !== existing.name) body.name = s("name");
    if (s("apiUrl") !== existing.apiUrl) body.apiUrl = s("apiUrl");
    if (secret) {
      body.tokenId = s("tokenId");
      body.tokenSecret = secret;
    } else if (s("tokenId") !== existing.tokenId) {
      body.tokenId = s("tokenId");
    }
    if (Object.keys(body).length === 0) return close();
    save.mutate(body);
  }
  const fieldError = (name: string) => {
    const code = fieldErrors[name];
    if (!code) return null;
    const key = `proxmox.fieldError.${code}`;
    return i18n.exists(key) ? t(key as never) : t("proxmox.errorInvalid");
  };

  return (
    <>
      <Dialog
        open={cluster !== null}
        onClose={close}
        title={existing ? t("proxmox.editTitle", { name: existing.name }) : t("proxmox.addTitle")}
        description={t("proxmox.addDescription")}
      >
        <form className="grid gap-4" onSubmit={submit} noValidate>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <details open={!existing} className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">{t("proxmox.howToTitle")}</summary>
            <div className="mt-3 grid gap-3 text-sm">
              <ol className="grid list-decimal gap-1 pl-5 text-muted-foreground">
                <li>{t("proxmox.howToStep1")}</li>
                <li>{t("proxmox.howToStep2")}</li>
                <li>{t("proxmox.howToStep3")}</li>
              </ol>
              <CommandBlock label={t("proxmox.howToCommands")} text={PVEUM_COMMANDS} />
              <p className="text-muted-foreground">{t("proxmox.howToSecret")}</p>
              <Alert tone="info">{t("proxmox.howToNever")}</Alert>
            </div>
          </details>
          <Field
            label={t("proxmox.name")}
            name="name"
            required
            maxLength={80}
            defaultValue={existing?.name ?? ""}
            error={fieldError("name")}
            autoComplete="off"
          />
          <Field
            label={t("proxmox.apiUrl")}
            hint={t("proxmox.apiUrlHint")}
            name="apiUrl"
            required
            defaultValue={existing?.apiUrl ?? ""}
            placeholder="https://pve1.example.lan:8006"
            error={fieldError("apiUrl")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("proxmox.tokenId")}
            hint={t("proxmox.tokenIdHint")}
            name="tokenId"
            required
            defaultValue={existing?.tokenId ?? ""}
            placeholder="garnetops@pve!inventory"
            error={fieldError("tokenId")}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            label={t("proxmox.tokenSecret")}
            hint={existing ? t("proxmox.tokenSecretKeep") : t("proxmox.tokenSecretHint")}
            name="tokenSecret"
            type="password"
            required={!existing}
            error={fieldError("tokenSecret")}
            autoComplete="new-password"
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
                  ? t("proxmox.saveChanges")
                  : t("proxmox.saveAndRead")}
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
        <dt className="text-muted-foreground">{t("proxmox.certSubject")}</dt>
        <dd className="font-mono break-all">{subject ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("proxmox.certIssuer")}</dt>
        <dd className="font-mono break-all">{issuer ?? "–"}</dd>
        <dt className="text-muted-foreground">{t("proxmox.certValid")}</dt>
        <dd>
          {validFrom ? formatDate(validFrom) : "–"} – {validTo ? formatDate(validTo) : "–"}
          {validTo && new Date(validTo) < new Date() ? (
            <span className="ml-2 text-destructive-text">{t("proxmox.certExpired")}</span>
          ) : null}
        </dd>
      </dl>
    </section>
  );
}

/**
 * Confirming a certificate (ADR 0012): the admin compares the fingerprint GarnetOps read with the
 * one Proxmox shows, and the API pins exactly the fingerprint that was shown. A change is a
 * security event, so the dialog says so and shows both certificates.
 */
function CertificateDialog({
  me,
  cluster,
  onClose,
}: {
  me: Me;
  cluster: ProxmoxCluster;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const candidate = cluster.certificate.candidate;
  const changed = cluster.certificate.status === "changed";

  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api<{ runId: string }>(`/proxmox/clusters/${cluster.id}/certificate/confirm`, {
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
        return setError(t("proxmox.certMismatch"));
      }
      if (e instanceof ApiError && e.code === "no-certificate") return setError(t("proxmox.noCertificate"));
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t(changed ? "proxmox.certChangedTitle" : "proxmox.certTitle", { name: cluster.name })}
        description={t(changed ? "proxmox.certChangedText" : "proxmox.certIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          {changed && cluster.certificate.fingerprint ? (
            <CertificateFacts
              label={t("proxmox.certPinned")}
              fingerprint={cluster.certificate.fingerprint}
              subject={cluster.certificate.subject}
              issuer={cluster.certificate.issuer}
              validFrom={cluster.certificate.validFrom}
              validTo={cluster.certificate.validTo}
            />
          ) : null}
          {candidate ? (
            <CertificateFacts
              label={changed ? t("proxmox.certOffered") : t("proxmox.certPresented")}
              fingerprint={candidate.fingerprint}
              subject={candidate.subject}
              issuer={candidate.issuer}
              validFrom={candidate.validFrom}
              validTo={candidate.validTo}
            />
          ) : null}
          {candidate ? (
            <p className="text-sm text-muted-foreground">
              {candidate.caTrusted ? t("proxmox.certCaTrusted") : t("proxmox.certSelfSigned")}
              {candidate.seenAt
                ? ` ${t("proxmox.certSeen", { when: formatDateTime(candidate.seenAt) })}`
                : ""}
            </p>
          ) : null}
          <div className="grid gap-1 text-sm text-muted-foreground">
            <span>{t("proxmox.certCompare")}</span>
            <code className="font-mono break-all text-foreground">{PVENODE_CERT_COMMAND}</code>
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
                : t(changed ? "proxmox.certConfirmChange" : "proxmox.certConfirm")}
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
 * A token that can do more than read (ADR 0012). GarnetOps still only ever sends read requests,
 * but a stolen token would not be limited to that. The sync stays off until an admin has seen
 * exactly which privileges these are and says so.
 */
function PrivilegesDialog({
  me,
  cluster,
  onClose,
}: {
  me: Me;
  cluster: ProxmoxCluster;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const extra = cluster.privileges.extra;

  const acknowledge = useMutation({
    mutationFn: (privileges: string[]) =>
      api(`/proxmox/clusters/${cluster.id}/privileges/acknowledge`, { method: "POST", body: { privileges } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await refreshAll(queryClient);
      onClose();
    },
    onError: async (e, privileges) => {
      if (stepUp.handled(e, () => acknowledge.mutate(privileges))) return;
      if (e instanceof ApiError && e.code === "privileges-changed") {
        await refreshAll(queryClient);
        return setError(t("proxmox.privilegesChanged"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={t("proxmox.privilegesTitle", { name: cluster.name })}
        description={t("proxmox.privilegesIntro")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Alert tone="error">{t("proxmox.privilegesWarning")}</Alert>
          <ul aria-label={t("proxmox.privilegesList")} className="flex flex-wrap gap-1.5">
            {extra.map((p) => (
              <li key={p}>
                <code className="rounded-md border bg-muted px-2 py-1 font-mono text-sm">{p}</code>
              </li>
            ))}
          </ul>
          <p className="text-sm text-muted-foreground">{t("proxmox.privilegesFix")}</p>
          <label className="flex items-start gap-2.5">
            <Checkbox
              className="mt-1"
              checked={understood}
              onChange={(e) => setUnderstood(e.target.checked)}
            />
            <span>{t("proxmox.privilegesUnderstood")}</span>
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button disabled={!understood || acknowledge.isPending} onClick={() => acknowledge.mutate(extra)}>
              {acknowledge.isPending ? t("common.loading") : t("proxmox.privilegesAcknowledge")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
