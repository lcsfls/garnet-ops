import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Check } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import { formatDateTime } from "../lib/format.ts";
import { useHostErrorText } from "../lib/host-error.ts";
import type { Me } from "../lib/session.ts";
import type { HostAccess, HostDetail } from "../lib/types.ts";
import { Segmented } from "./filters.tsx";
import { hostKeyFile, KeyFingerprint } from "./host-key-dialog.tsx";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { CopyButton } from "./ui/copy-button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";
import { EnrollmentHelper, useWazuhConnected } from "./wazuh-enrollment.tsx";

const STEPS = ["stepServer", "stepPrepare", "stepKey", "stepDone"] as const;
type Method = "command" | "download" | "copy";

interface Script {
  script: string;
  /** The source addresses as written into the script (normalised by the API). */
  allowedSource: string;
  sha256: string;
  filename: string;
  keyFingerprint: string;
}
interface SetupLink {
  url: string;
  command: string;
  sha256: string;
  expiresAt: string;
}

/**
 * A server created from a Proxmox guest (ADR 0012) or a Wazuh agent (ADR 0015): the wizard starts
 * with its name and address and links the new server to it. The rest is the usual agentless SSH flow.
 */
export interface ServerPrefill {
  name: string;
  address: string;
  /** Every address the guest is known by; the first is the proposal. */
  addresses: string[];
  source: "proxmox" | "wazuh";
  sourceRef: string;
  /** A Proxmox guest (ADR 0012) or a Wazuh agent (ADR 0015). */
  origin: { guest: string; cluster: string; vmid: number } | { agent: string; connection: string };
}

/** Field errors by field name, from a 422 whose messages are codes the web app translates. */
function fieldErrorsOf(e: ApiError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const x of e.problem?.errors ?? []) {
    const field = x.path.split(".")[0] ?? "";
    if (field && !out[field]) out[field] = x.message;
  }
  return out;
}

function saveAsFile(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/x-shellscript" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Add a server in four steps (ADR 0011): where it is and which address may use the key,
 * the setup script (one command, download or copy), the host key to confirm, and the first
 * inventory. The wizard can continue the setup of a server that was added earlier.
 */
export function AddServerWizard({
  open,
  hostId: existingId,
  me,
  onClose,
  prefill,
}: {
  open: boolean;
  /** Continue the setup of this server instead of adding a new one. */
  hostId?: string | null;
  me: Me;
  onClose: () => void;
  prefill?: ServerPrefill | undefined;
}) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [step, setStep] = useState(0);
  const [hostId, setHostId] = useState<string | null>(null);
  const [source, setSource] = useState("");
  const [script, setScript] = useState<Script | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const id = existingId ?? hostId;
  const wazuhConnected = useWazuhConnected();

  const access = useQuery({
    queryKey: ["host-access"],
    queryFn: () => api<HostAccess>("/hosts/access"),
    enabled: open,
    // The worker creates the key a moment after it is asked to.
    refetchInterval: (q) => (q.state.data?.ready ? false : 2000),
  });
  const ensured = useRef(false);
  useEffect(() => {
    if (open && access.data && !access.data.ready && !ensured.current) {
      ensured.current = true;
      void api("/hosts/access", { method: "POST" }).catch(() => {});
    }
  }, [open, access.data]);
  // Offer the source addresses of the last script.
  useEffect(() => {
    if (open && access.data?.allowedSource) setSource((s) => s || (access.data?.allowedSource ?? ""));
  }, [open, access.data?.allowedSource]);

  const existing = useQuery({
    queryKey: ["host", existingId],
    queryFn: () => api<HostDetail>(`/hosts/${existingId}`),
    enabled: open && Boolean(existingId),
  });

  function reset() {
    setStep(0);
    setHostId(null);
    setScript(null);
    setError(null);
    setFieldErrors({});
    ensured.current = false;
  }
  function close() {
    reset();
    onClose();
  }

  const submitServer = useMutation({
    mutationFn: async (values: { address: string; name: string; port: string; allowedSource: string }) => {
      // The script first: it checks the allowed source before anything is created.
      const rendered = await api<Script>("/hosts/setup-script", {
        method: "POST",
        body: { allowedSource: values.allowedSource },
      });
      if (existingId) return { id: existingId, rendered };
      const created = await api<{ id: string }>("/hosts", {
        method: "POST",
        body: {
          address: values.address,
          name: values.name || undefined,
          port: values.port || undefined,
          ...(prefill ? { source: prefill.source, sourceRef: prefill.sourceRef } : {}),
        },
      });
      return { id: created.id, rendered };
    },
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async ({ id: created, rendered }) => {
      setHostId(created);
      setScript(rendered);
      setSource(rendered.allowedSource);
      await queryClient.invalidateQueries({ queryKey: ["hosts"] });
      await queryClient.invalidateQueries({ queryKey: ["host-access"] });
      // The guest or agent it was created from is tracked now.
      await queryClient.invalidateQueries({
        predicate: (q) => /^(px|xdr)-/.test(String(q.queryKey[0])),
      });
      setStep(1);
    },
    onError: (e, values) => {
      if (stepUp.handled(e, () => submitServer.mutate(values))) return;
      if (e instanceof ApiError && e.code === "duplicate") return setError(t("servers.errorDuplicate"));
      if (e instanceof ApiError && e.code === "already-linked")
        return setError(
          prefill?.source === "wazuh" ? t("xdr.linkErrors.alreadyLinked") : t("servers.errorAlreadyLinked"),
        );
      if (e instanceof ApiError && e.code === "limit-reached") return setError(t("servers.errorLimit"));
      if (e instanceof ApiError && e.code === "access-key-pending")
        return setError(t("servers.accessPending"));
      if (e instanceof ApiError && e.status === 422) {
        const errors = fieldErrorsOf(e);
        setFieldErrors(errors);
        return setError(errors.sourceRef ? t("servers.errorSource") : t("servers.errorInvalid"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const text = (key: string) => String(form.get(key) ?? "").trim();
    submitServer.mutate({
      address: text("address"),
      name: text("name"),
      port: text("port"),
      allowedSource: source.trim(),
    });
  }

  const fieldError = (name: string) => {
    const code = fieldErrors[name];
    if (!code) return null;
    const key = `servers.fieldError.${code}`;
    return i18n.exists(key) ? t(key as never) : t("servers.errorInvalid");
  };

  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        title={t("servers.wizardTitle")}
        description={t("servers.wizardStep", {
          step: step + 1,
          total: STEPS.length,
          name: t(`servers.${STEPS[step] ?? "stepServer"}`),
        })}
      >
        <ol className="mb-4 flex gap-1.5" aria-hidden="true">
          {STEPS.map((name, index) => (
            <li
              key={name}
              className={cn("h-1 flex-1 rounded-full", index <= step ? "bg-primary" : "bg-muted")}
            />
          ))}
        </ol>
        {step === 0 ? (
          <>
            <form className="grid gap-4" onSubmit={submit} noValidate>
              {error ? <Alert tone="error">{error}</Alert> : null}
              {prefill && !existingId ? (
                <Alert tone="info">
                  {"agent" in prefill.origin
                    ? t("servers.fromWazuh", {
                        agent: prefill.origin.agent,
                        connection: prefill.origin.connection,
                      })
                    : t("servers.fromProxmox", {
                        guest: prefill.origin.guest,
                        cluster: prefill.origin.cluster,
                        vmid: prefill.origin.vmid,
                      })}
                </Alert>
              ) : null}
              {existingId ? (
                existing.data ? (
                  <p className="text-sm">
                    <span className="font-medium">{existing.data.name}</span>{" "}
                    <span className="font-mono text-muted-foreground">
                      {existing.data.address}:{existing.data.port}
                    </span>
                  </p>
                ) : null
              ) : (
                <>
                  <Field
                    label={t("servers.address")}
                    hint={
                      prefill
                        ? prefill.addresses.length === 0
                          ? t(
                              prefill.source === "wazuh"
                                ? "servers.wazuhNoAddress"
                                : "servers.proxmoxNoAddress",
                            )
                          : prefill.addresses.length > 1
                            ? t("servers.proxmoxAddresses", { addresses: prefill.addresses.join(", ") })
                            : t("servers.addressHint")
                        : t("servers.addressHint")
                    }
                    defaultValue={prefill?.address ?? ""}
                    error={fieldError("address")}
                    name="address"
                    required
                    autoComplete="off"
                    autoCapitalize="off"
                    spellCheck={false}
                    className="font-mono"
                  />
                  <div className="grid grid-cols-[minmax(0,1fr)_8rem] gap-4">
                    <Field
                      label={t("servers.name")}
                      hint={t("servers.nameHint")}
                      defaultValue={prefill?.name ?? ""}
                      error={fieldError("name")}
                      name="name"
                      maxLength={120}
                      autoComplete="off"
                    />
                    <Field
                      label={t("servers.port")}
                      error={fieldError("port")}
                      name="port"
                      inputMode="numeric"
                      defaultValue="22"
                      autoComplete="off"
                    />
                  </div>
                </>
              )}
              <Field
                label={t("servers.allowedSource")}
                hint={t("servers.allowedSourceHint")}
                error={fieldError("allowedSource")}
                name="allowedSource"
                required
                value={source}
                onChange={(e) => setSource(e.currentTarget.value)}
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
              />
              <DialogFooter>
                <Button variant="outline" onClick={close}>
                  {t("common.cancel")}
                </Button>
                <Button
                  type="submit"
                  disabled={submitServer.isPending || (Boolean(existingId) && !existing.data)}
                >
                  {submitServer.isPending
                    ? t("common.loading")
                    : t(existingId ? "common.continue" : "servers.addAndContinue")}
                </Button>
              </DialogFooter>
            </form>
            {!existingId && !prefill && wazuhConnected ? (
              <details className="mt-4 rounded-md border px-3 py-2" data-testid="monitor-with-wazuh">
                <summary className="cursor-pointer text-sm font-medium">{t("xdr.enrollInstead")}</summary>
                <div className="mt-3 grid gap-3">
                  <p className="text-sm text-muted-foreground">{t("xdr.enrollInsteadHint")}</p>
                  <EnrollmentHelper idPrefix="enroll-wizard" />
                </div>
              </details>
            ) : null}
          </>
        ) : null}
        {step === 1 && script ? (
          <PrepareStep
            script={script}
            source={source.trim()}
            accessFingerprint={script.keyFingerprint}
            onBack={() => setStep(0)}
            onNext={() => setStep(2)}
            onClose={close}
          />
        ) : null}
        {step === 2 && id ? (
          <HostKeyStep hostId={id} me={me} onDone={() => setStep(3)} onClose={close} />
        ) : null}
        {step === 3 && id ? (
          <DoneStep
            hostId={id}
            onClose={close}
            onAnother={() => {
              reset();
            }}
          />
        ) : null}
      </Dialog>
      {stepUp.dialog}
    </>
  );
}

function PrepareStep({
  script,
  source,
  accessFingerprint,
  onBack,
  onNext,
  onClose,
}: {
  script: Script;
  source: string;
  accessFingerprint: string;
  onBack: () => void;
  onNext: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [method, setMethod] = useState<Method>("command");
  const [link, setLink] = useState<SetupLink | null>(null);
  const [error, setError] = useState<string | null>(null);
  const createLink = useMutation({
    mutationFn: () =>
      api<SetupLink>("/hosts/setup-links", { method: "POST", body: { allowedSource: source } }),
    onMutate: () => setError(null),
    onSuccess: setLink,
    onError: () => setError(t("servers.scriptFailed")),
  });
  // A link belongs to one script; the script's checksum is shown with it.
  const sha256 = link && method === "command" ? link.sha256 : script.sha256;

  return (
    <div className="grid gap-4">
      <p>{t("servers.prepareIntro", { source })}</p>
      <Segmented
        label={t("servers.methods")}
        value={method}
        options={[
          { value: "command", label: t("servers.methodCommand") },
          { value: "download", label: t("servers.methodDownload") },
          { value: "copy", label: t("servers.methodCopy") },
        ]}
        onChange={setMethod}
      />
      {error ? <Alert tone="error">{error}</Alert> : null}
      {method === "command" ? (
        <div className="grid gap-2">
          <p className="text-sm text-muted-foreground">{t("servers.commandHint")}</p>
          {link ? (
            <>
              <label htmlFor="setup-command" className="text-sm font-medium">
                {t("servers.commandLabel")}
              </label>
              <textarea
                id="setup-command"
                readOnly
                rows={7}
                value={link.command}
                onFocus={(e) => e.currentTarget.select()}
                className="w-full resize-none rounded-md border border-input bg-muted px-3 py-2 font-mono text-sm break-all"
              />
              <div className="flex flex-wrap items-center gap-3">
                <CopyButton text={link.command} />
                <span className="text-sm text-muted-foreground">
                  {t("servers.linkExpires", { time: formatDateTime(link.expiresAt) })}
                </span>
              </div>
              <p className="text-sm text-muted-foreground">{t("servers.caHint")}</p>
            </>
          ) : (
            <div>
              <Button variant="outline" disabled={createLink.isPending} onClick={() => createLink.mutate()}>
                {createLink.isPending ? t("common.loading") : t("servers.createCommand")}
              </Button>
            </div>
          )}
        </div>
      ) : null}
      {method === "download" ? (
        <div className="grid gap-2">
          <p className="text-sm text-muted-foreground">{t("servers.downloadHint")}</p>
          <div>
            <Button variant="outline" onClick={() => saveAsFile(script.filename, script.script)}>
              {t("servers.downloadScript")}
            </Button>
          </div>
        </div>
      ) : null}
      {method === "copy" ? (
        <div className="grid gap-2">
          <label htmlFor="setup-script" className="text-sm font-medium">
            {t("servers.scriptLabel")}
          </label>
          <textarea
            id="setup-script"
            readOnly
            rows={8}
            value={script.script}
            onFocus={(e) => e.currentTarget.select()}
            className="max-h-64 w-full resize-y rounded-md border border-input bg-muted px-3 py-2 font-mono text-xs"
          />
          <div>
            <CopyButton text={script.script} />
          </div>
        </div>
      ) : null}
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("servers.checksum")}</dt>
        <dd className="font-mono break-all">{sha256}</dd>
        <dt className="text-muted-foreground">{t("servers.keyFingerprint")}</dt>
        <dd className="font-mono break-all">{accessFingerprint}</dd>
      </dl>
      <p className="text-sm text-muted-foreground">
        {t("servers.reviewHint")} {t("servers.uninstallHint")}
      </p>
      <DialogFooter>
        <Button variant="outline" onClick={onBack}>
          {t("common.back")}
        </Button>
        <Button variant="outline" onClick={onClose}>
          {t("servers.keyLater")}
        </Button>
        <Button onClick={onNext}>{t("common.continue")}</Button>
      </DialogFooter>
    </div>
  );
}

function HostKeyStep({
  hostId,
  me,
  onDone,
  onClose,
}: {
  hostId: string;
  me: Me;
  onDone: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const hostError = useHostErrorText();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const host = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => api<HostDetail>(`/hosts/${hostId}`),
    // The worker reads the key a moment after the server was added.
    refetchInterval: (q) => (q.state.data?.hostKey.candidate || q.state.data?.lastError ? false : 2000),
  });
  const candidate = host.data?.hostKey.candidate ?? null;
  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api<{ runId: string }>(`/hosts/${hostId}/host-key/confirm`, { method: "POST", body: { fingerprint } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await queryClient.invalidateQueries();
      onDone();
    },
    onError: async (e, fingerprint) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await queryClient.invalidateQueries({ queryKey: ["host", hostId] });
        return setError(t("servers.keyMismatch"));
      }
      setError(t("errors.actionFailed"));
    },
  });
  const again = useMutation({
    mutationFn: () => api(`/hosts/${hostId}/host-key/scan`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["host", hostId] }),
  });

  return (
    <div className="grid gap-4">
      {error ? <Alert tone="error">{error}</Alert> : null}
      {candidate ? (
        <>
          <p>{t("servers.keyIntro")}</p>
          <KeyFingerprint
            type={candidate.type}
            fingerprint={candidate.fingerprint}
            label={t("servers.keyFingerprintLabel")}
          />
          <div className="grid gap-1 text-sm text-muted-foreground">
            <span>{t("servers.keyCompare")}</span>
            <code className="font-mono break-all text-foreground">
              ssh-keygen -lf {hostKeyFile(candidate.type)}
            </code>
          </div>
        </>
      ) : host.data?.lastError ? (
        <Alert tone="error">{t("servers.keyScanFailed", { reason: hostError(host.data.lastError) })}</Alert>
      ) : (
        <p role="status" className="text-muted-foreground">
          {t("servers.keyWaiting")}
        </p>
      )}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          {t("servers.keyLater")}
        </Button>
        {candidate ? (
          <Button disabled={confirm.isPending} onClick={() => confirm.mutate(candidate.fingerprint)}>
            {confirm.isPending ? t("common.loading") : t("servers.keyConfirm")}
          </Button>
        ) : (
          <Button variant="outline" disabled={again.isPending} onClick={() => again.mutate()}>
            {t("servers.keyLookAgain")}
          </Button>
        )}
      </DialogFooter>
      {stepUp.dialog}
    </div>
  );
}

function DoneStep({
  hostId,
  onClose,
  onAnother,
}: {
  hostId: string;
  onClose: () => void;
  onAnother: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4">
      <div className="flex items-start gap-3">
        <Check aria-hidden="true" className="mt-1 size-5 flex-none text-muted-foreground" />
        <div>
          <p className="font-medium">{t("servers.doneTitle")}</p>
          <p className="text-muted-foreground">{t("servers.doneText")}</p>
        </div>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={onAnother}>
          {t("servers.addAnother")}
        </Button>
        <Link
          to="/servers/$id"
          params={{ id: hostId }}
          onClick={onClose}
          className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-base font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
        >
          {t("servers.openServer")}
        </Link>
      </DialogFooter>
    </div>
  );
}
