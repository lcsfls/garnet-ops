import {
  ACTIVE_LIMITS,
  ACTIVE_SCHEDULES,
  EXPOSURE_PORTS,
  STAGE2_ACKNOWLEDGEMENT_ID,
} from "@garnetops/core/exposure";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Loader } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { type ExposureDetail, verificationKey } from "../lib/exposure.ts";
import { formatDateTime } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { toast } from "../lib/toast.ts";
import { CopyRow, Notice, useExposureError } from "./exposure-parts.tsx";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field, FormField } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { useStepUp } from "./use-step-up.tsx";

/** The codes the API gives for a value it refused, each with its sentence. */
const ADD_PROBLEMS = [
  "empty",
  "tooLong",
  "url",
  "wildcard",
  "characters",
  "label",
  "singleLabel",
  "numericTld",
  "reservedName",
  "notPublic",
] as const;
const isAddProblem = (code: string): code is (typeof ADD_PROBLEMS)[number] =>
  (ADD_PROBLEMS as readonly string[]).includes(code);

/* -------------------------------------------------------------------------- */
/* Add an asset                                                                */
/* -------------------------------------------------------------------------- */

/** Adds a domain, host name or public address. Nothing is checked from outside until the asset exists; verification comes later. */
export function AddAssetDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [value, setValue] = useState("");
  const [subdomains, setSubdomains] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setValue("");
      setSubdomains(false);
      setError(null);
    }
  }, [open]);

  const add = useMutation({
    mutationFn: () =>
      api<{ id: string }>("/exposure", { method: "POST", body: { value, includeSubdomains: subdomains } }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["exposure"] });
      toast.success(t("exposure.added"));
      onClose();
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === "duplicate") return setError(t("exposure.addErrors.duplicate"));
      if (e instanceof ApiError && e.code === "limit-reached") return setError(t("exposure.addErrors.limit"));
      if (e instanceof ApiError && e.status === 422) {
        const code = e.problem?.errors?.[0]?.message ?? "";
        return setError(
          isAddProblem(code) ? t(`exposure.addErrors.${code}`) : t("exposure.addErrors.invalid"),
        );
      }
      setError(t("errors.actionFailed"));
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    add.mutate();
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("exposure.addTitle")}
      description={t("exposure.addDescription")}
    >
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          label={t("exposure.addValue")}
          hint={t("exposure.addValueHint")}
          name="value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          required
          maxLength={300}
          placeholder="www.example.com"
        />
        <label className="flex items-start gap-2.5">
          <Checkbox className="mt-1" checked={subdomains} onChange={(e) => setSubdomains(e.target.checked)} />
          <span>
            {t("exposure.addSubdomains")}
            <span className="block text-sm text-muted-foreground">{t("exposure.addSubdomainsHint")}</span>
          </span>
        </label>
        <p className="text-sm text-muted-foreground">{t("exposure.addStage1Note")}</p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" disabled={add.isPending || value.trim() === ""}>
            {add.isPending ? t("common.loading") : t("exposure.addSubmit")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}

/* -------------------------------------------------------------------------- */
/* Verify                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * The proof of control: the DNS record or the file an owner publishes, with copy buttons, and a "Check now" that asks the worker and
 * then waits for the result. The token is public by design (it is published in DNS or on the asset).
 */
export function VerifyDialog({
  assetId,
  open,
  onClose,
  email,
}: {
  assetId: string;
  open: boolean;
  onClose: () => void;
  email: string;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const errorText = useExposureError();
  const stepUp = useStepUp(email);
  const [since, setSince] = useState<number | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [failed, setFailed] = useState(false);

  const detail = useQuery({
    queryKey: ["exposure", "asset", assetId],
    queryFn: () => api<ExposureDetail>(`/exposure/${assetId}`),
    enabled: open,
    refetchInterval: since !== null ? 1500 : false,
  });
  const asset = detail.data;
  const checkedAt = asset?.verification.checkedAt ? new Date(asset.verification.checkedAt).getTime() : 0;
  const waiting = since !== null && checkedAt < since;
  const stopped = useRef(false);
  useEffect(() => {
    if (since !== null && !waiting && !stopped.current) {
      stopped.current = true;
      void queryClient.invalidateQueries({ queryKey: ["exposure"] });
    }
    if (since === null) stopped.current = false;
  }, [since, waiting, queryClient]);
  useEffect(() => {
    if (!open) setSince(null);
  }, [open]);

  const check = useMutation({
    mutationFn: () => api(`/exposure/${assetId}/verify`, { method: "POST" }),
    onMutate: () => {
      setFailed(false);
      // The worker's clock and the browser's can differ by a little: start a few seconds earlier.
      setSince(Date.now() - 5000);
    },
    onError: () => {
      setSince(null);
      setFailed(true);
    },
  });
  const rotate = useMutation({
    mutationFn: () => api(`/exposure/${assetId}/verify/rotate`, { method: "POST" }),
    onSuccess: async () => {
      setConfirmRotate(false);
      setSince(null);
      await queryClient.invalidateQueries({ queryKey: ["exposure"] });
    },
    onError: (e) => {
      if (stepUp.handled(e, () => rotate.mutate())) return setConfirmRotate(false);
      setFailed(true);
    },
  });

  const key = asset ? verificationKey(asset) : null;
  const instructions = asset?.instructions;

  // The nested dialogs sit beside the main one, not inside it: a native dialog's close event would otherwise
  // reach the outer dialog's handler through the React tree and close it as well.
  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={t("exposure.verifyTitle", { asset: asset?.value ?? "" })}
        description={t("exposure.verifyDescription")}
      >
        {!asset || !instructions ? (
          <p className="text-muted-foreground">
            {detail.isError ? t("errors.loadFailed") : t("common.loading")}
          </p>
        ) : (
          <div className="grid gap-4">
            {failed ? <Alert tone="error">{t("errors.actionFailed")}</Alert> : null}
            {key === "verified" ? (
              <Alert tone="info">
                <span data-testid="verify-state">
                  {t("exposure.verifyVerified", {
                    when: asset.verification.confirmedAt
                      ? formatDateTime(asset.verification.confirmedAt)
                      : "",
                  })}
                </span>
              </Alert>
            ) : key === "covered" ? (
              <Alert tone="info">
                <span data-testid="verify-state">
                  {t("exposure.verifyCovered", { parent: asset.verification.parent?.value ?? "" })}
                </span>
              </Alert>
            ) : key === "lost" ? (
              <Alert tone="error">
                <span data-testid="verify-state">{t("exposure.verifyLost")}</span>
              </Alert>
            ) : null}
            {!waiting && asset.verification.error && key !== "verified" ? (
              <Alert tone="error">
                <span data-testid="verify-error">{errorText(asset.verification.error)}</span>
              </Alert>
            ) : null}

            {instructions.dns ? (
              <section className="grid gap-3 rounded-lg border p-4" aria-labelledby="verify-dns">
                <h3 id="verify-dns" className="font-medium">
                  {t("exposure.verifyDnsTitle")}
                </h3>
                <p className="text-sm text-muted-foreground">{t("exposure.verifyDnsText")}</p>
                <CopyRow
                  id="verify-dns-name"
                  label={t("exposure.verifyDnsName")}
                  value={instructions.dns.name}
                />
                <CopyRow
                  id="verify-dns-value"
                  label={t("exposure.verifyDnsValue")}
                  value={instructions.value}
                />
              </section>
            ) : null}
            <section className="grid gap-3 rounded-lg border p-4" aria-labelledby="verify-file">
              <h3 id="verify-file" className="font-medium">
                {t("exposure.verifyFileTitle")}
              </h3>
              <p className="text-sm text-muted-foreground">
                {asset.kind === "ip" ? t("exposure.verifyFileTextIp") : t("exposure.verifyFileText")}
              </p>
              <CopyRow
                id="verify-file-url"
                label={t("exposure.verifyFileUrl")}
                value={instructions.file.url}
              />
              <CopyRow
                id="verify-file-content"
                label={t("exposure.verifyFileContent")}
                value={instructions.value}
              />
            </section>
            <p className="text-sm text-muted-foreground">{t("exposure.verifyNote")}</p>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmRotate(true)}>
                {t("exposure.verifyNewCode")}
              </Button>
              <Button variant="outline" onClick={onClose}>
                {t("common.close")}
              </Button>
              <Button disabled={check.isPending || waiting} onClick={() => check.mutate()}>
                {waiting ? (
                  <>
                    <Loader aria-hidden="true" className="size-4 animate-spin motion-reduce:animate-none" />
                    {t("exposure.verifyChecking")}
                  </>
                ) : (
                  <>
                    <Check aria-hidden="true" className="size-4" />
                    {t("exposure.verifyCheckNow")}
                  </>
                )}
              </Button>
            </DialogFooter>
          </div>
        )}
      </Dialog>
      <ConfirmDialog
        open={confirmRotate}
        title={t("exposure.verifyNewCodeTitle")}
        description={t("exposure.verifyNewCodeText")}
        confirmLabel={t("exposure.verifyNewCode")}
        pending={rotate.isPending}
        error={failed ? t("errors.actionFailed") : null}
        onConfirm={() => rotate.mutate()}
        onClose={() => setConfirmRotate(false)}
      />
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Stage 2                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Switching stage 2 on or off, and running it by hand. Switching on shows what the stage does, what it never does and the warning
 * about the infrastructure behind a name, and asks for an explicit acknowledgement per asset. The API wants a recent sign-in.
 */
export function Stage2Dialog({
  asset,
  open,
  onClose,
  email,
}: {
  asset: ExposureDetail;
  open: boolean;
  onClose: () => void;
  email: string;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(email);
  const [schedule, setSchedule] = useState<(typeof ACTIVE_SCHEDULES)[number]>(asset.stage2.schedule);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const on = asset.stage2.enabled;
  const verified = asset.verification.effective;

  useEffect(() => {
    if (!open) {
      setAcknowledged(false);
      setError(null);
    } else {
      setSchedule(asset.stage2.schedule);
    }
  }, [open, asset.stage2.schedule]);

  const done = async (message: string) => {
    await queryClient.invalidateQueries({ queryKey: ["exposure"] });
    toast.success(message);
    onClose();
  };
  const fail = (e: unknown, again: () => void) => {
    if (stepUp.handled(e, again)) return;
    if (e instanceof ApiError && e.code === "not-verified")
      return setError(t("exposure.stage2Errors.notVerified"));
    if (e instanceof ApiError && e.code === "too-soon") return setError(t("exposure.stage2Errors.tooSoon"));
    setError(t("errors.actionFailed"));
  };
  const enable = useMutation({
    mutationFn: () =>
      api(`/exposure/${asset.id}/stage2`, {
        method: "PUT",
        body: {
          enabled: true,
          schedule,
          acknowledgement: STAGE2_ACKNOWLEDGEMENT_ID,
          confirmed: acknowledged,
        },
      }),
    onMutate: () => setError(null),
    onSuccess: () => done(t("exposure.stage2SwitchedOn")),
    onError: (e) => fail(e, () => enable.mutate()),
  });
  const disable = useMutation({
    mutationFn: () => api(`/exposure/${asset.id}/stage2`, { method: "PUT", body: { enabled: false } }),
    onMutate: () => setError(null),
    onSuccess: () => done(t("exposure.stage2SwitchedOff")),
    onError: (e) => fail(e, () => disable.mutate()),
  });
  const runNow = useMutation({
    mutationFn: () => api(`/exposure/${asset.id}/stage2/run`, { method: "POST" }),
    onMutate: () => setError(null),
    onSuccess: () => done(t("exposure.stage2RunQueued")),
    onError: (e) => fail(e, () => runNow.mutate()),
  });

  const next = asset.stage2.nextManualAt ? new Date(asset.stage2.nextManualAt) : null;
  const canRunNow = on && (!next || next.getTime() <= Date.now());

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={t(on ? "exposure.stage2ManageTitle" : "exposure.stage2EnableTitle", { asset: asset.value })}
        description={t("exposure.stage2Description")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Notice title={t("exposure.stage2WarningTitle")}>{t("exposure.stage2WarningText")}</Notice>

          <section className="grid gap-2" aria-labelledby="stage2-does">
            <h3 id="stage2-does" className="font-medium">
              {t("exposure.stage2DoesTitle")}
            </h3>
            <ul className="grid list-disc gap-1 pl-5 text-sm text-muted-foreground">
              <li>{t("exposure.stage2DoesPorts", { count: EXPOSURE_PORTS.length })}</li>
              <li>
                {t("exposure.stage2DoesLimits", {
                  concurrency: ACTIVE_LIMITS.concurrency,
                  gap: ACTIVE_LIMITS.gapMs,
                  timeout: ACTIVE_LIMITS.connectTimeoutMs / 1000,
                })}
              </li>
              <li>
                {t("exposure.stage2DoesBanner", {
                  seconds: ACTIVE_LIMITS.bannerReadMs / 1000,
                  bytes: ACTIVE_LIMITS.bannerBytes,
                })}
              </li>
              <li>{t("exposure.stage2DoesOnce")}</li>
            </ul>
            <details className="text-sm">
              <summary className="cursor-pointer text-primary-text">{t("exposure.stage2PortList")}</summary>
              <ul className="mt-2 flex flex-wrap gap-1.5" data-testid="stage2-ports">
                {EXPOSURE_PORTS.map((p) => (
                  <li key={p.port} className="rounded-md border px-2 py-0.5 text-muted-foreground">
                    <span className="font-mono text-foreground">{p.port}</span>{" "}
                    {t(`exposure.service.${p.service}` as MessageKey)}
                  </li>
                ))}
              </ul>
            </details>
          </section>

          <section className="grid gap-2" aria-labelledby="stage2-never">
            <h3 id="stage2-never" className="font-medium">
              {t("exposure.stage2NeverTitle")}
            </h3>
            <p className="text-sm text-muted-foreground">{t("exposure.stage2NeverText")}</p>
            <p className="text-sm text-muted-foreground">{t("exposure.stage2IdsNote")}</p>
          </section>

          {on ? (
            <>
              <p className="text-sm text-muted-foreground">
                {t("exposure.stage2OnSince", {
                  schedule: t(`exposure.schedule.${asset.stage2.schedule}`),
                  when: asset.stage2.acknowledgedAt ? formatDateTime(asset.stage2.acknowledgedAt) : "",
                })}
              </p>
              {!canRunNow && next ? (
                <p className="text-sm text-muted-foreground">
                  {t("exposure.stage2NextRun", { when: formatDateTime(next) })}
                </p>
              ) : null}
            </>
          ) : !verified ? (
            <Alert tone="info">{t("exposure.stage2NeedsProof")}</Alert>
          ) : (
            <>
              <div className="max-w-60">
                <FormField label={t("exposure.stage2Schedule")}>
                  {(control) => (
                    <Select
                      {...control}
                      value={schedule}
                      onChange={(e) => setSchedule(e.target.value as typeof schedule)}
                    >
                      {ACTIVE_SCHEDULES.map((s) => (
                        <option key={s} value={s}>
                          {t(`exposure.schedule.${s}`)}
                        </option>
                      ))}
                    </Select>
                  )}
                </FormField>
              </div>
              <label className="flex items-start gap-2.5 rounded-md border p-3">
                <Checkbox
                  className="mt-1"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                <span>
                  <b className="font-medium">{t("exposure.stage2Acknowledge")}</b>
                  <span className="block text-sm text-muted-foreground">
                    {t("exposure.stage2AcknowledgeHint")}
                  </span>
                </span>
              </label>
            </>
          )}
          <p className="text-sm text-muted-foreground">{t("exposure.notLegalAdvice")}</p>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.close")}
            </Button>
            {on ? (
              <>
                <Button
                  variant="outline"
                  disabled={!canRunNow || runNow.isPending}
                  onClick={() => runNow.mutate()}
                >
                  {t("exposure.stage2RunNow")}
                </Button>
                <Button variant="destructive" disabled={disable.isPending} onClick={() => disable.mutate()}>
                  {t("exposure.stage2SwitchOff")}
                </Button>
              </>
            ) : (
              <Button
                disabled={!verified || !acknowledged || enable.isPending}
                onClick={() => enable.mutate()}
              >
                {enable.isPending ? t("common.loading") : t("exposure.stage2SwitchOn")}
              </Button>
            )}
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
