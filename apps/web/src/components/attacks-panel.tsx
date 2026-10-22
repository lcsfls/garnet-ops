import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ExternalLink, Trash2, Upload } from "lucide-react";
import { type FormEvent, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { geoipReasonKey, osintReasonKey, uploadReason } from "../lib/attacks.ts";
import { formatBytes, formatDateTime, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";
import type { AttackSettings, GeoipDatasetView, GeoipKind } from "../lib/types.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Field } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { useStepUp } from "./use-step-up.tsx";

const KINDS: readonly GeoipKind[] = ["country", "asn"];

/** PUT of the file as the request body: streamed by the browser, read as a stream by the API. */
async function uploadGeoip(kind: GeoipKind, file: File): Promise<{ rows: number; month: string | null }> {
  const res = await fetch(`/api/v1/attacks/geoip/${kind}?filename=${encodeURIComponent(file.name)}`, {
    method: "PUT",
    credentials: "same-origin",
    headers: { "content-type": "application/gzip", accept: "application/json" },
    body: file,
  });
  if (!res.ok) {
    const json = res.headers.get("content-type")?.includes("json")
      ? await res.json().catch(() => null)
      : null;
    throw new ApiError(res.status, json);
  }
  return (await res.json()) as { rows: number; month: string | null };
}

/** The first field error code of a validation problem, e.g. "key_tooShort". */
function fieldCode(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.status !== 422) return null;
  const errors = error.problem?.errors;
  return errors?.[0]?.message ?? null;
}

/**
 * Settings, Attack overview (owners and admins; ADR 0016): the local location data (manual
 * import or the opt-in monthly download), how long source addresses are kept, and the optional
 * reputation lookup. Everything that makes data leave the network is off by default and says so
 * in plain words before it can be switched on.
 */
export function AttacksPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const settings = useQuery({
    queryKey: ["attacks-settings"],
    queryFn: () => api<AttackSettings>("/attacks/settings"),
  });
  const refresh = () =>
    queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("attacks-") });
  const data = settings.data;

  return (
    <>
      {data && !data.wazuhConnected ? (
        <Card>
          <div className="flex flex-wrap items-center gap-3 px-5 py-4">
            <div className="min-w-0 flex-[1_1_20rem]">
              <h2 className="font-semibold">{t("attacks.settings.noWazuhTitle")}</h2>
              <p className="text-sm text-muted-foreground">{t("attacks.settings.noWazuhText")}</p>
            </div>
            <Link
              to="/settings"
              search={{ section: "xdr" }}
              className="inline-flex h-9 items-center rounded-md border border-input bg-card px-3 font-medium shadow-xs hover:bg-accent"
            >
              {t("attacks.settings.noWazuhLink")}
            </Link>
          </div>
        </Card>
      ) : null}
      {!data ? (
        <Card>
          <CardHeader title={t("attacks.settings.title")} description={t("attacks.settings.description")} />
          <QueryStatus query={settings} />
        </Card>
      ) : (
        <>
          <GeoipCard data={data} stepUp={stepUp} onChanged={refresh} />
          <DownloadCard data={data} stepUp={stepUp} onChanged={refresh} />
          <RetentionCard data={data} stepUp={stepUp} onChanged={refresh} />
          <OsintCard data={data} stepUp={stepUp} onChanged={refresh} />
        </>
      )}
      {stepUp.dialog}
    </>
  );
}

type StepUp = ReturnType<typeof useStepUp>;
interface CardProps {
  data: AttackSettings;
  stepUp: StepUp;
  onChanged: () => Promise<unknown>;
}

/* -------------------------------------------------------------------------- */
/* Location data                                                               */
/* -------------------------------------------------------------------------- */

function GeoipCard({ data, stepUp, onChanged }: CardProps) {
  const { t } = useTranslation();
  const kindName = (kind: GeoipKind) =>
    t(kind === "country" ? "attacks.settings.kindCountry" : "attacks.settings.kindAsn");
  const [removing, setRemoving] = useState<GeoipKind | null>(null);
  const remove = useMutation({
    mutationFn: (kind: GeoipKind) => api(`/attacks/geoip/${kind}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(null);
      await onChanged();
    },
    onError: (e, kind) => {
      if (stepUp.handled(e, () => remove.mutate(kind))) setRemoving(null);
    },
  });
  const loaded = new Map(data.geoip.datasets.map((d) => [d.kind, d]));
  return (
    <Card>
      <CardHeader title={t("attacks.settings.geoTitle")} description={t("attacks.settings.geoDescription")} />
      <div className="px-5 pb-4 text-sm text-muted-foreground">
        <a
          href={data.geoip.attribution.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-primary-text hover:underline"
        >
          <ExternalLink aria-hidden="true" className="size-3.5" />
          {data.geoip.attribution.text}
        </a>
      </div>
      <table className="w-full border-t text-left" data-testid="geoip-datasets">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <th className="px-5 py-2.5 font-medium">{t("attacks.settings.columnData")}</th>
            <th className="px-3 py-2.5 font-medium">{t("attacks.settings.columnStatus")}</th>
            <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
              {t("attacks.settings.columnRelease")}
            </th>
            <th className="hidden px-3 py-2.5 text-right font-medium @3xl:table-cell">
              {t("attacks.settings.columnRanges")}
            </th>
            <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
              {t("attacks.settings.columnSource")}
            </th>
            <th className="px-5 py-2.5 text-right font-medium">
              <span className="sr-only">{t("xdr.columnActions")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {KINDS.map((kind) => {
            const d = loaded.get(kind) as GeoipDatasetView;
            return (
              <tr key={kind} className="border-b align-top last:border-0" data-testid={`geoip-${kind}`}>
                <td className="px-5 py-3 font-medium">{kindName(kind)}</td>
                <td className="px-3 py-3">
                  {d.active ? (
                    <div className="grid gap-0.5">
                      <span>
                        <Badge tone="neutral">
                          {d.active.stale ? t("attacks.settings.old") : t("attacks.settings.loaded")}
                        </Badge>
                      </span>
                      <span
                        className="text-sm text-muted-foreground"
                        title={formatDateTime(d.active.loadedAt)}
                      >
                        {formatRelative(d.active.loadedAt)}
                      </span>
                    </div>
                  ) : (
                    <span className="text-muted-foreground">{t("attacks.settings.notLoaded")}</span>
                  )}
                  {d.lastFailure ? (
                    <p className="mt-1 text-sm text-destructive-text">
                      {t("attacks.settings.lastFailure", {
                        when: formatRelative(d.lastFailure.at),
                        reason: t(geoipReasonKey(d.lastFailure.error)),
                      })}
                    </p>
                  ) : null}
                </td>
                <td className="hidden px-3 py-3 @3xl:table-cell">
                  {d.active ? (d.active.month ?? t("attacks.settings.unknownRelease")) : "–"}
                </td>
                <td className="hidden px-3 py-3 text-right tabular-nums @3xl:table-cell">
                  {d.active ? d.active.rows.toLocaleString() : "–"}
                </td>
                <td className="hidden px-3 py-3 @3xl:table-cell">
                  {d.active
                    ? t(
                        d.active.source === "import"
                          ? "attacks.settings.sourceImport"
                          : "attacks.settings.sourceDownload",
                      )
                    : "–"}
                </td>
                <td className="px-5 py-2 text-right">
                  {d.active ? (
                    <Button
                      variant="ghost"
                      className="h-9 px-2.5"
                      aria-label={t("attacks.settings.remove", { kind: kindName(kind) })}
                      onClick={() => setRemoving(kind)}
                    >
                      <Trash2 aria-hidden="true" className="size-4" />
                    </Button>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="grid gap-3 border-t px-5 py-4">
        <h3 className="text-sm font-medium">{t("attacks.settings.importTitle")}</h3>
        <p className="text-sm text-muted-foreground">
          {t("attacks.settings.importHint", { size: formatBytes(data.geoip.limits.maxCompressedBytes) })}
        </p>
        {KINDS.map((kind) => (
          <ImportRow key={kind} kind={kind} label={kindName(kind)} stepUp={stepUp} onImported={onChanged} />
        ))}
      </div>
      <ConfirmDialog
        open={removing !== null}
        title={t("attacks.settings.removeTitle")}
        description={t("attacks.settings.removeDescription")}
        confirmLabel={t("attacks.settings.removeConfirm")}
        pending={remove.isPending}
        error={
          remove.isError && !(remove.error instanceof ApiError && remove.error.code === "step-up-required")
            ? t("errors.actionFailed")
            : null
        }
        onConfirm={() => removing && remove.mutate(removing)}
        onClose={() => setRemoving(null)}
      />
    </Card>
  );
}

function ImportRow({
  kind,
  label,
  stepUp,
  onImported,
}: {
  kind: GeoipKind;
  label: string;
  stepUp: StepUp;
  onImported: () => Promise<unknown>;
}) {
  const { t } = useTranslation();
  const input = useRef<HTMLInputElement>(null);
  const id = useId();
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "info"; text: string } | null>(null);
  const upload = useMutation({
    mutationFn: (f: File) => uploadGeoip(kind, f),
    onMutate: () => setMessage(null),
    onSuccess: async (result) => {
      setMessage({ tone: "info", text: t("attacks.settings.importDone", { rows: result.rows }) });
      setFile(null);
      if (input.current) input.current.value = "";
      await onImported();
    },
    onError: (e, f) => {
      if (stepUp.handled(e, () => upload.mutate(f))) return;
      setMessage({ tone: "error", text: t(geoipReasonKey(uploadReason(e))) });
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!file) return setMessage({ tone: "error", text: t("attacks.settings.importNeedsFile") });
    upload.mutate(file);
  };
  return (
    <form onSubmit={submit} className="grid gap-2" data-testid={`import-${kind}`}>
      <div className="flex flex-wrap items-end gap-3">
        <div className="grid min-w-0 flex-[1_1_18rem] gap-1.5">
          <label htmlFor={id} className="text-sm font-medium">
            {t("attacks.settings.chooseFile", { kind: label })}
          </label>
          <input
            id={id}
            ref={input}
            type="file"
            accept=".gz,application/gzip,application/x-gzip"
            className="block w-full rounded-md border border-input bg-card px-3 py-2 text-sm shadow-xs file:mr-3 file:rounded-md file:border-0 file:bg-muted file:px-3 file:py-1 file:text-sm"
            onChange={(e) => {
              setFile(e.currentTarget.files?.[0] ?? null);
              setMessage(null);
            }}
          />
        </div>
        <Button type="submit" variant="outline" disabled={upload.isPending}>
          <Upload aria-hidden="true" className="size-4" />
          {upload.isPending
            ? t("attacks.settings.importing")
            : t("attacks.settings.importButton", { kind: label })}
        </Button>
      </div>
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
    </form>
  );
}

/* -------------------------------------------------------------------------- */
/* Monthly download                                                            */
/* -------------------------------------------------------------------------- */

function DownloadCard({ data, stepUp, onChanged }: CardProps) {
  const { t } = useTranslation();
  const download = data.geoip.download;
  const toggle = useMutation({
    mutationFn: (enabled: boolean) =>
      api("/attacks/settings", { method: "PATCH", body: { geoipDownloadEnabled: enabled } }),
    onSuccess: onChanged,
    onError: (e, enabled) => {
      stepUp.handled(e, () => toggle.mutate(enabled));
    },
  });
  return (
    <Card>
      <CardHeader
        title={t("attacks.settings.downloadTitle")}
        description={t("attacks.settings.downloadDescription")}
      />
      <div className="grid gap-3 px-5 pb-5">
        <label className="flex items-start gap-2.5">
          <Checkbox
            className="mt-1"
            checked={download.enabled}
            disabled={toggle.isPending}
            onChange={(e) => toggle.mutate(e.currentTarget.checked)}
          />
          <span className="font-medium">{t("attacks.settings.downloadEnable")}</span>
        </label>
        <div>
          <p className="text-sm text-muted-foreground">{t("attacks.settings.downloadUrls")}</p>
          <ul className="mt-1 grid gap-0.5">
            {KINDS.map((kind) => (
              <li key={kind}>
                <code className="font-mono text-sm break-all" data-testid={`download-url-${kind}`}>
                  {data.geoip.urls[kind]}
                </code>
              </li>
            ))}
          </ul>
        </div>
        <p className="text-sm text-muted-foreground">{t("attacks.settings.downloadNote")}</p>
        {download.enabled ? (
          <div className="text-sm text-muted-foreground">
            {download.enabledAt ? (
              <p>{t("attacks.settings.downloadOn", { when: formatRelative(download.enabledAt) })}</p>
            ) : null}
            <p>
              {download.lastAttemptAt
                ? t("attacks.settings.downloadLastAttempt", { when: formatRelative(download.lastAttemptAt) })
                : t("attacks.settings.downloadNever")}
            </p>
            {download.lastError ? (
              <p className="text-destructive-text">
                {t("attacks.settings.downloadFailed", { reason: t(geoipReasonKey(download.lastError)) })}
              </p>
            ) : null}
          </div>
        ) : null}
        {toggle.isError && !(toggle.error instanceof ApiError && toggle.error.code === "step-up-required") ? (
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        ) : null}
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Retention                                                                   */
/* -------------------------------------------------------------------------- */

function RetentionCard({ data, stepUp, onChanged }: CardProps) {
  const { t } = useTranslation();
  const [days, setDays] = useState(String(data.retentionDays));
  const [purging, setPurging] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const valid =
    /^\d{1,3}$/.test(days) && Number(days) >= data.retention.min && Number(days) <= data.retention.max;
  const save = useMutation({
    mutationFn: () => api("/attacks/settings", { method: "PATCH", body: { retentionDays: Number(days) } }),
    onMutate: () => setMessage(null),
    onSuccess: async () => {
      setMessage(t("attacks.settings.retentionSaved"));
      await onChanged();
    },
    onError: (e) => {
      stepUp.handled(e, () => save.mutate());
    },
  });
  const purge = useMutation({
    mutationFn: () =>
      api<{ sourceAddresses: number; attackWindows: number }>("/attacks/data", { method: "DELETE" }),
    onSuccess: async (result) => {
      setPurging(false);
      setMessage(
        t("attacks.settings.purged", { sources: result.sourceAddresses, windows: result.attackWindows }),
      );
      await onChanged();
    },
    onError: (e) => {
      if (stepUp.handled(e, () => purge.mutate())) setPurging(false);
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) save.mutate();
  };
  return (
    <Card>
      <CardHeader
        title={t("attacks.settings.retentionTitle")}
        description={t("attacks.settings.retentionDescription")}
      />
      <form onSubmit={submit} className="grid max-w-[34rem] gap-3 px-5 pb-5">
        <Field
          label={t("attacks.settings.retentionDays")}
          hint={t("attacks.settings.retentionHint", {
            min: data.retention.min,
            max: data.retention.max,
            default: data.retention.default,
          })}
          type="number"
          inputMode="numeric"
          min={data.retention.min}
          max={data.retention.max}
          value={days}
          onChange={(e) => setDays(e.currentTarget.value)}
          error={valid ? null : t("errors.invalidValue")}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!valid || save.isPending || Number(days) === data.retentionDays}>
            {t("attacks.settings.retentionSave")}
          </Button>
          <Button variant="destructive" onClick={() => setPurging(true)}>
            <Trash2 aria-hidden="true" className="size-4" />
            {t("attacks.settings.purgeButton")}
          </Button>
        </div>
        {message ? <Alert tone="info">{message}</Alert> : null}
        {save.isError && !(save.error instanceof ApiError && save.error.code === "step-up-required") ? (
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        ) : null}
      </form>
      <ConfirmDialog
        open={purging}
        title={t("attacks.settings.purgeTitle")}
        description={t("attacks.settings.purgeDescription")}
        confirmLabel={t("attacks.settings.purgeConfirm")}
        pending={purge.isPending}
        error={
          purge.isError && !(purge.error instanceof ApiError && purge.error.code === "step-up-required")
            ? t("errors.actionFailed")
            : null
        }
        onConfirm={() => purge.mutate()}
        onClose={() => setPurging(false)}
      />
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* OSINT                                                                       */
/* -------------------------------------------------------------------------- */

function OsintCard({ data, stepUp, onChanged }: CardProps) {
  const { t } = useTranslation();
  const o = data.osint;
  const provider = o.providers.find((p) => p.id === (o.provider ?? o.providers[0]?.id)) ?? o.providers[0];
  const [providerId, setProviderId] = useState(provider?.id ?? "");
  const [apiKey, setApiKey] = useState("");
  const [topN, setTopN] = useState(String(o.topN));
  const [budget, setBudget] = useState(String(o.dailyBudget));
  const [ackLeave, setAckLeave] = useState(false);
  const [ackTerms, setAckTerms] = useState(false);
  const [removingKey, setRemovingKey] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selected = o.providers.find((p) => p.id === providerId) ?? provider;
  const name = selected?.name ?? "";

  const numbersOk =
    /^\d{1,4}$/.test(topN) &&
    Number(topN) >= o.limits.topN.min &&
    Number(topN) <= o.limits.topN.max &&
    /^\d{1,4}$/.test(budget) &&
    Number(budget) >= o.limits.dailyBudget.min &&
    Number(budget) <= o.limits.dailyBudget.max;

  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api("/attacks/settings", { method: "PATCH", body: { osint: body } }),
    onMutate: () => {
      setError(null);
      setMessage(null);
    },
    onSuccess: async () => {
      setMessage(t("attacks.settings.osintSaved"));
      setApiKey("");
      setAckLeave(false);
      setAckTerms(false);
      setRemovingKey(false);
      await onChanged();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => patch.mutate(body))) return;
      const code = fieldCode(e);
      if (code?.startsWith("key_")) return setError(t(`attacks.settings.saveErrors.${code}` as MessageKey));
      if (code?.startsWith("ack_")) return setError(t("attacks.settings.saveErrors.ack"));
      setError(t("attacks.settings.saveErrors.generic"));
      setRemovingKey(false);
    },
  });
  const enable = (event: FormEvent) => {
    event.preventDefault();
    if (!numbersOk || !selected) return;
    patch.mutate({
      enabled: true,
      provider: selected.id,
      ...(apiKey.trim() ? { apiKey: apiKey.trim() } : {}),
      topN: Number(topN),
      dailyBudget: Number(budget),
      acknowledge: [...(ackLeave ? ["addressesLeaveNetwork"] : []), ...(ackTerms ? ["termsChecked"] : [])],
    });
  };
  const save = (event: FormEvent) => {
    event.preventDefault();
    if (!numbersOk) return;
    patch.mutate({
      topN: Number(topN),
      dailyBudget: Number(budget),
      ...(apiKey.trim() ? { apiKey: apiKey.trim() } : {}),
    });
  };
  const lastError = o.lastError ? osintReasonKey(o.lastError) : null;

  return (
    <Card>
      <CardHeader
        title={t("attacks.settings.osintTitle")}
        description={t("attacks.settings.osintDescription")}
        actions={
          <Badge tone={o.enabled ? "info" : "neutral"}>
            {o.enabled ? t("attacks.settings.osintOn") : t("attacks.settings.osintOff")}
          </Badge>
        }
      />
      <form
        onSubmit={o.enabled ? save : enable}
        className="grid max-w-[40rem] gap-4 px-5 pb-5"
        data-testid="osint-form"
      >
        <div
          role="note"
          className="grid gap-1.5 rounded-lg border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-4 py-3"
        >
          <b className="font-semibold">{t("attacks.settings.osintWarningTitle")}</b>
          <p className="text-sm">
            {t("attacks.settings.osintWarningText", {
              count: Number(topN) || o.topN,
              provider: name,
              hours: o.limits.cacheHours,
            })}
          </p>
          <p className="text-sm">{t("attacks.settings.osintTermsText", { provider: name })}</p>
          {selected ? (
            <a
              href={selected.termsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex w-fit items-center gap-1 text-sm text-primary-text hover:underline"
            >
              <ExternalLink aria-hidden="true" className="size-3.5" />
              {t("attacks.settings.osintTermsLink", { provider: name })}
            </a>
          ) : null}
        </div>

        <label className="grid gap-1.5">
          <span className="text-sm font-medium">{t("attacks.settings.osintProvider")}</span>
          <Select
            className="w-full max-w-[20rem]"
            value={providerId}
            disabled={o.enabled}
            onChange={(e) => setProviderId(e.currentTarget.value)}
          >
            {o.providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </label>

        <Field
          label={o.keySet ? t("attacks.settings.osintApiKeyReplace") : t("attacks.settings.osintApiKey")}
          hint={`${o.keySet ? `${t("attacks.settings.osintKeySet")} ` : `${t("attacks.settings.osintKeyMissing")} `}${t("attacks.settings.osintApiKeyHint")}`}
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={apiKey}
          onChange={(e) => setApiKey(e.currentTarget.value)}
        />

        <div className="grid gap-4 @3xl:grid-cols-2">
          <Field
            label={t("attacks.settings.osintTopN")}
            hint={t("attacks.settings.osintTopNHint", { min: o.limits.topN.min, max: o.limits.topN.max })}
            type="number"
            inputMode="numeric"
            min={o.limits.topN.min}
            max={o.limits.topN.max}
            value={topN}
            onChange={(e) => setTopN(e.currentTarget.value)}
          />
          <Field
            label={t("attacks.settings.osintBudget")}
            hint={t("attacks.settings.osintBudgetHint", {
              min: o.limits.dailyBudget.min,
              max: o.limits.dailyBudget.max,
              free: selected?.freeDailyLimit ?? 0,
            })}
            type="number"
            inputMode="numeric"
            min={o.limits.dailyBudget.min}
            max={o.limits.dailyBudget.max}
            value={budget}
            onChange={(e) => setBudget(e.currentTarget.value)}
          />
        </div>

        {!o.enabled ? (
          <fieldset className="grid gap-2.5">
            <legend className="sr-only">{t("attacks.settings.osintAckLegend")}</legend>
            <label className="flex items-start gap-2.5">
              <Checkbox
                className="mt-1"
                checked={ackLeave}
                onChange={(e) => setAckLeave(e.currentTarget.checked)}
              />
              <span>{t("attacks.settings.osintAckLeave", { provider: name })}</span>
            </label>
            <label className="flex items-start gap-2.5">
              <Checkbox
                className="mt-1"
                checked={ackTerms}
                onChange={(e) => setAckTerms(e.currentTarget.checked)}
              />
              <span>{t("attacks.settings.osintAckTerms", { provider: name })}</span>
            </label>
          </fieldset>
        ) : (
          <div className="grid gap-0.5 text-sm text-muted-foreground">
            <p>{t("attacks.settings.osintUsage", { used: o.usageToday, budget: o.dailyBudget })}</p>
            <p>
              {o.lastRunAt
                ? t("attacks.settings.osintLastRun", { when: formatRelative(o.lastRunAt) })
                : t("attacks.settings.osintNoRun")}
            </p>
            {lastError ? (
              <p className="text-destructive-text">
                {t("attacks.settings.osintLastError", { reason: t(lastError) })}
              </p>
            ) : null}
          </div>
        )}

        {error ? <Alert tone="error">{error}</Alert> : null}
        {message ? <Alert tone="info">{message}</Alert> : null}

        <div className="flex flex-wrap items-center gap-3">
          {o.enabled ? (
            <>
              <Button type="submit" disabled={!numbersOk || patch.isPending}>
                {t("attacks.settings.osintSave")}
              </Button>
              <Button
                variant="outline"
                disabled={patch.isPending}
                onClick={() => patch.mutate({ enabled: false })}
              >
                {t("attacks.settings.osintDisable")}
              </Button>
            </>
          ) : (
            <Button
              type="submit"
              disabled={
                !numbersOk || patch.isPending || !ackLeave || !ackTerms || (!o.keySet && apiKey.trim() === "")
              }
            >
              {t("attacks.settings.osintEnable")}
            </Button>
          )}
          {o.keySet ? (
            <Button variant="destructive" onClick={() => setRemovingKey(true)}>
              {t("attacks.settings.osintRemoveKey")}
            </Button>
          ) : null}
        </div>
      </form>
      <ConfirmDialog
        open={removingKey}
        title={t("attacks.settings.osintRemoveKeyTitle")}
        description={t("attacks.settings.osintRemoveKeyDescription")}
        confirmLabel={t("attacks.settings.osintRemoveKey")}
        pending={patch.isPending}
        error={error}
        onConfirm={() => patch.mutate({ apiKey: null })}
        onClose={() => setRemovingKey(false)}
      />
    </Card>
  );
}
