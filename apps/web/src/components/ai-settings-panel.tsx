import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PlugZap, Trash2, TriangleAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";
import type { AiProbe, AiSettings } from "../lib/types.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Field, FormRow } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";

const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

/** Host with port of a typed address, or an empty string while it is not a URL yet. */
function hostOf(value: string): string {
  try {
    return new URL(value.trim()).host;
  } catch {
    return "";
  }
}

type Configured = Extract<AiSettings, { configured: true }>;

const DEFAULTS = { maxTokens: 1024, temperature: 0.2, timeoutSeconds: 120, maxConcurrent: 2 };

/** Settings, AI (owners and admins): the model endpoint, its limits, and the switch (ADR 0013). */
export function AiSettingsPanel({ me }: { me: Me }) {
  const query = useQuery({ queryKey: ["ai-settings"], queryFn: () => api<AiSettings>("/ai/settings") });
  if (!query.data) {
    return (
      <Card>
        <QueryStatus query={query} />
      </Card>
    );
  }
  return <AiForm stored={query.data.configured ? query.data : null} me={me} />;
}

function AiForm({ stored, me }: { stored: Configured | null; me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [enabled, setEnabled] = useState(stored?.enabled ?? false);
  const [baseUrl, setBaseUrl] = useState(stored?.baseUrl ?? "");
  const [model, setModel] = useState(stored?.model ?? "");
  const [apiKey, setApiKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [maxTokens, setMaxTokens] = useState(String(stored?.maxTokens ?? DEFAULTS.maxTokens));
  const [temperature, setTemperature] = useState(String(stored?.temperature ?? DEFAULTS.temperature));
  const [timeoutSeconds, setTimeoutSeconds] = useState(
    String(stored?.timeoutSeconds ?? DEFAULTS.timeoutSeconds),
  );
  const [maxConcurrent, setMaxConcurrent] = useState(String(stored?.maxConcurrent ?? DEFAULTS.maxConcurrent));
  const [acknowledge, setAcknowledge] = useState(stored?.externalAcknowledged ?? false);
  // Set by the server when the address turned out to be outside the network.
  const [needsAck, setNeedsAck] = useState(stored?.scope === "external");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [models, setModels] = useState<string[] | null>(null);
  const [probeNote, setProbeNote] = useState<{ tone: "error" | "info"; text: string } | null>(null);
  const [removing, setRemoving] = useState(false);

  const host = hostOf(baseUrl);
  const typedHttp = baseUrl.trim().toLowerCase().startsWith("http://");
  const scope = stored && stored.baseUrl === baseUrl.trim().replace(/\/+$/, "") ? stored.scope : null;

  const body = () => ({
    enabled,
    baseUrl: baseUrl.trim(),
    model: model.trim(),
    ...(apiKey ? { apiKey } : {}),
    ...(clearKey && !apiKey ? { clearApiKey: true } : {}),
    maxTokens: Number(maxTokens),
    temperature: Number(temperature),
    timeoutSeconds: Number(timeoutSeconds),
    maxConcurrent: Number(maxConcurrent),
    ...(needsAck && acknowledge ? { acknowledgeExternal: true } : {}),
  });

  /** Turns the server's refusal into text the person can act on, in their language. */
  function explain(e: unknown, retry: () => void): boolean {
    if (stepUp.handled(e, retry)) return true;
    if (e instanceof ApiError && e.status === 422) {
      const code = e.code;
      if (code === "external-not-acknowledged") {
        setNeedsAck(true);
        setFieldErrors({ acknowledgeExternal: t("ai.externalAckRequired") });
        return true;
      }
      const errors = Object.fromEntries(
        (e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message]),
      );
      setFieldErrors({
        ...(errors.baseUrl ? { baseUrl: t("ai.baseUrlRefused") } : {}),
        ...(errors.model ? { model: t("ai.testNeedsModel") } : {}),
        ...Object.fromEntries(
          Object.keys(errors)
            .filter((k) => !["baseUrl", "model"].includes(k))
            .map((k) => [k, t("ai.saveFailed")]),
        ),
      });
      return true;
    }
    return false;
  }

  const save = useMutation({
    mutationFn: () => api<AiSettings>("/ai/settings", { method: "PUT", body: body() }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
      setSaved(false);
    },
    onSuccess: async (result) => {
      queryClient.setQueryData(["ai-settings"], result);
      setApiKey("");
      setClearKey(false);
      // Findings pages show the model and where it runs.
      await queryClient.invalidateQueries({ queryKey: ["ai-thread"] });
      setSaved(true);
    },
    onError: (e) => {
      if (explain(e, () => save.mutate())) return;
      setError(t("ai.saveFailed"));
    },
  });

  const remove = useMutation({
    mutationFn: () => api("/ai/settings", { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(false);
      queryClient.setQueryData(["ai-settings"], { configured: false });
      await queryClient.invalidateQueries({ queryKey: ["ai-thread"] });
    },
    onError: (e) => {
      stepUp.handled(e, () => remove.mutate());
    },
  });

  /** Queues a probe (the worker holds the key) and waits for its result. */
  const probe = useMutation({
    mutationFn: async (kind: "models" | "test"): Promise<AiProbe> => {
      const { id } = await api<{ id: string }>("/ai/probe", {
        method: "POST",
        body: {
          kind,
          baseUrl: baseUrl.trim(),
          ...(kind === "test" ? { model: model.trim() } : {}),
          ...(apiKey ? { apiKey } : {}),
          ...(!apiKey && !clearKey && stored?.hasApiKey ? { useStoredKey: true } : {}),
          ...(needsAck && acknowledge ? { acknowledgeExternal: true } : {}),
        },
      });
      for (let attempt = 0; attempt < 50; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 600));
        const result = await api<AiProbe>(`/ai/probe/${id}`);
        if (result.status === "done") return result;
      }
      throw new Error("probe timed out");
    },
    onMutate: () => {
      setProbeNote(null);
      setFieldErrors({});
    },
    onSuccess: (result) => {
      const r = result.result;
      if (!r?.ok && r?.error === "external-not-acknowledged") {
        // The worker found the address outside the network (this server could not resolve it).
        setNeedsAck(true);
        setFieldErrors({ acknowledgeExternal: t("ai.externalAckRequired") });
        return setProbeNote({
          tone: "error",
          text: t("ai.testFailed", { reason: t("ai.error.externalNotAcknowledged") }),
        });
      }
      if (!r?.ok) {
        const reason = t(`ai.error.${camel(r?.error ?? "internal")}` as MessageKey);
        return setProbeNote({ tone: "error", text: t("ai.testFailed", { reason }) });
      }
      if (result.kind === "models") {
        const list = r.models ?? [];
        setModels(list);
        setProbeNote({ tone: "info", text: t("ai.modelsLoaded", { count: list.length }) });
      } else {
        setProbeNote({
          tone: "info",
          text: t("ai.testOk", { ms: r.latencyMs ?? 0, chars: r.replyChars ?? 0 }),
        });
      }
    },
    onError: (e, kind) => {
      if (explain(e, () => probe.mutate(kind))) return;
      setProbeNote({ tone: "error", text: t("ai.testFailed", { reason: t("ai.error.internal") }) });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  const external = scope === "external" || needsAck;
  const probeBusy = probe.isPending;

  return (
    <>
      <Card>
        <CardHeader
          title={t("ai.settingsTitle")}
          description={t("ai.settingsDescription")}
          actions={
            stored?.scope === "external" ? (
              <Badge className="bg-warning/18 text-warning-text">
                <TriangleAlert aria-hidden="true" />
                {t("ai.externalBadge")}
              </Badge>
            ) : null
          }
        />
        <form className="grid gap-5 px-5 py-5" onSubmit={submit} onChange={() => setSaved(false)}>
          {error ? <Alert tone="error">{error}</Alert> : null}

          <div className="grid gap-1">
            <label className="flex items-center gap-2.5 font-medium">
              <Checkbox checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              {t("ai.enabled")}
            </label>
            <p className="ml-[26px] text-sm text-muted-foreground">{t("ai.enabledHint")}</p>
          </div>

          <div className="grid gap-1.5">
            <Field
              label={t("ai.baseUrl")}
              hint={t("ai.baseUrlHint")}
              error={fieldErrors.baseUrl}
              name="baseUrl"
              value={baseUrl}
              onChange={(e) => {
                setBaseUrl(e.target.value);
                // The outside-the-network confirmation belongs to the host it was given for.
                const same =
                  stored?.scope === "external" && hostOf(e.target.value) === hostOf(stored.baseUrl);
                setNeedsAck(same);
                setAcknowledge(same && stored.externalAcknowledged);
                setFieldErrors({});
              }}
              required
              autoComplete="off"
              spellCheck={false}
              placeholder="https://llm.example.lan/v1"
              className="font-mono text-sm"
            />
            {typedHttp && !external ? <Alert tone="info">{t("ai.insecureNote")}</Alert> : null}
            {scope ? (
              <p className="text-sm text-muted-foreground">
                {scope === "private"
                  ? t("ai.scopePrivate")
                  : scope === "external"
                    ? t("ai.scopeExternal")
                    : t("ai.scopeUnknown")}
              </p>
            ) : null}
          </div>

          {external ? (
            <div className="grid gap-2 rounded-md border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-3.5 py-3">
              <p className="flex items-center gap-2 font-semibold">
                <TriangleAlert aria-hidden="true" className="size-4 flex-none text-warning-text" />
                {t("ai.externalTitle")}
              </p>
              <p className="text-sm">{t("ai.externalText", { host: host || "…" })}</p>
              <label className="flex items-start gap-2.5">
                <Checkbox
                  className="mt-1"
                  checked={acknowledge}
                  onChange={(e) => setAcknowledge(e.target.checked)}
                />
                <span>{t("ai.externalAck", { host: host || "…" })}</span>
              </label>
              {fieldErrors.acknowledgeExternal ? (
                <p role="alert" className="text-sm text-destructive-text">
                  {fieldErrors.acknowledgeExternal}
                </p>
              ) : null}
            </div>
          ) : null}

          <div className="grid gap-1.5">
            <label htmlFor="ai-model" className="text-sm font-medium">
              {t("ai.model")}
            </label>
            <div className="flex flex-wrap gap-2">
              <input
                id="ai-model"
                name="model"
                list="ai-models"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                aria-describedby="ai-model-hint"
                aria-invalid={fieldErrors.model ? true : undefined}
                className="h-10 min-w-0 flex-[1_1_14rem] rounded-md border border-input bg-card px-3 font-mono text-sm shadow-xs aria-invalid:border-destructive"
              />
              <datalist id="ai-models">
                {models?.map((name) => (
                  <option key={name} value={name} />
                ))}
              </datalist>
              <Button
                variant="outline"
                disabled={probeBusy || baseUrl.trim() === ""}
                onClick={() => probe.mutate("models")}
              >
                {probe.isPending && probe.variables === "models" ? t("ai.loadingModels") : t("ai.loadModels")}
              </Button>
            </div>
            <p id="ai-model-hint" className="text-sm text-muted-foreground">
              {fieldErrors.model ?? t("ai.modelHint")}
            </p>
          </div>

          <div className="grid gap-1.5">
            <Field
              label={t("ai.apiKey")}
              hint={stored?.hasApiKey && !clearKey ? t("ai.apiKeyStored") : t("ai.apiKeyHint")}
              name="apiKey"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              autoComplete="new-password"
              spellCheck={false}
            />
            {stored?.hasApiKey ? (
              <label className="flex items-center gap-2.5 text-sm">
                <Checkbox checked={clearKey} onChange={(e) => setClearKey(e.target.checked)} />
                {t("ai.apiKeyRemove")}
              </label>
            ) : null}
          </div>

          <FormRow columns={2} from="md">
            <Field
              label={t("ai.maxTokens")}
              hint={t("ai.maxTokensHint")}
              type="number"
              min={64}
              max={8192}
              step={1}
              required
              value={maxTokens}
              onChange={(e) => setMaxTokens(e.target.value)}
            />
            <Field
              label={t("ai.temperature")}
              hint={t("ai.temperatureHint")}
              type="number"
              min={0}
              max={2}
              step={0.1}
              required
              value={temperature}
              onChange={(e) => setTemperature(e.target.value)}
            />
            <Field
              label={t("ai.timeout")}
              hint={t("ai.timeoutHint")}
              type="number"
              min={10}
              max={600}
              step={1}
              required
              value={timeoutSeconds}
              onChange={(e) => setTimeoutSeconds(e.target.value)}
            />
            <Field
              label={t("ai.maxConcurrent")}
              hint={t("ai.maxConcurrentHint")}
              type="number"
              min={1}
              max={8}
              step={1}
              required
              value={maxConcurrent}
              onChange={(e) => setMaxConcurrent(e.target.value)}
            />
          </FormRow>

          {probeNote ? <Alert tone={probeNote.tone}>{probeNote.text}</Alert> : null}

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? t("ai.saving") : t("ai.save")}
            </Button>
            <Button
              variant="outline"
              disabled={probeBusy || baseUrl.trim() === "" || model.trim() === ""}
              onClick={() => probe.mutate("test")}
            >
              <PlugZap aria-hidden="true" className="size-4" />
              {probe.isPending && probe.variables === "test" ? t("ai.testing") : t("ai.test")}
            </Button>
            {saved ? (
              <span role="status" className="text-sm text-muted-foreground">
                {t("ai.saved")}
              </span>
            ) : null}
            {stored ? (
              <Button variant="ghost" className="ml-auto" onClick={() => setRemoving(true)}>
                <Trash2 aria-hidden="true" className="size-4" />
                {t("ai.remove")}
              </Button>
            ) : null}
          </div>
        </form>
      </Card>
      <ConfirmDialog
        open={removing}
        title={t("ai.removeTitle")}
        description={t("ai.removeDescription")}
        confirmLabel={t("ai.removeConfirm")}
        pending={remove.isPending}
        error={
          remove.isError && !(remove.error instanceof ApiError && remove.error.code === "step-up-required")
            ? t("errors.actionFailed")
            : null
        }
        onConfirm={() => remove.mutate()}
        onClose={() => setRemoving(false)}
      />
      {stepUp.dialog}
    </>
  );
}
