<script lang="ts" module>
  import type { AiSettings } from "../../../types.ts";

  export type Configured = Extract<AiSettings, { configured: true }>;

  const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

  /** Host with port of a typed address, or an empty string while it is not a URL yet. */
  function hostOf(value: string): string {
    try {
      return new URL(value.trim()).host;
    } catch {
      return "";
    }
  }

  const DEFAULTS = { maxTokens: 1024, temperature: 0.2, timeoutSeconds: 120, maxConcurrent: 2 };
</script>

<script lang="ts">
  import { PlugZap, Trash2, TriangleAlert } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { ApiError, api } from "../../../api.ts";
  import { type MessageKey, t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { AiProbe } from "../../../types.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import ConfirmDialog from "../../ui/ConfirmDialog.svelte";
  import Field from "../../ui/Field.svelte";
  import FormRow from "../../ui/FormRow.svelte";

  let { stored, me }: { stored: Configured | null; me: Me } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  // The form starts from what is stored and keeps what is typed when the stored settings change after a save.
  const initial = untrack(() => stored);
  let enabled = $state(initial?.enabled ?? false);
  let baseUrl = $state(initial?.baseUrl ?? "");
  let model = $state(initial?.model ?? "");
  let apiKey = $state("");
  let clearKey = $state(false);
  // Number inputs bound with bind:value hold numbers once edited; the body converts with Number() either way.
  let maxTokens = $state<string | number>(String(initial?.maxTokens ?? DEFAULTS.maxTokens));
  let temperature = $state<string | number>(String(initial?.temperature ?? DEFAULTS.temperature));
  let timeoutSeconds = $state<string | number>(String(initial?.timeoutSeconds ?? DEFAULTS.timeoutSeconds));
  let maxConcurrent = $state<string | number>(String(initial?.maxConcurrent ?? DEFAULTS.maxConcurrent));
  let acknowledge = $state(initial?.externalAcknowledged ?? false);
  // Set by the server when the address turned out to be outside the network.
  let needsAck = $state(initial?.scope === "external");
  let fieldErrors = $state<Record<string, string>>({});
  let error = $state<string | null>(null);
  let models = $state<string[] | null>(null);
  let probeNote = $state<{ tone: "error" | "info"; text: string } | null>(null);
  let removing = $state(false);

  const host = $derived(hostOf(baseUrl));
  const typedHttp = $derived(baseUrl.trim().toLowerCase().startsWith("http://"));
  const scope = $derived(stored && stored.baseUrl === baseUrl.trim().replace(/\/+$/, "") ? stored.scope : null);

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

  function changeBaseUrl(value: string) {
    baseUrl = value;
    // The outside-the-network confirmation belongs to the host it was given for.
    const same = stored?.scope === "external" && hostOf(value) === hostOf(stored.baseUrl);
    needsAck = same;
    acknowledge = same && (stored?.externalAcknowledged ?? false);
    fieldErrors = {};
  }

  /** Turns the server's refusal into text the person can act on, in their language. */
  function explain(e: unknown, retry: () => void): boolean {
    if (stepUp.handled(e, retry)) return true;
    if (e instanceof ApiError && e.status === 422) {
      const code = e.code;
      if (code === "external-not-acknowledged") {
        needsAck = true;
        fieldErrors = { acknowledgeExternal: t("ai.externalAckRequired") };
        return true;
      }
      const errors = Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message]));
      fieldErrors = {
        ...(errors.baseUrl ? { baseUrl: t("ai.baseUrlRefused") } : {}),
        ...(errors.model ? { model: t("ai.testNeedsModel") } : {}),
        ...Object.fromEntries(
          Object.keys(errors)
            .filter((k) => !["baseUrl", "model"].includes(k))
            .map((k) => [k, t("ai.saveFailed")]),
        ),
      };
      return true;
    }
    return false;
  }

  const save = createMutation(() => ({
    mutationFn: () => api<AiSettings>("/ai/settings", { method: "PUT", body: body() }),
    onMutate: () => {
      error = null;
      fieldErrors = {};
    },
    onSuccess: async (result: AiSettings) => {
      queryClient.setQueryData(["ai-settings"], result);
      apiKey = "";
      clearKey = false;
      // Findings pages show the model and where it runs.
      await queryClient.invalidateQueries({ queryKey: ["ai-thread"] });
      toast.success(t("ai.saved"));
    },
    onError: (e: Error) => {
      if (explain(e, () => save.mutate())) return;
      error = t("ai.saveFailed");
    },
  }));

  const remove = createMutation(() => ({
    mutationFn: () => api("/ai/settings", { method: "DELETE" }),
    onSuccess: async () => {
      removing = false;
      queryClient.setQueryData(["ai-settings"], { configured: false });
      await queryClient.invalidateQueries({ queryKey: ["ai-thread"] });
    },
    onError: (e: Error) => {
      stepUp.handled(e, () => remove.mutate());
    },
  }));

  /** Queues a probe (the worker holds the key) and waits for its result. */
  const probe = createMutation(() => ({
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
      probeNote = null;
      fieldErrors = {};
    },
    onSuccess: (result: AiProbe) => {
      const r = result.result;
      if (!r?.ok && r?.error === "external-not-acknowledged") {
        // The worker found the address outside the network (this server could not resolve it).
        needsAck = true;
        fieldErrors = { acknowledgeExternal: t("ai.externalAckRequired") };
        probeNote = {
          tone: "error",
          text: t("ai.testFailed", { reason: t("ai.error.externalNotAcknowledged") }),
        };
        return;
      }
      if (!r?.ok) {
        const reason = t(`ai.error.${camel(r?.error ?? "internal")}` as MessageKey);
        probeNote = { tone: "error", text: t("ai.testFailed", { reason }) };
        return;
      }
      if (result.kind === "models") {
        const list = r.models ?? [];
        models = list;
        probeNote = { tone: "info", text: t("ai.modelsLoaded", { count: list.length }) };
      } else {
        probeNote = {
          tone: "info",
          text: t("ai.testOk", { ms: r.latencyMs ?? 0, chars: r.replyChars ?? 0 }),
        };
      }
    },
    onError: (e: Error, kind: "models" | "test") => {
      if (explain(e, () => probe.mutate(kind))) return;
      probeNote = { tone: "error", text: t("ai.testFailed", { reason: t("ai.error.internal") }) };
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    save.mutate();
  }

  const external = $derived(scope === "external" || needsAck);
  const probeBusy = $derived(probe.isPending);
</script>

{#snippet externalBadge()}
  <Badge class="bg-warning/18 text-warning-text">
    <TriangleAlert aria-hidden="true" />
    {t("ai.externalBadge")}
  </Badge>
{/snippet}

<Card>
  <CardHeader
    title={t("ai.settingsTitle")}
    description={t("ai.settingsDescription")}
    actions={stored?.scope === "external" ? externalBadge : undefined}
  />
  <form class="grid gap-5 px-5 py-5" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}

    <div class="grid gap-1">
      <label class="flex items-center gap-2.5 font-medium">
        <Checkbox bind:checked={enabled} />
        {t("ai.enabled")}
      </label>
      <p class="ml-[26px] text-sm text-muted-foreground">{t("ai.enabledHint")}</p>
    </div>

    <div class="grid gap-1.5">
      <Field
        label={t("ai.baseUrl")}
        hint={t("ai.baseUrlHint")}
        error={fieldErrors.baseUrl}
        name="baseUrl"
        bind:value={() => baseUrl, changeBaseUrl}
        required
        autocomplete="off"
        spellcheck={false}
        placeholder="https://llm.example.lan/v1"
        class="font-mono text-sm"
      />
      {#if typedHttp && !external}<Alert tone="info">{t("ai.insecureNote")}</Alert>{/if}
      {#if scope}
        <p class="text-sm text-muted-foreground">
          {scope === "private" ? t("ai.scopePrivate") : scope === "external" ? t("ai.scopeExternal") : t("ai.scopeUnknown")}
        </p>
      {/if}
    </div>

    {#if external}
      <div
        class="grid gap-2 rounded-md border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-3.5 py-3"
      >
        <p class="flex items-center gap-2 font-semibold">
          <TriangleAlert aria-hidden="true" class="size-4 flex-none text-warning-text" />
          {t("ai.externalTitle")}
        </p>
        <p class="text-sm">{t("ai.externalText", { host: host || "…" })}</p>
        <label class="flex items-start gap-2.5">
          <Checkbox class="mt-1" bind:checked={acknowledge} />
          <span>{t("ai.externalAck", { host: host || "…" })}</span>
        </label>
        {#if fieldErrors.acknowledgeExternal}
          <p role="alert" class="text-sm text-destructive-text">
            {fieldErrors.acknowledgeExternal}
          </p>
        {/if}
      </div>
    {/if}

    <div class="grid gap-1.5">
      <label for="ai-model" class="text-sm font-medium">
        {t("ai.model")}
      </label>
      <div class="flex flex-wrap gap-2">
        <input
          id="ai-model"
          name="model"
          list="ai-models"
          bind:value={model}
          autocomplete="off"
          spellcheck={false}
          aria-describedby="ai-model-hint"
          aria-invalid={fieldErrors.model ? true : undefined}
          class="h-10 min-w-0 flex-[1_1_14rem] rounded-md border border-input bg-card px-3 font-mono text-sm shadow-xs aria-invalid:border-destructive"
        />
        <datalist id="ai-models">
          {#each models ?? [] as name (name)}
            <option value={name}></option>
          {/each}
        </datalist>
        <Button variant="outline" disabled={probeBusy || baseUrl.trim() === ""} onclick={() => probe.mutate("models")}>
          {probe.isPending && probe.variables === "models" ? t("ai.loadingModels") : t("ai.loadModels")}
        </Button>
      </div>
      <p id="ai-model-hint" class="text-sm text-muted-foreground">
        {fieldErrors.model ?? t("ai.modelHint")}
      </p>
    </div>

    <div class="grid gap-1.5">
      <Field
        label={t("ai.apiKey")}
        hint={stored?.hasApiKey && !clearKey ? t("ai.apiKeyStored") : t("ai.apiKeyHint")}
        name="apiKey"
        type="password"
        bind:value={apiKey}
        autocomplete="new-password"
        spellcheck={false}
      />
      {#if stored?.hasApiKey}
        <label class="flex items-center gap-2.5 text-sm">
          <Checkbox bind:checked={clearKey} />
          {t("ai.apiKeyRemove")}
        </label>
      {/if}
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
        bind:value={maxTokens}
      />
      <Field
        label={t("ai.temperature")}
        hint={t("ai.temperatureHint")}
        type="number"
        min={0}
        max={2}
        step={0.1}
        required
        bind:value={temperature}
      />
      <Field
        label={t("ai.timeout")}
        hint={t("ai.timeoutHint")}
        type="number"
        min={10}
        max={600}
        step={1}
        required
        bind:value={timeoutSeconds}
      />
      <Field
        label={t("ai.maxConcurrent")}
        hint={t("ai.maxConcurrentHint")}
        type="number"
        min={1}
        max={8}
        step={1}
        required
        bind:value={maxConcurrent}
      />
    </FormRow>

    {#if probeNote}<Alert tone={probeNote.tone}>{probeNote.text}</Alert>{/if}

    <div class="flex flex-wrap items-center gap-3">
      <Button type="submit" disabled={save.isPending}>
        {save.isPending ? t("ai.saving") : t("ai.save")}
      </Button>
      <Button
        variant="outline"
        disabled={probeBusy || baseUrl.trim() === "" || model.trim() === ""}
        onclick={() => probe.mutate("test")}
      >
        <PlugZap aria-hidden="true" class="size-4" />
        {probe.isPending && probe.variables === "test" ? t("ai.testing") : t("ai.test")}
      </Button>
      {#if stored}
        <Button variant="ghost" class="ml-auto" onclick={() => (removing = true)}>
          <Trash2 aria-hidden="true" class="size-4" />
          {t("ai.remove")}
        </Button>
      {/if}
    </div>
  </form>
</Card>
<ConfirmDialog
  open={removing}
  title={t("ai.removeTitle")}
  description={t("ai.removeDescription")}
  confirmLabel={t("ai.removeConfirm")}
  pending={remove.isPending}
  error={remove.isError && !(remove.error instanceof ApiError && remove.error.code === "step-up-required")
    ? t("errors.actionFailed")
    : null}
  onConfirm={() => remove.mutate()}
  onClose={() => (removing = false)}
/>
<StepUpPrompt {stepUp} email={me.user.email} />
