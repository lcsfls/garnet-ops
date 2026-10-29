<script lang="ts">
  import { LANGUAGE_NAMES, LANGUAGES } from "@garnetops/i18n";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { language, t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Field from "../../ui/Field.svelte";
  import FormRow from "../../ui/FormRow.svelte";
  import Radio from "../../ui/Radio.svelte";
  import Select from "../../ui/Select.svelte";
  import ChannelEventsFields from "./ChannelEventsFields.svelte";
  import { type ChannelEvent, FORMATS, filtersBody, KINDS, type Kind, type MinSeverity } from "./channels.ts";

  let { me, open, onClose }: { me: Me; open: boolean; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let kind = $state<Kind>("webhook");
  let events = $state<ChannelEvent[]>(["finding.new_critical", "gate.blocked"]);
  let minSeverity = $state<MinSeverity>("high");
  let repositoryIds = $state<string[] | null>(null);
  let error = $state<string | null>(null);
  let fieldErrors = $state<Record<string, string>>({});
  const create = createMutation(() => ({
    mutationFn: (body: Record<string, unknown>) => api("/notifications/channels", { method: "POST", body }),
    onMutate: () => {
      error = null;
      fieldErrors = {};
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      close();
    },
    onError: (e: Error, body: Record<string, unknown>) => {
      if (stepUp.handled(e, () => create.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        fieldErrors = Object.fromEntries(
          (e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message]),
        );
        error = t("repositories.errorInvalid");
        return;
      }
      error = t("errors.actionFailed");
    },
  }));

  function close() {
    kind = "webhook";
    events = ["finding.new_critical", "gate.blocked"];
    minSeverity = "high";
    repositoryIds = null;
    error = null;
    fieldErrors = {};
    onClose();
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const f = new FormData(event.currentTarget as HTMLFormElement);
    const s = (k: string) => String(f.get(k) ?? "").trim();
    const list = (k: string) =>
      s(k)
        .split(/[\s,;]+/)
        .filter(Boolean);
    const base = {
      name: s("name"),
      events,
      language: s("language") || "en",
      kind,
      filters: filtersBody(minSeverity, repositoryIds),
    };
    const body =
      kind === "webhook"
        ? { ...base, format: s("format"), url: s("url") }
        : kind === "smtp"
          ? {
              ...base,
              host: s("host"),
              port: Number(s("port")),
              security: s("security"),
              username: s("username") || undefined,
              password: String(f.get("password") ?? "") || undefined,
              from: s("from"),
              to: list("to"),
            }
          : {
              ...base,
              tenantId: s("tenantId"),
              clientId: s("clientId"),
              clientSecret: String(f.get("clientSecret") ?? ""),
              from: s("from"),
              to: list("to"),
            };
    create.mutate(body);
  }

  const defaultLanguage = $derived(LANGUAGES.find((l) => l === language()) ?? "en");
</script>

<Dialog {open} onClose={close} title={t("settings.addChannelTitle")} description={t("settings.addChannelDescription")}>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <Field label={t("settings.channelName")} name="name" required maxlength={80} error={fieldErrors.name} />
    <fieldset class="grid gap-2">
      <legend class="mb-1.5 text-sm font-medium">{t("settings.channelKind")}</legend>
      {#each KINDS as k (k)}
        <label class="flex items-center gap-2.5">
          <Radio name="kind" value={k} checked={kind === k} onchange={() => (kind = k)} />
          {t(`settings.kind.${k}`)}
        </label>
      {/each}
    </fieldset>
    {#if kind === "webhook"}
      <label class="grid gap-1.5">
        <span class="text-sm font-medium">{t("settings.webhookFormat")}</span>
        <Select name="format" value="discord">
          {#each FORMATS as format (format)}
            <option value={format}>{t(`settings.format.${format}`)}</option>
          {/each}
        </Select>
      </label>
      <Field
        label={t("settings.webhookUrl")}
        hint={t("settings.webhookUrlHint")}
        name="url"
        type="url"
        required
        autocomplete="off"
        spellcheck={false}
        class="font-mono text-sm"
        error={fieldErrors.url}
      />
    {/if}
    {#if kind === "smtp"}
      <FormRow columns={["1fr", "8rem"]} from="md">
        <Field label={t("settings.smtpHost")} name="host" required spellcheck={false} error={fieldErrors.host} />
        <Field label={t("settings.smtpPort")} name="port" type="number" required value={587} min={1} max={65535} />
      </FormRow>
      <label class="grid gap-1.5">
        <span class="text-sm font-medium">{t("settings.smtpSecurity")}</span>
        <Select name="security" value="starttls">
          <option value="starttls">{t("settings.smtpSecurityStartTls")}</option>
          <option value="tls">{t("settings.smtpSecurityTls")}</option>
        </Select>
      </label>
      <Field label={t("settings.smtpUser")} name="username" autocomplete="off" />
      <Field
        label={t("settings.smtpPassword")}
        name="password"
        type="password"
        autocomplete="new-password"
        error={fieldErrors.password}
      />
    {/if}
    {#if kind === "graph"}
      <Alert tone="info">{t("settings.graphHint")}</Alert>
      <Field
        label={t("settings.graphTenant")}
        name="tenantId"
        required
        spellcheck={false}
        error={fieldErrors.tenantId}
      />
      <Field
        label={t("settings.graphClient")}
        name="clientId"
        required
        spellcheck={false}
        error={fieldErrors.clientId}
      />
      <Field
        label={t("settings.graphSecret")}
        name="clientSecret"
        type="password"
        required
        autocomplete="new-password"
      />
    {/if}
    {#if kind !== "webhook"}
      <Field label={t("settings.mailFrom")} name="from" type="email" required error={fieldErrors.from} />
      <Field
        label={t("settings.mailTo")}
        hint={t("settings.mailToHint")}
        name="to"
        required
        error={fieldErrors.to}
      />
    {/if}
    <ChannelEventsFields bind:events bind:minSeverity bind:repositoryIds error={fieldErrors.filters} />
    <label class="grid gap-1.5">
      <span class="text-sm font-medium">{t("settings.channelLanguage")}</span>
      <Select name="language" value={defaultLanguage}>
        {#each LANGUAGES as l (l)}
          <option value={l}>{LANGUAGE_NAMES[l]}</option>
        {/each}
      </Select>
    </label>
    <DialogFooter>
      <Button variant="outline" onclick={close}>
        {t("common.cancel")}
      </Button>
      <Button
        type="submit"
        disabled={create.isPending || events.length === 0 || repositoryIds?.length === 0}
      >
        {create.isPending ? t("common.loading") : t("settings.channelSave")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
<StepUpPrompt {stepUp} email={me.user.email} />
