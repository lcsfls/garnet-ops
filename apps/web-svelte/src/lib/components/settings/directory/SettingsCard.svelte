<script lang="ts">
  import {
    DIRECTORY_LIMITS,
    DIRECTORY_PRESET_VALUES,
    type DirectoryPreset,
    GROUP_MODES,
    TLS_TRUSTS,
  } from "@garnetops/core/directory";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { ApiError, api } from "../../../api.ts";
  import type { DirectoryView } from "../../../directory.ts";
  import { formatDateTime, formatRelative } from "../../../format.ts";
  import { hasKey, t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Field from "../../ui/Field.svelte";
  import FormField from "../../ui/FormField.svelte";
  import FormRow from "../../ui/FormRow.svelte";
  import Radio from "../../ui/Radio.svelte";
  import Select from "../../ui/Select.svelte";
  import TextAreaField from "../../ui/TextAreaField.svelte";
  import { bodyOf, type FormState, initialState, MODE_HINTS, MODE_LABELS, PRESET_LABELS } from "./form.ts";
  import GroupRoles from "./GroupRoles.svelte";

  const PRESETS = Object.keys(PRESET_LABELS) as DirectoryPreset[];

  let { me, view, onSaved }: { me: Me; view: DirectoryView; onSaved: () => void } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  // The parent remounts this card after a save ({#key}), so the form starts from the stored settings each time.
  const form = $state<FormState>(untrack(() => initialState(view.settings)));
  let error = $state<string | null>(null);
  let fieldErrors = $state<Record<string, string>>({});
  const settings = $derived(view.settings);

  const save = createMutation(() => ({
    mutationFn: (body: Record<string, unknown>) => api<DirectoryView>("/directory", { method: "PUT", body }),
    onMutate: () => {
      error = null;
      fieldErrors = {};
    },
    onSuccess: async (result: DirectoryView) => {
      toast.success(t("directory.saved"));
      if (result.switchedOff) toast.info(t("directory.switchedOff"));
      // A pinned server's certificate is read as soon as it is known, so there is something to confirm.
      if (result.settings?.tlsTrust === "pin" && result.servers.some((s) => !s.certificate?.pin)) {
        await api("/directory/certificates/scan", { method: "POST", body: {} }).catch(() => {});
      }
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      onSaved();
    },
    onError: (e: Error, body: Record<string, unknown>) => {
      if (stepUp.handled(e, () => save.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        const errors: Record<string, string> = {};
        for (const item of e.problem?.errors ?? []) errors[item.path] = item.message;
        fieldErrors = errors;
        error = t("directory.errorInvalid");
        return;
      }
      if (e instanceof ApiError && e.code === "not-tested") {
        error = t("directory.errorNotTested");
        return;
      }
      if (e instanceof ApiError && e.status === 429) {
        error = t("errors.tooManyAttempts");
        return;
      }
      error = t("errors.actionFailed");
    },
  }));

  const errorOf = (...paths: string[]) => {
    const found = paths.map((p) => fieldErrors[p]).find(Boolean);
    if (!found) return null;
    const key = `directory.fieldError.${found}`;
    return hasKey(key) ? t(key as never) : t("directory.errorInvalid");
  };
  const serverError = () => {
    const path = Object.keys(fieldErrors).find((p) => p === "servers" || p.startsWith("servers."));
    return path ? errorOf(path) : null;
  };
  const groupError = () => {
    const path = Object.keys(fieldErrors).find((p) => p === "groupRoles" || p.startsWith("groupRoles."));
    return path ? errorOf(path) : null;
  };

  function applyPreset(preset: DirectoryPreset) {
    const values = DIRECTORY_PRESET_VALUES[preset];
    // "Other" keeps what is typed; the two known types fill in their usual settings.
    Object.assign(form, { preset, ...(preset === "custom" ? {} : values) });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    save.mutate(bodyOf(form));
  }

  const tested = $derived(view.testedAt !== null);
</script>

{#snippet status()}
  <Badge tone={settings?.enabled ? "info" : "neutral"}>
    {settings?.enabled ? t("directory.statusOn") : t("directory.statusOff")}
  </Badge>
{/snippet}

<Card>
  <CardHeader
    title={t("directory.panelTitle")}
    description={t("directory.panelDescription")}
    actions={view.configured ? status : undefined}
  />
  <form class="grid gap-5 px-5 pt-1 pb-5" onsubmit={submit} novalidate data-testid="directory-form">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {#if view.bindBlockedUntil}<Alert tone="error">{t("directory.blocked")}</Alert>{/if}
    {#if view.configured && view.accounts > 0}
      <p class="text-sm text-muted-foreground">{t("directory.accounts", { count: view.accounts })}</p>
    {/if}

    <FormField id="directory-preset" label={t("directory.preset")} hint={t("directory.presetHint")}>
      {#snippet children(control)}
        <Select
          {...control}
          bind:value={() => form.preset, (value) => applyPreset(value as DirectoryPreset)}
          class="max-w-80"
        >
          {#each PRESETS as p (p)}
            <option value={p}>{t(PRESET_LABELS[p])}</option>
          {/each}
        </Select>
      {/snippet}
    </FormField>

    <fieldset class="grid gap-4 border-t pt-4">
      <legend class="mb-1 font-medium">{t("directory.connectionTitle")}</legend>
      <TextAreaField
        id="directory-servers"
        label={t("directory.servers")}
        hint={t("directory.serversHint")}
        bind:value={form.servers}
        rows={3}
        placeholder={"ldaps://dc1.example.lan\nldaps://dc2.example.lan"}
        error={serverError()}
        autocapitalize="off"
        autocomplete="off"
        spellcheck={false}
        class="font-mono text-sm"
      />
      <fieldset class="grid gap-2">
        <legend class="mb-1 text-sm font-medium">{t("directory.trust")}</legend>
        {#each TLS_TRUSTS as trust (trust)}
          <div class="flex items-start gap-2.5">
            <Radio
              id={`directory-trust-${trust}`}
              name="tlsTrust"
              value={trust}
              checked={form.tlsTrust === trust}
              onchange={() => (form.tlsTrust = trust)}
              aria-describedby={`directory-trust-${trust}-hint`}
              class="mt-1"
            />
            <div>
              <label for={`directory-trust-${trust}`}>{t(`directory.trusts.${trust}`)}</label>
              <span id={`directory-trust-${trust}-hint`} class="block text-sm text-muted-foreground">
                {t(`directory.trustHints.${trust}`)}
              </span>
            </div>
          </div>
        {/each}
      </fieldset>
      {#if form.tlsTrust === "ca"}
        <TextAreaField
          id="directory-ca"
          label={t("directory.caCertificate")}
          hint={t("directory.caCertificateHint")}
          bind:value={form.caCertificate}
          rows={5}
          placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
          error={errorOf("caCertificate")}
          spellcheck={false}
          class="font-mono text-[13px]"
        />
      {/if}
      {#if form.tlsTrust === "pin"}
        <p class="text-sm text-muted-foreground">{t("directory.pinNote")}</p>
      {/if}
    </fieldset>

    <fieldset class="grid gap-4 border-t pt-4">
      <legend class="mb-1 font-medium">{t("directory.serviceTitle")}</legend>
      <p class="-mt-2 text-sm text-muted-foreground">{t("directory.serviceHint")}</p>
      <Field
        id="directory-bind-dn"
        label={t("directory.bindDn")}
        bind:value={form.bindDn}
        placeholder="CN=svc-garnetops,OU=Service,DC=example,DC=lan"
        error={errorOf("bindDn")}
        autocapitalize="off"
        autocomplete="off"
        spellcheck={false}
        class="font-mono text-sm"
      />
      <Field
        id="directory-bind-password"
        label={t("directory.bindPassword")}
        hint={settings?.bindPasswordSet ? t("directory.bindPasswordKeep") : t("directory.bindPasswordHint")}
        type="password"
        bind:value={form.bindPassword}
        error={errorOf("bindPassword")}
        autocomplete="new-password"
        maxlength={DIRECTORY_LIMITS.bindPasswordMax}
      />
    </fieldset>

    <fieldset class="grid gap-4 border-t pt-4">
      <legend class="mb-1 font-medium">{t("directory.usersTitle")}</legend>
      <Field
        id="directory-base"
        label={t("directory.userBaseDn")}
        hint={t("directory.userBaseDnHint")}
        bind:value={form.userBaseDn}
        placeholder="OU=Users,DC=example,DC=lan"
        error={errorOf("userBaseDn")}
        autocapitalize="off"
        autocomplete="off"
        spellcheck={false}
        class="font-mono text-sm"
      />
      <Field
        id="directory-filter"
        label={t("directory.userFilter")}
        hint={t("directory.userFilterHint")}
        bind:value={form.userFilter}
        error={errorOf("userFilter")}
        autocapitalize="off"
        autocomplete="off"
        spellcheck={false}
        class="font-mono text-sm"
      />
      <FormRow columns={3} from="lg">
        <Field
          id="directory-attr-email"
          label={t("directory.emailAttribute")}
          bind:value={form.emailAttribute}
          error={errorOf("emailAttribute")}
          autocapitalize="off"
          spellcheck={false}
          class="font-mono text-sm"
        />
        <Field
          id="directory-attr-name"
          label={t("directory.nameAttribute")}
          bind:value={form.nameAttribute}
          error={errorOf("nameAttribute")}
          autocapitalize="off"
          spellcheck={false}
          class="font-mono text-sm"
        />
        <Field
          id="directory-attr-id"
          label={t("directory.uniqueIdAttribute")}
          hint={t("directory.uniqueIdAttributeHint")}
          bind:value={form.uniqueIdAttribute}
          error={errorOf("uniqueIdAttribute")}
          autocapitalize="off"
          spellcheck={false}
          class="font-mono text-sm"
        />
      </FormRow>
    </fieldset>

    <fieldset class="grid gap-4 border-t pt-4">
      <legend class="mb-1 font-medium">{t("directory.groupsTitle")}</legend>
      <p class="-mt-2 text-sm text-muted-foreground">{t("directory.groupsHint")}</p>
      <FormField id="directory-group-mode" label={t("directory.groupMode")} hint={t(MODE_HINTS[form.groupMode])}>
        {#snippet children(control)}
          <Select {...control} bind:value={form.groupMode} class="max-w-96">
            {#each GROUP_MODES as mode (mode)}
              <option value={mode}>{t(MODE_LABELS[mode])}</option>
            {/each}
          </Select>
        {/snippet}
      </FormField>
      {#if form.groupMode === "search"}
        <Field
          id="directory-group-filter"
          label={t("directory.groupFilter")}
          hint={t("directory.groupFilterHint")}
          bind:value={form.groupFilter}
          error={errorOf("groupFilter")}
          autocapitalize="off"
          spellcheck={false}
          class="font-mono text-sm"
        />
      {/if}
      <GroupRoles
        rows={form.groupRoles}
        onChange={(rows) => (form.groupRoles = rows)}
        error={groupError()}
        invalid={Object.keys(fieldErrors)
          .filter((p) => p.startsWith("groupRoles."))
          .map((p) => Number(p.split(".")[1]))}
      />
    </fieldset>

    <fieldset class="grid gap-4 border-t pt-4">
      <legend class="mb-1 font-medium">{t("directory.optionsTitle")}</legend>
      <label class="flex items-start gap-2.5">
        <Checkbox class="mt-1" bind:checked={form.emailVerified} />
        <span>
          {t("directory.emailVerified")}
          <span class="block text-sm text-muted-foreground">{t("directory.emailVerifiedHint")}</span>
        </span>
      </label>
      <details class="rounded-md border px-3 py-2">
        <summary class="cursor-pointer text-sm font-medium">{t("directory.advanced")}</summary>
        <div class="mt-3">
          <FormRow columns={3} from="lg">
            <Field
              label={t("directory.connectTimeout")}
              type="number"
              min={DIRECTORY_LIMITS.connectTimeoutSeconds.min}
              max={DIRECTORY_LIMITS.connectTimeoutSeconds.max}
              bind:value={form.connectTimeoutSeconds}
              error={errorOf("connectTimeoutSeconds")}
            />
            <Field
              label={t("directory.operationTimeout")}
              type="number"
              min={DIRECTORY_LIMITS.operationTimeoutSeconds.min}
              max={DIRECTORY_LIMITS.operationTimeoutSeconds.max}
              bind:value={form.operationTimeoutSeconds}
              error={errorOf("operationTimeoutSeconds")}
            />
            <Field
              label={t("directory.sizeLimit")}
              hint={t("directory.sizeLimitHint")}
              type="number"
              min={DIRECTORY_LIMITS.sizeLimit.min}
              max={DIRECTORY_LIMITS.sizeLimit.max}
              bind:value={form.sizeLimit}
              error={errorOf("sizeLimit")}
            />
          </FormRow>
        </div>
      </details>
    </fieldset>

    <div class="grid gap-3 border-t pt-4">
      <label class="flex items-start gap-2.5">
        <Checkbox
          class="mt-1"
          bind:checked={form.enabled}
          disabled={!tested && !form.enabled}
          data-testid="directory-enabled"
        />
        <span>
          {t("directory.enable")}
          <span class="block text-sm text-muted-foreground">
            {tested && view.testedAt
              ? t("directory.enableTested", { when: formatRelative(view.testedAt) })
              : t("directory.enableUntested")}
          </span>
        </span>
      </label>
      <div class="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? t("common.loading") : t("directory.save")}
        </Button>
        {#if view.testedAt}
          <span class="text-sm text-muted-foreground">
            {t("directory.lastTest", { when: formatDateTime(view.testedAt) })}
          </span>
        {/if}
      </div>
    </div>
  </form>
  <StepUpPrompt {stepUp} email={me.user.email} />
</Card>
