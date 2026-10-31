<script lang="ts" module>
  /** One key of the own vulnerability database build as the API shows it; the key itself is never returned. */
  export interface VulnDbBuildKeyState {
    configured: boolean;
    setAt: string | null;
    /** Null when the person was removed, or set it from another organisation of this installation. */
    setBy: string | null;
  }
</script>

<script lang="ts">
  import { VULNDB_BUILD_HOSTS, VULNDB_BUILD_KEYS } from "@garnetops/core/vulndb-build";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Field from "../../ui/Field.svelte";
  import Notice from "../../websites/Notice.svelte";

  /**
   * One optional key of the own vulnerability database build: whether it is set, by whom and when, and a dialog to set or
   * replace it. The value is sent once, sealed by the API at once and never shown again.
   */
  let {
    kind,
    current: info,
    canEdit,
    stepUp,
  }: { kind: "github" | "nvd"; current: VulnDbBuildKeyState; canEdit: boolean; stepUp: StepUp } = $props();

  const CONFIG = {
    github: {
      path: "/vulndb-build/github-token",
      body: (value: string) => ({ token: value }),
      pattern: VULNDB_BUILD_KEYS.githubToken,
      host: VULNDB_BUILD_HOSTS.githubToken,
      maxlength: 266,
    },
    nvd: {
      path: "/vulndb-build/nvd-api-key",
      body: (value: string) => ({ key: value }),
      pattern: VULNDB_BUILD_KEYS.nvdApiKey,
      host: VULNDB_BUILD_HOSTS.nvdApiKey,
      maxlength: 36,
    },
  } as const;
  const config = $derived(CONFIG[kind]);

  const queryClient = useQueryClient();
  let asking = $state(false);
  let value = $state("");
  let acknowledged = $state(false);
  let error = $state<string | null>(null);
  const valid = $derived(config.pattern.test(value.trim()));

  const close = () => {
    asking = false;
    value = "";
    acknowledged = false;
  };
  const save = createMutation(() => ({
    mutationFn: () =>
      api(config.path, { method: "PUT", body: { ...config.body(value.trim()), acknowledged } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["vulndb-build"] });
      close();
      toast.success(t(`settings.vulnDbBuild.${kind}.saved`));
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      error =
        e instanceof ApiError && e.status === 422
          ? t(`settings.vulnDbBuild.${kind}.invalid`)
          : t("errors.actionFailed");
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api(config.path, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["vulndb-build"] });
      toast.success(t(`settings.vulnDbBuild.${kind}.removed`));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<section class="grid gap-2 border-t px-5 py-4" data-testid={`vulndb-build-${kind}`} aria-labelledby={`vulndb-build-${kind}-title`}>
  <div class="flex flex-wrap items-start gap-x-3 gap-y-1">
    <div class="min-w-0 flex-1">
      <h3 id={`vulndb-build-${kind}-title`} class="font-medium">{t(`settings.vulnDbBuild.${kind}.title`)}</h3>
      <p class="text-sm text-muted-foreground">{t(`settings.vulnDbBuild.${kind}.text`)}</p>
    </div>
    <Badge tone={info.configured ? "info" : "neutral"}>
      {info.configured ? t("settings.vulnDbBuild.configured") : t("settings.vulnDbBuild.notSet")}
    </Badge>
  </div>
  <p class="text-sm text-muted-foreground">
    {t(`settings.vulnDbBuild.${kind}.sends`, { host: config.host })}
    {#if info.configured && info.setAt}
      {info.setBy
        ? t("settings.vulnDbBuild.setBy", { name: info.setBy, when: formatDateTime(info.setAt) })
        : t("settings.vulnDbBuild.setAt", { when: formatDateTime(info.setAt) })}
    {/if}
  </p>
  {#if canEdit}
    <div class="flex flex-wrap gap-2">
      <Button
        variant="outline"
        onclick={() => {
          error = null;
          asking = true;
        }}
      >
        {info.configured ? t(`settings.vulnDbBuild.${kind}.replace`) : t(`settings.vulnDbBuild.${kind}.set`)}
      </Button>
      {#if info.configured}
        <Button variant="outline" disabled={remove.isPending} onclick={() => remove.mutate()}>
          {t(`settings.vulnDbBuild.${kind}.remove`)}
        </Button>
      {/if}
    </div>
  {/if}
</section>

{#if asking}
  <Dialog
    open
    onClose={close}
    title={t(`settings.vulnDbBuild.${kind}.title`)}
    description={t(`settings.vulnDbBuild.${kind}.text`)}
  >
    <form
      class="grid gap-4"
      onsubmit={(e) => {
        e.preventDefault();
        // The API checks the shape again; this only spares a round trip and says what is wrong.
        if (!valid) error = t(`settings.vulnDbBuild.${kind}.invalid`);
        else save.mutate();
      }}
    >
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Notice title={t(`settings.vulnDbBuild.${kind}.sends`, { host: config.host })} />
      <Field
        label={t(`settings.vulnDbBuild.${kind}.field`)}
        hint={t("settings.vulnDbBuild.keyHint")}
        type="password"
        name={`vulndb-${kind}-key`}
        bind:value
        autocomplete="off"
        spellcheck={false}
        required
        maxlength={config.maxlength}
        class="font-mono"
      />
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>{t(`settings.vulnDbBuild.${kind}.acknowledge`, { host: config.host })}</span>
      </label>
      <DialogFooter>
        <Button type="button" variant="outline" onclick={close}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={!acknowledged || value.trim() === "" || save.isPending}>
          {save.isPending ? t("common.loading") : t("settings.save")}
        </Button>
      </DialogFooter>
    </form>
  </Dialog>
{/if}
