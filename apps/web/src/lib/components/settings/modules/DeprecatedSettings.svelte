<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatRelative } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import QueryStatus from "../../QueryStatus.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Button from "../../ui/Button.svelte";
  import Field from "../../ui/Field.svelte";
  import TextAreaField from "../../ui/TextAreaField.svelte";

  /**
   * The settings of the deprecated packages module (ADR 0051): which registries are asked (the public ones, or the organisation's
   * own) and which names never leave. Everyone sees them; admins with a recent sign-in change them.
   */
  type Ecosystem = "npm" | "pypi" | "crates";
  interface Settings {
    enabled: boolean;
    registries: Record<Ecosystem, string | null>;
    defaults: Record<Ecosystem, string>;
    excluded: string[];
    lastRun: {
      at: string;
      asked: number;
      failed: number;
      skipped: number;
      problems: Record<string, string>;
    } | null;
  }
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const settings = createQuery(() => ({
    queryKey: ["deprecated-settings"],
    queryFn: () => api<Settings>("/deprecated/settings"),
  }));
  const ECOSYSTEMS: Ecosystem[] = ["npm", "pypi", "crates"];

  let registries = $state<Record<Ecosystem, string>>({ npm: "", pypi: "", crates: "" });
  let excluded = $state("");
  let error = $state<string | null>(null);
  let loaded = false;
  $effect(() => {
    const s = settings.data;
    if (!s || loaded) return;
    loaded = true;
    registries = {
      npm: s.registries.npm ?? "",
      pypi: s.registries.pypi ?? "",
      crates: s.registries.crates ?? "",
    };
    excluded = s.excluded.join("\n");
  });

  const save = createMutation(() => ({
    mutationFn: () =>
      api<Settings>("/deprecated/settings", {
        method: "PUT",
        body: {
          registries: Object.fromEntries(ECOSYSTEMS.map((e) => [e, registries[e].trim() || null])),
          excluded: excluded
            .split(/[\n,]/)
            .map((x) => x.trim())
            .filter(Boolean),
        },
      }),
    onSuccess: (next: Settings) => {
      error = null;
      queryClient.setQueryData(["deprecated-settings"], next);
      toast.success(t("deprecated.saved"));
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      if (e instanceof ApiError && e.status === 422)
        error = e.problem?.errors?.[0]?.message ?? t("errors.actionFailed");
      else toast.error(t("errors.actionFailed"));
    },
  }));
  const check = createMutation(() => ({
    mutationFn: () => api("/deprecated/check", { method: "POST" }),
    onSuccess: () => toast.success(t("deprecated.checkQueued")),
    onError: (e: Error) =>
      toast.error(
        e instanceof ApiError && e.status === 429 ? t("deprecated.checkRecent") : t("errors.actionFailed"),
      ),
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    save.mutate();
  }
</script>

<StepUpPrompt {stepUp} email={me.user.email} />
<section class="grid gap-4 rounded-lg border p-4" aria-labelledby="deprecated-settings" data-testid="deprecated-settings">
  <div class="grid gap-1">
    <h3 id="deprecated-settings" class="font-medium">{t("deprecated.settingsTitle")}</h3>
    <p class="text-sm text-muted-foreground">{t("deprecated.settingsText")}</p>
  </div>
  <QueryStatus query={settings} />
  {#if settings.data}
    {@const s = settings.data}
    <form class="grid gap-4" onsubmit={submit}>
      <div class="grid gap-3 @3xl:grid-cols-3">
        {#each ECOSYSTEMS as e (e)}
          <Field
            label={t(`deprecated.registry.${e}`)}
            hint={t("deprecated.registryHint")}
            placeholder={s.defaults[e]}
            inputmode="url"
            disabled={!canEdit}
            bind:value={registries[e]}
          />
        {/each}
      </div>
      <TextAreaField
        label={t("deprecated.excluded")}
        hint={t("deprecated.excludedHint")}
        rows={3}
        disabled={!canEdit}
        bind:value={excluded}
        {error}
      />
      <div class="flex flex-wrap items-center gap-2">
        {#if canEdit}
          <Button type="submit" disabled={save.isPending}>{t("deprecated.save")}</Button>
        {/if}
        {#if me.role !== "viewer"}
          <Button variant="secondary" disabled={check.isPending} onclick={() => check.mutate()}>
            {t("deprecated.checkNow")}
          </Button>
        {/if}
      </div>
    </form>
    <p class="text-sm text-muted-foreground" data-testid="deprecated-last-run">
      {#if s.lastRun}
        {t("deprecated.lastRun", {
          when: formatRelative(s.lastRun.at),
          asked: s.lastRun.asked,
          failed: s.lastRun.failed,
          skipped: s.lastRun.skipped,
        })}
        {#each Object.entries(s.lastRun.problems) as [e, code] (e)}
          <span class="block">{t("deprecated.problem", { registry: t(`deprecated.registry.${e as Ecosystem}`), code })}</span>
        {/each}
      {:else}
        {t("deprecated.neverRun")}
      {/if}
    </p>
  {/if}
</section>
