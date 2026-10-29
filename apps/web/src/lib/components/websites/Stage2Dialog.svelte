<script lang="ts">
  import {
    ACTIVE_LIMITS,
    ACTIVE_SCHEDULES,
    EXPOSURE_PORTS,
    STAGE2_ACKNOWLEDGEMENT_ID,
  } from "@garnetops/core/exposure";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Select from "../ui/Select.svelte";
  import Notice from "./Notice.svelte";

  /**
   * Switching stage 2 on or off, and running it by hand (ADR 0023). Switching on shows what the stage does, what it never
   * does and the warning about the infrastructure behind a name, and asks for an explicit acknowledgement per website. The
   * API wants a recent sign-in. Mounted fresh each time it opens.
   */
  let { asset, email, onClose }: { asset: ExposureDetail; email: string; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  // svelte-ignore state_referenced_locally
  let schedule = $state<(typeof ACTIVE_SCHEDULES)[number]>(asset.stage2.schedule);
  let acknowledged = $state(false);
  let error = $state<string | null>(null);
  const on = $derived(asset.stage2.enabled);
  const verified = $derived(asset.verification.effective);

  async function done(message: string) {
    await queryClient.invalidateQueries({ queryKey: ["websites"] });
    toast.success(message);
    onClose();
  }
  function fail(e: Error, again: () => void) {
    if (stepUp.handled(e, again)) return;
    if (e instanceof ApiError && e.code === "not-verified") error = t("websites.stage2Errors.notVerified");
    else if (e instanceof ApiError && e.code === "too-soon") error = t("websites.stage2Errors.tooSoon");
    else error = t("errors.actionFailed");
  }
  const enable = createMutation(() => ({
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
    onMutate: () => {
      error = null;
    },
    onSuccess: () => done(t("websites.stage2SwitchedOn")),
    onError: (e: Error) => fail(e, () => enable.mutate()),
  }));
  const disable = createMutation(() => ({
    mutationFn: () => api(`/exposure/${asset.id}/stage2`, { method: "PUT", body: { enabled: false } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => done(t("websites.stage2SwitchedOff")),
    onError: (e: Error) => fail(e, () => disable.mutate()),
  }));
  const runNow = createMutation(() => ({
    mutationFn: () => api(`/exposure/${asset.id}/stage2/run`, { method: "POST" }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => done(t("websites.stage2RunQueued")),
    onError: (e: Error) => fail(e, () => runNow.mutate()),
  }));

  const next = $derived(asset.stage2.nextManualAt ? new Date(asset.stage2.nextManualAt) : null);
  const canRunNow = $derived(on && (!next || next.getTime() <= Date.now()));
</script>

<Dialog
  open
  {onClose}
  title={t(on ? "websites.stage2ManageTitle" : "websites.stage2EnableTitle", { asset: asset.value })}
  description={t("websites.stage2Description")}
>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <Notice title={t("websites.stage2WarningTitle")}>{t("websites.stage2WarningText")}</Notice>

    <section class="grid gap-2" aria-labelledby="stage2-does">
      <h3 id="stage2-does" class="font-medium">{t("websites.stage2DoesTitle")}</h3>
      <ul class="grid list-disc gap-1 pl-5 text-sm text-muted-foreground">
        <li>{t("websites.stage2DoesPorts", { count: EXPOSURE_PORTS.length })}</li>
        <li>
          {t("websites.stage2DoesLimits", {
            concurrency: ACTIVE_LIMITS.concurrency,
            gap: ACTIVE_LIMITS.gapMs,
            timeout: ACTIVE_LIMITS.connectTimeoutMs / 1000,
          })}
        </li>
        <li>
          {t("websites.stage2DoesBanner", {
            seconds: ACTIVE_LIMITS.bannerReadMs / 1000,
            bytes: ACTIVE_LIMITS.bannerBytes,
          })}
        </li>
        <li>{t("websites.stage2DoesOnce")}</li>
      </ul>
      <details class="text-sm">
        <summary class="cursor-pointer text-primary-text">{t("websites.stage2PortList")}</summary>
        <ul class="mt-2 flex flex-wrap gap-1.5" data-testid="stage2-ports">
          {#each EXPOSURE_PORTS as p (p.port)}
            <li class="rounded-md border px-2 py-0.5 text-muted-foreground">
              <span class="font-mono text-foreground">{p.port}</span>
              {t(`websites.service.${p.service}` as MessageKey)}
            </li>
          {/each}
        </ul>
      </details>
    </section>

    <section class="grid gap-2" aria-labelledby="stage2-never">
      <h3 id="stage2-never" class="font-medium">{t("websites.stage2NeverTitle")}</h3>
      <p class="text-sm text-muted-foreground">{t("websites.stage2NeverText")}</p>
      <p class="text-sm text-muted-foreground">{t("websites.stage2IdsNote")}</p>
    </section>

    {#if on}
      <p class="text-sm text-muted-foreground">
        {t("websites.stage2OnSince", {
          schedule: t(`websites.schedule.${asset.stage2.schedule}`),
          when: asset.stage2.acknowledgedAt ? formatDateTime(asset.stage2.acknowledgedAt) : "",
        })}
      </p>
      {#if !canRunNow && next}
        <p class="text-sm text-muted-foreground">{t("websites.stage2NextRun", { when: formatDateTime(next) })}</p>
      {/if}
    {:else if !verified}
      <Alert tone="info">{t("websites.stage2NeedsProof")}</Alert>
    {:else}
      <div class="grid max-w-60 gap-1.5">
        <label for="stage2-schedule" class="text-sm font-medium">{t("websites.stage2Schedule")}</label>
        <Select
          id="stage2-schedule"
          value={schedule}
          onchange={(e) => (schedule = e.currentTarget.value as typeof schedule)}
        >
          {#each ACTIVE_SCHEDULES as s (s)}
            <option value={s}>{t(`websites.schedule.${s}`)}</option>
          {/each}
        </Select>
      </div>
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>
          <b class="font-medium">{t("websites.stage2Acknowledge")}</b>
          <span class="block text-sm text-muted-foreground">{t("websites.stage2AcknowledgeHint")}</span>
        </span>
      </label>
    {/if}
    <p class="text-sm text-muted-foreground">{t("websites.notLegalAdvice")}</p>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.close")}</Button>
      {#if on}
        <Button variant="outline" disabled={!canRunNow || runNow.isPending} onclick={() => runNow.mutate()}>
          {t("websites.stage2RunNow")}
        </Button>
        <Button variant="destructive" disabled={disable.isPending} onclick={() => disable.mutate()}>
          {t("websites.stage2SwitchOff")}
        </Button>
      {:else}
        <Button disabled={!verified || !acknowledged || enable.isPending} onclick={() => enable.mutate()}>
          {enable.isPending ? t("common.loading") : t("websites.stage2SwitchOn")}
        </Button>
      {/if}
    </DialogFooter>
  </div>
</Dialog>
<StepUpPrompt {stepUp} {email} />
