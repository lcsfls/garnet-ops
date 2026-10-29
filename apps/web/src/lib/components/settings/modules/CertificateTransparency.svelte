<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
  import { hasKey, type MessageKey, t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { ExposureSettings } from "../../../websites.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import QueryStatus from "../../QueryStatus.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Notice from "../../websites/Notice.svelte";

  /**
   * Website monitoring's one switch that sends data out of the network (ADR 0023): the Certificate Transparency lookup. It
   * sends the domain names of verified websites to a public search service, so it is off until an owner or admin switches it
   * on, knowing exactly what is sent where.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let asking = $state(false);
  let acknowledged = $state(false);
  let error = $state<string | null>(null);

  const query = createQuery(() => ({
    queryKey: ["websites", "settings"],
    queryFn: () => api<ExposureSettings>("/exposure/settings"),
  }));
  const ct = $derived(query.data?.certificateTransparency);

  const save = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api("/exposure/settings", {
        method: "PUT",
        body: { ct: { enabled, acknowledged: enabled ? acknowledged : undefined } },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async (_: unknown, enabled: boolean) => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      asking = false;
      acknowledged = false;
      toast.success(t(enabled ? "websites.ctSwitchedOn" : "websites.ctSwitchedOff"));
    },
    onError: (e: Error, enabled: boolean) => {
      if (stepUp.handled(e, () => save.mutate(enabled))) return;
      error =
        e instanceof ApiError && e.status === 422
          ? t("websites.ctNeedsAcknowledgement")
          : t("errors.actionFailed");
    },
  }));
  const ctError = (code: string) =>
    hasKey(`websites.ctError.${code}`) ? t(`websites.ctError.${code}` as MessageKey) : code;
</script>

<Card>
  <CardHeader title={t("websites.settingsTitle")} description={t("websites.settingsDescription")} />
  <div class="grid gap-3 px-5 pb-5">
    <QueryStatus {query} />
    {#if error && !asking}<Alert tone="error">{error}</Alert>{/if}
    {#if ct}
      <section class="grid gap-3 rounded-lg border p-4" aria-labelledby="ct-title" data-testid="ct-section">
        <div class="flex flex-wrap items-center gap-2">
          <h3 id="ct-title" class="font-medium">{t("websites.ctTitle")}</h3>
          <Badge tone={ct.enabled ? "info" : "neutral"}>{t(ct.enabled ? "websites.ctOn" : "websites.ctOff")}</Badge>
        </div>
        <p class="text-sm text-muted-foreground">{t("websites.ctText")}</p>
        <Notice title={t("websites.ctLeavesTitle", { provider: ct.provider.name })}>
          {t("websites.ctLeavesText", { provider: ct.provider.name, operator: ct.provider.operator })}
        </Notice>
        <div class="grid gap-1">
          <span class="text-sm font-medium">{t("websites.ctRequest")}</span>
          <code data-testid="ct-url" class="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all">
            {ct.provider.urlTemplate}
          </code>
          <span class="text-sm text-muted-foreground">{t("websites.ctRequestHint")}</span>
        </div>
        {#if ct.enabled}
          <p class="text-sm text-muted-foreground">
            {t("websites.ctEnabledBy", {
              name: ct.enabledBy ?? "–",
              when: ct.enabledAt ? formatDateTime(ct.enabledAt) : "–",
            })}
            {t("websites.ctUsage", { used: ct.usageToday, budget: ct.dailyBudget })}
          </p>
        {/if}
        {#if ct.lastError}<Alert tone="error">{ctError(ct.lastError)}</Alert>{/if}
        {#if canEdit}
          <div>
            {#if ct.enabled}
              <Button variant="outline" disabled={save.isPending} onclick={() => save.mutate(false)}>
                {t("websites.ctSwitchOff")}
              </Button>
            {:else}
              <Button
                onclick={() => {
                  error = null;
                  asking = true;
                }}
              >
                {t("websites.ctSwitchOn")}
              </Button>
            {/if}
          </div>
        {/if}
      </section>
    {/if}
  </div>
</Card>

{#if ct && asking}
  <Dialog
    open
    onClose={() => (asking = false)}
    title={t("websites.ctAskTitle", { provider: ct.provider.name })}
    description={t("websites.ctAskDescription")}
  >
    <div class="grid gap-4">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Notice title={t("websites.ctLeavesTitle", { provider: ct.provider.name })}>
        {t("websites.ctLeavesText", { provider: ct.provider.name, operator: ct.provider.operator })}
      </Notice>
      <code class="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all">{ct.provider.urlTemplate}</code>
      <p class="text-sm text-muted-foreground">{t("websites.ctTermsNote", { provider: ct.provider.name })}</p>
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>{t("websites.ctAcknowledge", { provider: ct.provider.name })}</span>
      </label>
      <DialogFooter>
        <Button variant="outline" onclick={() => (asking = false)}>{t("common.cancel")}</Button>
        <Button disabled={!acknowledged || save.isPending} onclick={() => save.mutate(true)}>
          {save.isPending ? t("common.loading") : t("websites.ctSwitchOn")}
        </Button>
      </DialogFooter>
    </div>
  </Dialog>
{/if}
<StepUpPrompt {stepUp} email={me.user.email} />
