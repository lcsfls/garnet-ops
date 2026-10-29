<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
  import type { HostSettings } from "../../../hosts.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
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
   * The one switch of hosts and containers that sends data out of the network (ADR 0034): asking public registries for newer images.
   * Off until an owner or admin switches it on, with an acknowledgement and a recent sign-in.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let asking = $state(false);
  let acknowledged = $state(false);
  let error = $state<string | null>(null);

  const query = createQuery(() => ({
    queryKey: ["hosts", "settings"],
    queryFn: () => api<HostSettings>("/hosts/settings"),
  }));
  const rc = $derived(query.data?.registryChecks);

  const save = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api("/hosts/settings", {
        method: "PUT",
        body: { registryChecks: { enabled, acknowledged: enabled ? acknowledged : undefined } },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async (_: unknown, enabled: boolean) => {
      await queryClient.invalidateQueries({ queryKey: ["hosts"] });
      asking = false;
      acknowledged = false;
      toast.success(t(enabled ? "hosts.registrySwitchedOn" : "hosts.registrySwitchedOff"));
    },
    onError: (e: Error, enabled: boolean) => {
      if (stepUp.handled(e, () => save.mutate(enabled))) return;
      error =
        e instanceof ApiError && e.status === 422
          ? t("websites.ctNeedsAcknowledgement")
          : t("errors.actionFailed");
    },
  }));
</script>

<Card>
  <CardHeader title={t("hosts.settingsTitle")} description={t("hosts.settingsDescription")} />
  <div class="grid gap-3 px-5 pb-5">
    <QueryStatus {query} />
    {#if error && !asking}<Alert tone="error">{error}</Alert>{/if}
    {#if rc}
      <section class="grid gap-3 rounded-lg border p-4" aria-labelledby="registry-title" data-testid="registry-section">
        <div class="flex flex-wrap items-center gap-2">
          <h3 id="registry-title" class="font-medium">{t("hosts.registryTitle")}</h3>
          <Badge tone={rc.enabled ? "info" : "neutral"}>{rc.enabled ? t("hosts.registryOn") : t("hosts.registryOff")}</Badge>
        </div>
        <p class="text-sm text-muted-foreground">{t("hosts.registryText")}</p>
        <Notice title={t("hosts.registryLeavesTitle")}>{t("hosts.registryLeavesText")}</Notice>
        {#if rc.enabled}
          <p class="text-sm text-muted-foreground">
            {t("hosts.registryEnabledBy", {
              name: rc.enabledBy ?? "–",
              when: rc.enabledAt ? formatDateTime(rc.enabledAt) : "–",
            })}
          </p>
        {/if}
        {#if canEdit}
          <div>
            {#if rc.enabled}
              <Button variant="outline" disabled={save.isPending} onclick={() => save.mutate(false)}>
                {t("hosts.registrySwitchOff")}
              </Button>
            {:else}
              <Button
                onclick={() => {
                  error = null;
                  asking = true;
                }}
              >
                {t("hosts.registrySwitchOn")}
              </Button>
            {/if}
          </div>
        {/if}
      </section>
    {/if}
  </div>
</Card>

{#if asking}
  <Dialog open onClose={() => (asking = false)} title={t("hosts.registryAskTitle")} description={t("hosts.registryAskDescription")}>
    <div class="grid gap-4">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Notice title={t("hosts.registryLeavesTitle")}>{t("hosts.registryLeavesText")}</Notice>
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>{t("hosts.registryAcknowledge")}</span>
      </label>
      <DialogFooter>
        <Button variant="outline" onclick={() => (asking = false)}>{t("common.cancel")}</Button>
        <Button disabled={!acknowledged || save.isPending} onclick={() => save.mutate(true)}>
          {save.isPending ? t("common.loading") : t("hosts.registrySwitchOn")}
        </Button>
      </DialogFooter>
    </div>
  </Dialog>
{/if}
<StepUpPrompt {stepUp} email={me.user.email} />
