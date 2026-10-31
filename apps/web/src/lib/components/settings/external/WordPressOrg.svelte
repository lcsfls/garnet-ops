<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { ExposureSettings } from "../../../websites.ts";
  import Card from "../../Card.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Notice from "../../websites/Notice.svelte";

  /**
   * Latest versions of WordPress plugins and themes from wordpress.org (ADR 0042, part 2). It sends the slugs the websites' home
   * pages name to api.wordpress.org, so it is off until an owner or admin switches it on, knowing exactly what is sent where.
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
  const wp = $derived(query.data?.wordpressOrg);

  const save = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api("/exposure/settings", {
        method: "PUT",
        body: { wordpressOrg: { enabled, acknowledged: enabled ? acknowledged : undefined } },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async (_: unknown, enabled: boolean) => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      asking = false;
      acknowledged = false;
      toast.success(t(enabled ? "websites.wpOrgSwitchedOn" : "websites.wpOrgSwitchedOff"));
    },
    onError: (e: Error, enabled: boolean) => {
      if (stepUp.handled(e, () => save.mutate(enabled))) return;
      error =
        e instanceof ApiError && e.status === 422
          ? t("websites.ctNeedsAcknowledgement")
          : t("errors.actionFailed");
    },
  }));
  const example = $derived(
    wp ? `https://${wp.host}/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>` : "",
  );
</script>

{#if wp}
  <Card>
    <section class="grid gap-3 p-5" aria-labelledby="wp-org-title" data-testid="wordpress-org-section">
      <div class="flex flex-wrap items-center gap-2">
        <h3 id="wp-org-title" class="font-medium">{t("websites.wpOrgTitle")}</h3>
        <Badge tone={wp.enabled ? "info" : "neutral"}>{t(wp.enabled ? "websites.ctOn" : "websites.ctOff")}</Badge>
      </div>
      <p class="text-sm text-muted-foreground">{t("websites.wpOrgText")}</p>
      <Notice title={t("websites.wpOrgLeavesTitle", { host: wp.host })}>{t("websites.wpOrgLeavesText")}</Notice>
      <code class="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all">{example}</code>
      {#if wp.enabled}
        <p class="text-sm text-muted-foreground">
          {t("websites.ctEnabledBy", {
            name: wp.enabledBy ?? "–",
            when: wp.enabledAt ? formatDateTime(wp.enabledAt) : "–",
          })}
        </p>
      {/if}
      {#if error && !asking}<Alert tone="error">{error}</Alert>{/if}
      {#if canEdit}
        <div>
          {#if wp.enabled}
            <Button variant="outline" disabled={save.isPending} onclick={() => save.mutate(false)}>
              {t("websites.wpOrgSwitchOff")}
            </Button>
          {:else}
            <Button
              onclick={() => {
                error = null;
                asking = true;
              }}
            >
              {t("websites.wpOrgSwitchOn")}
            </Button>
          {/if}
        </div>
      {/if}
    </section>
  </Card>
{/if}

{#if wp && asking}
  <Dialog
    open
    onClose={() => (asking = false)}
    title={t("websites.wpOrgAskTitle")}
    description={t("websites.wpOrgText")}
  >
    <div class="grid gap-4">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Notice title={t("websites.wpOrgLeavesTitle", { host: wp.host })}>{t("websites.wpOrgLeavesText")}</Notice>
      <code class="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all">{example}</code>
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>{t("websites.wpOrgAcknowledge", { host: wp.host })}</span>
      </label>
      <DialogFooter>
        <Button variant="outline" onclick={() => (asking = false)}>{t("common.cancel")}</Button>
        <Button disabled={!acknowledged || save.isPending} onclick={() => save.mutate(true)}>
          {save.isPending ? t("common.loading") : t("websites.wpOrgSwitchOn")}
        </Button>
      </DialogFooter>
    </div>
  </Dialog>
{/if}
<StepUpPrompt {stepUp} email={me.user.email} />
