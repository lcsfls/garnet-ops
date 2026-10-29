<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { toast } from "../../../toast.svelte.ts";
  import { refreshMe } from "../../account/refresh-me.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import ConfirmDialog from "../../ui/ConfirmDialog.svelte";
  import CertificateTransparency from "./CertificateTransparency.svelte";

  /**
   * Settings, Modules (ADR 0033): parts of GarnetOps an organisation switches on. Website monitoring is off by default,
   * because once it is on the installation connects to public hosts an admin names. Switching is audited; switching off
   * keeps the data and switches stage 2 off for every website.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const websites = $derived(me.organization.modules?.websites === true);
  const queryClient = useQueryClient();
  let confirmOff = $state(false);

  const save = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api<{ websites: boolean }>("/organization/modules/websites", { method: "PUT", body: { enabled } }),
    onSuccess: async (_: unknown, enabled: boolean) => {
      confirmOff = false;
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      await refreshMe(queryClient);
      toast.success(enabled ? t("settings.moduleWebsitesOn") : t("settings.moduleWebsitesOffDone"));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<Card>
  <CardHeader title={t("settings.modulesTitle")} description={t("settings.modulesDescription")} />
  <div class="grid gap-3 px-5 pb-5">
    {#if !canEdit}<Alert tone="info">{t("settings.modulesViewerHint")}</Alert>{/if}
    <section class="grid gap-3 rounded-lg border p-4" aria-labelledby="module-websites" data-testid="module-websites">
      <div class="flex flex-wrap items-center gap-2">
        <h3 id="module-websites" class="font-medium">{t("settings.moduleWebsitesTitle")}</h3>
        <Badge tone={websites ? "info" : "neutral"}>{websites ? t("settings.moduleOn") : t("settings.moduleOff")}</Badge>
      </div>
      <p class="text-sm text-muted-foreground">{t("settings.moduleWebsitesText")}</p>
      {#if !websites}<p class="text-sm text-muted-foreground">{t("settings.moduleWebsitesOffNote")}</p>{/if}
      {#if canEdit}
        <div class="flex flex-wrap gap-2">
          {#if websites}
            <a
              href="/websites"
              class="inline-flex h-10 items-center justify-center rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
            >
              {t("settings.moduleOpen")}
            </a>
            <Button variant="outline" disabled={save.isPending} onclick={() => (confirmOff = true)}>
              {t("settings.moduleSwitchOff")}
            </Button>
          {:else}
            <Button disabled={save.isPending} onclick={() => save.mutate(true)}>{t("settings.moduleSwitchOn")}</Button>
          {/if}
        </div>
      {/if}
    </section>
  </div>
</Card>

{#if websites}<CertificateTransparency {me} />{/if}

<ConfirmDialog
  open={confirmOff}
  title={t("settings.moduleWebsitesOffTitle")}
  description={t("settings.moduleWebsitesOffText")}
  confirmLabel={t("settings.moduleSwitchOff")}
  pending={save.isPending}
  onConfirm={() => save.mutate(false)}
  onClose={() => (confirmOff = false)}
/>
