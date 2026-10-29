<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import { refreshMe } from "../../account/refresh-me.ts";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import ConfirmDialog from "../../ui/ConfirmDialog.svelte";

  /** One module (ADR 0033): what it does, whether it is on, and the switch for owners and admins. */
  let {
    module,
    on,
    canEdit,
    openHref,
  }: { module: "websites" | "hosts"; on: boolean; canEdit: boolean; openHref: string } = $props();

  const key = $derived(module === "websites" ? "Websites" : "Hosts");
  const queryClient = useQueryClient();
  let confirmOff = $state(false);

  const save = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api(`/organization/modules/${module}`, { method: "PUT", body: { enabled } }),
    onSuccess: async (_: unknown, enabled: boolean) => {
      confirmOff = false;
      await queryClient.invalidateQueries({ queryKey: [module] });
      await refreshMe(queryClient);
      toast.success(enabled ? t(`settings.module${key}On`) : t(`settings.module${key}OffDone`));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<section class="grid gap-3 rounded-lg border p-4" aria-labelledby="module-{module}" data-testid="module-{module}">
  <div class="flex flex-wrap items-center gap-2">
    <h3 id="module-{module}" class="font-medium">{t(`settings.module${key}Title`)}</h3>
    <Badge tone={on ? "info" : "neutral"}>{on ? t("settings.moduleOn") : t("settings.moduleOff")}</Badge>
  </div>
  <p class="text-sm text-muted-foreground">{t(`settings.module${key}Text`)}</p>
  {#if !on}<p class="text-sm text-muted-foreground">{t(`settings.module${key}OffNote`)}</p>{/if}
  {#if canEdit}
    <div class="flex flex-wrap gap-2">
      {#if on}
        <a
          href={openHref}
          class="inline-flex h-10 items-center justify-center rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
        >
          {module === "websites" ? t("settings.moduleOpen") : t("settings.moduleHostsOpen")}
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

<ConfirmDialog
  open={confirmOff}
  title={t(`settings.module${key}OffTitle`)}
  description={t(`settings.module${key}OffText`)}
  confirmLabel={t("settings.moduleSwitchOff")}
  pending={save.isPending}
  onConfirm={() => save.mutate(false)}
  onClose={() => (confirmOff = false)}
/>
