<script lang="ts">
  import { PowerOff } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../api.ts";
  import { t } from "../i18n.svelte.ts";
  import { toast } from "../toast.svelte.ts";
  import { refreshMe } from "./account/refresh-me.ts";
  import Card from "./Card.svelte";
  import Button from "./ui/Button.svelte";

  /**
   * What a page of a module shows while the module is off (ADR 0033): what the module does, and for owners and admins
   * the switch itself, so the feature can be found and started where it lives.
   */
  let { module, canSwitch }: { module: "websites" | "hosts"; canSwitch: boolean } = $props();

  const key = $derived(module === "websites" ? "Websites" : "Hosts");
  const queryClient = useQueryClient();
  const switchOn = createMutation(() => ({
    mutationFn: () => api(`/organization/modules/${module}`, { method: "PUT", body: { enabled: true } }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: [module] });
      await refreshMe(queryClient);
      toast.success(t(`settings.module${key}On`));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<Card>
  <div class="grid gap-2 px-5 py-6" data-testid="{module}-module-off">
    <h2 class="flex items-center gap-2 font-medium">
      <PowerOff aria-hidden="true" class="size-4 text-muted-foreground" />{t(`${module}.moduleOffTitle`)}
    </h2>
    <p class="text-muted-foreground">{t(`settings.module${key}Text`)}</p>
    <p class="text-muted-foreground">{t(`${module}.moduleOffText`)}</p>
    {#if canSwitch}
      <Button class="mt-2 w-fit" disabled={switchOn.isPending} onclick={() => switchOn.mutate()}>
        {t("settings.moduleSwitchOn")}
      </Button>
    {/if}
  </div>
</Card>
