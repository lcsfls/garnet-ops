<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
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
  import Radio from "../../ui/Radio.svelte";
  import Notice from "../../websites/Notice.svelte";

  type Provider = { id: string; name: string; servers: string[]; privacy: string };
  type PublicDns = {
    provider: string | null;
    enabledAt: string | null;
    enabledBy: string | null;
    providers: Provider[];
  };

  /**
   * The public DNS resolver next to the local one, for lookups of public names only (website checks, the proof of control,
   * registry checks, Certificate Transparency). Off by default: the names looked up go to the provider, so choosing one needs an
   * owner or admin, an acknowledgement and a recent sign-in.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let choice = $state<string | null | undefined>(undefined);
  let acknowledged = $state(false);
  let error = $state<string | null>(null);

  const query = createQuery(() => ({
    queryKey: ["organization", "dns"],
    queryFn: () => api<PublicDns>("/organization/dns"),
  }));
  const current = $derived(query.data?.provider ?? null);
  const selected = $derived(choice === undefined ? current : choice);
  const selectedProvider = $derived(query.data?.providers.find((p) => p.id === selected) ?? null);
  const currentProvider = $derived(query.data?.providers.find((p) => p.id === current) ?? null);
  const changed = $derived(selected !== current);

  const save = createMutation(() => ({
    mutationFn: () =>
      api<PublicDns>("/organization/dns", {
        method: "PUT",
        body: { provider: selected, acknowledged: selected ? acknowledged : undefined },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async (saved: PublicDns) => {
      queryClient.setQueryData(["organization", "dns"], saved);
      choice = undefined;
      acknowledged = false;
      toast.success(saved.provider ? t("settings.publicDnsOn") : t("settings.publicDnsOffDone"));
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      error =
        e instanceof ApiError && e.status === 422
          ? t("websites.ctNeedsAcknowledgement")
          : t("errors.actionFailed");
    },
  }));
</script>

<Card>
  <CardHeader title={t("settings.publicDnsTitle")} description={t("settings.publicDnsDescription")} />
  <div class="grid gap-3 px-5 pb-5" data-testid="public-dns">
    <QueryStatus {query} />
    {#if query.data}
      <div class="flex flex-wrap items-center gap-2">
        <Badge tone={currentProvider ? "info" : "neutral"}>
          {currentProvider ? currentProvider.name : t("settings.publicDnsOff")}
        </Badge>
        {#if currentProvider && query.data.enabledAt}
          <span class="text-sm text-muted-foreground">
            {t("settings.publicDnsEnabledBy", {
              name: query.data.enabledBy ?? "–",
              when: formatDateTime(query.data.enabledAt),
            })}
          </span>
        {/if}
      </div>
      <fieldset class="grid gap-2" disabled={!canEdit || save.isPending}>
        <legend class="sr-only">{t("settings.publicDnsTitle")}</legend>
        <label class="flex items-start gap-2.5 rounded-md border p-3">
          <Radio class="mt-1" name="public-dns" checked={selected === null} onchange={() => (choice = null)} />
          <span class="grid gap-0.5">
            <span class="font-medium">{t("settings.publicDnsOff")}</span>
            <span class="text-sm text-muted-foreground">{t("settings.publicDnsOffText")}</span>
          </span>
        </label>
        {#each query.data.providers as provider (provider.id)}
          <label class="flex items-start gap-2.5 rounded-md border p-3">
            <Radio
              class="mt-1"
              name="public-dns"
              checked={selected === provider.id}
              onchange={() => (choice = provider.id)}
            />
            <span class="grid gap-0.5">
              <span class="font-medium">{provider.name}</span>
              <span class="text-sm text-muted-foreground">{provider.servers.join(", ")}</span>
            </span>
          </label>
        {/each}
      </fieldset>
      {#if canEdit && changed}
        {#if selectedProvider}
          <Notice title={t("settings.publicDnsLeavesTitle")}>
            {t("settings.publicDnsLeavesText", {
              provider: selectedProvider.name,
              servers: selectedProvider.servers.join(", "),
            })}
            <a class="text-primary-text hover:underline" href={selectedProvider.privacy} rel="noreferrer noopener" target="_blank">
              {t("settings.publicDnsPrivacy")}
            </a>
          </Notice>
          <label class="flex items-start gap-2.5 rounded-md border p-3">
            <Checkbox class="mt-1" bind:checked={acknowledged} />
            <span>{t("settings.publicDnsAcknowledge", { provider: selectedProvider.name })}</span>
          </label>
        {/if}
        {#if error}<Alert tone="error">{error}</Alert>{/if}
        <div class="flex gap-2">
          <Button disabled={save.isPending || (selectedProvider !== null && !acknowledged)} onclick={() => save.mutate()}>
            {save.isPending ? t("common.loading") : t("settings.save")}
          </Button>
          <Button variant="outline" onclick={() => (choice = undefined)}>{t("common.cancel")}</Button>
        </div>
      {/if}
    {/if}
  </div>
</Card>
<StepUpPrompt {stepUp} email={me.user.email} />
