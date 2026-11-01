<script lang="ts">
  import { Webhook } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import CopyRow from "../websites/CopyRow.svelte";

  /**
   * Scan on push (ADR 0045): the forge calls GarnetOps when someone pushes, and a push to the scanned branch starts a scan.
   * Owners and admins, or the owner of a private repository, switch it on with a recent sign-in; address and secret are shown
   * once, to be entered in the forge. The last deliveries say what happened, so the setup can be checked from here.
   */
  let { repositoryId, me }: { repositoryId: string; me: Me } = $props();

  type Delivery = { at: string; event: string; result: string };
  type View = {
    enabled: boolean;
    canManage: boolean;
    url: string | null;
    createdAt: string | null;
    lastDeliveryAt: string | null;
    deliveries: Delivery[];
  };

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const key = $derived(["repository", repositoryId, "webhook"]);
  const view = createQuery(() => ({
    queryKey: key,
    queryFn: () => api<View>(`/repositories/${repositoryId}/webhook`),
    refetchInterval: 30_000,
  }));
  const data = $derived(view.data);
  let created = $state<{ url: string; secret: string } | null>(null);
  let turningOff = $state(false);

  const create = createMutation(() => ({
    mutationFn: () =>
      api<{ url: string; secret: string }>(`/repositories/${repositoryId}/webhook`, { method: "POST" }),
    onSuccess: async (result: { url: string; secret: string }) => {
      created = result;
      await queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (e: Error) => void stepUp.handled(e, () => create.mutate()),
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repositoryId}/webhook`, { method: "DELETE" }),
    onSuccess: async () => {
      turningOff = false;
      await queryClient.invalidateQueries({ queryKey: key });
    },
  }));

  const resultText = (code: string) => {
    const k = `repository.webhook.result.${code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase())}`;
    return hasKey(k) ? t(k as MessageKey) : code;
  };
  /** Only a scan that was queued is news; a refused signature needs a look; the rest is neutral. */
  const tone = (code: string) =>
    code === "bad-signature" ? "critical" : code === "scan-queued" ? "info" : "neutral";
</script>

<Card>
  <CardHeader title={t("repository.webhook.title")} description={t("repository.webhook.description")} />
  <div class="grid gap-3 px-5 pb-5" data-testid="repository-webhook">
    {#if data}
      <div class="flex flex-wrap items-center gap-2">
        <Badge tone={data.enabled ? "info" : "neutral"}>
          <Webhook aria-hidden="true" />
          {data.enabled ? t("repository.webhook.on") : t("repository.webhook.off")}
        </Badge>
        {#if data.lastDeliveryAt}
          <span class="text-sm text-muted-foreground">
            {t("repository.webhook.lastDelivery", { when: formatRelative(data.lastDeliveryAt) })}
          </span>
        {:else if data.enabled}
          <span class="text-sm text-muted-foreground">{t("repository.webhook.noDelivery")}</span>
        {/if}
      </div>
      {#if data.enabled && data.url}
        <CopyRow label={t("repository.webhook.address")} value={data.url} id={`webhook-url-${repositoryId}`} />
      {:else if !data.enabled}
        <p class="text-sm text-muted-foreground">{t("repository.webhook.offHint")}</p>
      {/if}

      {#if data.deliveries.length > 0}
        <table class="w-full text-left text-sm" data-testid="repository-webhook-deliveries">
          <caption class="sr-only">{t("repository.webhook.deliveries")}</caption>
          <thead class="text-muted-foreground">
            <tr>
              <th class="py-1 pr-3 font-medium">{t("repository.webhook.when")}</th>
              <th class="py-1 pr-3 font-medium">{t("repository.webhook.event")}</th>
              <th class="py-1 font-medium">{t("repository.webhook.result.title")}</th>
            </tr>
          </thead>
          <tbody>
            {#each data.deliveries as d, i (`${d.at}-${i}`)}
              <tr class="border-t">
                <td class="py-1 pr-3 whitespace-nowrap">
                  <time datetime={d.at} title={formatDateTime(d.at)}>{formatRelative(d.at)}</time>
                </td>
                <td class="py-1 pr-3 font-mono">{d.event}</td>
                <td class="py-1"><Badge tone={tone(d.result)}>{resultText(d.result)}</Badge></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if create.isError && !stepUp.open}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
      {#if data.canManage}
        <div class="flex flex-wrap gap-2">
          <Button
            variant={data.enabled ? "outline" : "primary"}
            disabled={create.isPending}
            onclick={() => create.mutate()}
          >
            {data.enabled ? t("repository.webhook.replace") : t("repository.webhook.enable")}
          </Button>
          {#if data.enabled}
            <Button variant="outline" onclick={() => (turningOff = true)}>{t("repository.webhook.disable")}</Button>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</Card>

{#if created}
  <Dialog
    open
    onClose={() => (created = null)}
    title={t("repository.webhook.createdTitle")}
    description={t("repository.webhook.createdDescription")}
  >
    <div class="grid gap-4">
      <CopyRow label={t("repository.webhook.address")} value={created.url} id="webhook-created-url" />
      <CopyRow label={t("repository.webhook.secret")} value={created.secret} id="webhook-created-secret" />
      <Alert tone="info">{t("repository.webhook.secretOnce")}</Alert>
      <div class="grid gap-2 text-sm">
        <p class="font-medium">{t("repository.webhook.howTitle")}</p>
        <ul class="grid list-disc gap-1 pl-5">
          <li>{t("repository.webhook.howGithub")}</li>
          <li>{t("repository.webhook.howGitea")}</li>
          <li>{t("repository.webhook.howReach")}</li>
        </ul>
      </div>
      <DialogFooter>
        <Button onclick={() => (created = null)}>{t("repository.webhook.done")}</Button>
      </DialogFooter>
    </div>
  </Dialog>
{/if}
<ConfirmDialog
  open={turningOff}
  title={t("repository.webhook.disableTitle")}
  description={t("repository.webhook.disableDescription")}
  confirmLabel={t("repository.webhook.disable")}
  pending={remove.isPending}
  error={remove.isError ? t("errors.actionFailed") : null}
  onConfirm={() => remove.mutate()}
  onClose={() => (turningOff = false)}
/>
<StepUpPrompt {stepUp} email={me.user.email} />
