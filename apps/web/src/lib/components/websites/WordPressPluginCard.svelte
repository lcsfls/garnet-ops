<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import CopyRow from "./CopyRow.svelte";

  /**
   * The GarnetOps WordPress plugin (ADR 0042, part 4): GarnetOps reads the exact WordPress, PHP, plugin and theme versions from it
   * at the daily look. Connecting creates a token that is shown once; the plugin on the site keeps only its fingerprint.
   */
  let {
    detail,
    canEdit,
    email,
    class: className = "",
  }: { detail: ExposureDetail; canEdit: boolean; email: string; class?: string } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let token = $state<string | null>(null);

  const read = $derived(detail.passive?.wordpressPlugin ?? null);
  const verified = $derived(detail.verification.effective);
  const errorText = (code: string) =>
    hasKey(`websites.wpPlugin.error.${code}`) ? t(`websites.wpPlugin.error.${code}` as MessageKey) : code;

  const connect = createMutation(() => ({
    mutationFn: () => api<{ token: string }>(`/exposure/${detail.id}/wordpress-plugin`, { method: "POST" }),
    onSuccess: async (result: { token: string }) => {
      token = result.token;
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => connect.mutate())) return;
      toast.error(t("errors.actionFailed"));
    },
  }));
  const disconnect = createMutation(() => ({
    mutationFn: () => api(`/exposure/${detail.id}/wordpress-plugin`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.wpPlugin.disconnected"));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

{#if detail.kind === "domain"}
  <Card class={className}>
    <CardHeader title={t("websites.wpPlugin.title")} description={t("websites.wpPlugin.description")}>
      {#snippet actions()}
        {#if detail.wordpressPlugin.connected}
          <Badge tone={read && !read.error ? "info" : "neutral"}>{t("websites.wpPlugin.connected")}</Badge>
        {/if}
      {/snippet}
    </CardHeader>
    <div class="grid gap-3 px-5 pb-5" data-testid="websites-wordpress-plugin">
      {#if detail.wordpressPlugin.connected}
        <p class="text-sm text-muted-foreground">
          {t("websites.wpPlugin.connectedAt", {
            when: detail.wordpressPlugin.connectedAt ? formatDateTime(detail.wordpressPlugin.connectedAt) : "–",
          })}
        </p>
        {#if !read}
          <p class="text-sm">{t("websites.wpPlugin.waiting")}</p>
        {:else if read.error}
          <Alert tone="error">{errorText(read.error)}</Alert>
        {:else}
          <p class="text-sm">
            {t("websites.wpPlugin.read", {
              when: detail.passive?.takenAt ? formatDateTime(detail.passive.takenAt) : "–",
              version: read.pluginVersion ?? "–",
            })}
          </p>
        {/if}
      {:else if !verified}
        <p class="text-sm text-muted-foreground">{t("websites.wpPlugin.verifyFirst")}</p>
      {/if}
      <a
        href="/api/v1/exposure/wordpress-plugin.zip"
        download
        class="text-sm text-primary-text hover:underline">{t("websites.wpPlugin.download")}</a
      >
      {#if canEdit && verified}
        <div class="flex flex-wrap gap-2">
          <Button
            variant={detail.wordpressPlugin.connected ? "outline" : "primary"}
            disabled={connect.isPending}
            onclick={() => connect.mutate()}
          >
            {detail.wordpressPlugin.connected ? t("websites.wpPlugin.newToken") : t("websites.wpPlugin.connect")}
          </Button>
          {#if detail.wordpressPlugin.connected}
            <Button variant="outline" disabled={disconnect.isPending} onclick={() => disconnect.mutate()}>
              {t("websites.wpPlugin.disconnect")}
            </Button>
          {/if}
        </div>
      {/if}
    </div>
  </Card>
{/if}

{#if token}
  <Dialog
    open
    onClose={() => (token = null)}
    title={t("websites.wpPlugin.tokenTitle")}
    description={t("websites.wpPlugin.tokenDescription")}
  >
    <div class="grid gap-4">
      <ol class="grid list-decimal gap-1 pl-5 text-sm">
        <li>
          <a href="/api/v1/exposure/wordpress-plugin.zip" download class="text-primary-text hover:underline"
            >{t("websites.wpPlugin.stepDownload")}</a
          >
        </li>
        <li>{t("websites.wpPlugin.stepInstall")}</li>
        <li>{t("websites.wpPlugin.stepPaste")}</li>
      </ol>
      <CopyRow label={t("websites.wpPlugin.token")} value={token} id="websites-wordpress-token" />
      <Alert tone="info">{t("websites.wpPlugin.tokenOnce")}</Alert>
      <DialogFooter>
        <Button onclick={() => (token = null)}>{t("websites.wpPlugin.done")}</Button>
      </DialogFooter>
    </div>
  </Dialog>
{/if}
<StepUpPrompt {stepUp} {email} />
