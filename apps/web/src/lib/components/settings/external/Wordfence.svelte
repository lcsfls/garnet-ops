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
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Field from "../../ui/Field.svelte";
  import Notice from "../../websites/Notice.svelte";

  /**
   * Advisories for WordPress, its plugins and themes from the Wordfence Intelligence feed (ADR 0042, part 3), with the
   * organisation's own API key. The key is sealed at once and never shown again; it goes only to Wordfence, once a day.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let asking = $state(false);
  let key = $state("");
  let acknowledged = $state(false);
  let error = $state<string | null>(null);

  const query = createQuery(() => ({
    queryKey: ["websites", "settings"],
    queryFn: () => api<ExposureSettings>("/exposure/settings"),
  }));
  const wf = $derived(query.data?.wordfence);

  const save = createMutation(() => ({
    mutationFn: () => api("/exposure/settings/wordfence", { method: "PUT", body: { key, acknowledged } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      asking = false;
      key = "";
      acknowledged = false;
      toast.success(t("websites.wordfenceSaved"));
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      error =
        e instanceof ApiError && e.status === 422 ? t("websites.wordfenceInvalid") : t("errors.actionFailed");
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api("/exposure/settings/wordfence", { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.wordfenceRemoved"));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const errorText = (code: string) =>
    hasKey(`websites.wordfenceError.${code}`) ? t(`websites.wordfenceError.${code}` as MessageKey) : code;
</script>

{#if wf}
  <Card>
    <CardHeader title={t("websites.wordfenceTitle")} description={t("websites.wordfenceText")}>
      {#snippet actions()}
        <Badge tone={wf.configured ? "info" : "neutral"}>
          {wf.configured ? t("websites.wordfenceConfigured") : t("websites.wordfenceNotSet")}
        </Badge>
      {/snippet}
    </CardHeader>
    <div class="grid gap-3 px-5 pb-5" data-testid="wordfence-section">
      <Notice title={t("websites.wordfenceLeavesTitle", { host: wf.host })}>{t("websites.wordfenceLeavesText")}</Notice>
      {#if wf.configured}
        <p class="text-sm text-muted-foreground">
          {t("websites.wordfenceSetBy", { name: wf.setBy ?? "–", when: wf.setAt ? formatDateTime(wf.setAt) : "–" })}
          {wf.syncedAt
            ? t("websites.wordfenceSynced", { when: formatDateTime(wf.syncedAt), count: wf.advisories })
            : t("websites.wordfenceWaiting")}
        </p>
        {#if wf.error}<Alert tone="error">{errorText(wf.error)}</Alert>{/if}
      {/if}
      {#if canEdit}
        <div class="flex flex-wrap gap-2">
          <Button
            variant={wf.configured ? "outline" : "primary"}
            onclick={() => {
              error = null;
              asking = true;
            }}
          >
            {wf.configured ? t("websites.wordfenceReplace") : t("websites.wordfenceSet")}
          </Button>
          {#if wf.configured}
            <Button variant="outline" disabled={remove.isPending} onclick={() => remove.mutate()}>
              {t("websites.wordfenceRemove")}
            </Button>
          {/if}
        </div>
      {/if}
    </div>
  </Card>
{/if}

{#if wf && asking}
  <Dialog open onClose={() => (asking = false)} title={t("websites.wordfenceAskTitle")} description={t("websites.wordfenceText")}>
    <form
      class="grid gap-4"
      onsubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Notice title={t("websites.wordfenceLeavesTitle", { host: wf.host })}>{t("websites.wordfenceLeavesText")}</Notice>
      <Field
        label={t("websites.wordfenceKey")}
        hint={t("websites.wordfenceKeyHint")}
        type="password"
        name="wordfence-key"
        bind:value={key}
        autocomplete="off"
        spellcheck={false}
        required
        maxlength={200}
        class="font-mono"
      />
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>{t("websites.wordfenceAcknowledge", { host: wf.host })}</span>
      </label>
      <DialogFooter>
        <Button type="button" variant="outline" onclick={() => (asking = false)}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={!acknowledged || key.trim().length < 20 || save.isPending}>
          {save.isPending ? t("common.loading") : t("settings.save")}
        </Button>
      </DialogFooter>
    </form>
  </Dialog>
{/if}
<StepUpPrompt {stepUp} email={me.user.email} />
