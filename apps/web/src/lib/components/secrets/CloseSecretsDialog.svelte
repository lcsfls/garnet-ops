<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";

  /**
   * Closing one secret or several (ADR 0049) as revoked or "not a secret", with a reason that goes into the audit log. Common
   * reasons are one click away; they fill the field, which stays editable.
   */
  let {
    action,
    count = 1,
    pending = false,
    error = null,
    onSubmit,
    onClose,
  }: {
    action: "revoke" | "dismiss" | null;
    /** More than one: the title says how many. */
    count?: number;
    pending?: boolean;
    error?: string | null;
    onSubmit: (reason: string) => void;
    onClose: () => void;
  } = $props();
  let reason = $state("");
  const id = $props.id();

  $effect(() => {
    if (action) reason = "";
  });

  const PRESETS = {
    revoke: ["rotated", "gone"],
    dismiss: ["test", "example", "public"],
  } as const;

  const title = $derived(
    action === "dismiss"
      ? count > 1
        ? t("secrets.bulk.dismissTitle", { count })
        : t("secrets.dismissTitle")
      : count > 1
        ? t("secrets.bulk.revokeTitle", { count })
        : t("secrets.revokeTitle"),
  );

  function submit(event: SubmitEvent) {
    event.preventDefault();
    onSubmit(reason.trim());
  }
</script>

<Dialog
  open={action !== null}
  {onClose}
  {title}
  description={action === "dismiss" ? t("secrets.dismissDescription") : t("secrets.revokeDescription")}
>
  <form class="grid gap-4" onsubmit={submit}>
    <div class="grid gap-1.5">
      <label for="{id}-reason" class="text-sm font-medium">{t("secrets.reason")}</label>
      {#if action}
        <div class="flex flex-wrap gap-1.5" role="group" aria-label={t("secrets.presetsLabel")}>
          {#each PRESETS[action] as preset (preset)}
            <button
              type="button"
              class="rounded-md border border-control px-2 py-1 text-sm hover:bg-[var(--hover-bg)]"
              onclick={() => (reason = t(`secrets.presets.${preset}`))}
            >
              {t(`secrets.presets.${preset}`)}
            </button>
          {/each}
        </div>
      {/if}
      <textarea
        id="{id}-reason"
        name="reason"
        bind:value={reason}
        required
        minlength={10}
        maxlength={1000}
        rows={3}
        aria-describedby="{id}-hint"
        class="rounded-md border border-control bg-card px-3 py-2 text-base shadow-xs"
      ></textarea>
      <p id="{id}-hint" class="text-sm text-muted-foreground">{error ?? t("secrets.reasonHint")}</p>
    </div>
    <DialogFooter>
      <Button variant="secondary" onclick={onClose}>{t("common.cancel")}</Button>
      <Button variant="primary" type="submit" disabled={pending}>
        {action === "dismiss" ? t("secrets.dismiss") : t("secrets.revoke")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
