<script lang="ts">
  import type { Snippet } from "svelte";
  import { t } from "../../i18n.svelte.ts";
  import Alert from "./Alert.svelte";
  import Button from "./Button.svelte";
  import Dialog from "./Dialog.svelte";
  import DialogFooter from "./DialogFooter.svelte";

  /**
   * Asks before an action that cannot be undone, in the app's own dialog rather than the browser's unstyled
   * `confirm()`. The dialog's close button gets the focus first, so pressing Enter by accident does nothing harmful.
   */
  let {
    open,
    title,
    description,
    confirmLabel,
    pending = false,
    error = null,
    onConfirm,
    onClose,
    children,
  }: {
    open: boolean;
    title: string;
    description: string;
    confirmLabel: string;
    pending?: boolean;
    /** Shown when the action failed; the dialog stays open so the user can retry or cancel. */
    error?: string | null;
    onConfirm: () => void;
    onClose: () => void;
    /** A choice that goes with the action, such as "also remove …". */
    children?: Snippet;
  } = $props();
</script>

<Dialog {open} {onClose} {title} {description}>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {@render children?.()}
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
      <Button variant="destructive" disabled={pending} onclick={onConfirm}>
        {pending ? t("common.loading") : confirmLabel}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
