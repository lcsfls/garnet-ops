<script lang="ts">
  import { X } from "@lucide/svelte";
  import type { Snippet } from "svelte";
  import { t } from "../../i18n.svelte.ts";

  /**
   * A panel that slides in from the right edge, on the native <dialog> element: focus is trapped, Escape closes it and
   * the page behind is inert, like Dialog.
   */
  let {
    open,
    onClose,
    title,
    children,
  }: { open: boolean; onClose: () => void; title: string; children: Snippet } = $props();

  let dialog: HTMLDialogElement | undefined = $state();
  const titleId = $props.id();

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  });
</script>

<dialog
  bind:this={dialog}
  onclose={onClose}
  aria-labelledby={titleId}
  class="fixed inset-y-0 right-0 left-auto m-0 h-dvh max-h-dvh w-[min(36rem,100vw)] max-w-none overflow-hidden border-l bg-background p-0 text-foreground shadow-[0_0_40px_oklch(0_0_0/25%)] backdrop:bg-[oklch(0.12_0.02_15/50%)]"
>
  {#if open}
    <div class="flex h-full min-h-0 flex-col">
      <div class="flex items-center gap-3 border-b bg-card px-5 py-3">
        <h2 id={titleId} class="min-w-0 flex-1 font-semibold">{title}</h2>
        <button
          type="button"
          onclick={onClose}
          aria-label={t("common.close")}
          class="grid size-8 place-items-center rounded-md hover:bg-accent"
        >
          <X aria-hidden="true" class="size-4" />
        </button>
      </div>
      <div class="min-h-0 flex-1 p-4">{@render children()}</div>
    </div>
  {/if}
</dialog>
