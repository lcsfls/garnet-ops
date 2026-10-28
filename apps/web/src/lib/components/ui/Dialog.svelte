<script lang="ts">
  import { X } from "@lucide/svelte";
  import type { Snippet } from "svelte";
  import { t } from "../../i18n.svelte.ts";

  /**
   * Modal dialog on the native <dialog> element: focus trapping, Escape and the inert background come from the
   * browser.
   */
  let {
    open,
    onClose,
    title,
    description,
    children,
  }: { open: boolean; onClose: () => void; title: string; description?: string; children: Snippet } =
    $props();

  let dialog: HTMLDialogElement | undefined = $state();
  // Several dialogs can be mounted at once (e.g. one per table row), so ids must be unique.
  const titleId = $props.id();
  const descriptionId = `${titleId}-description`;

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
  aria-describedby={description ? descriptionId : undefined}
  class="m-auto max-h-[calc(100vh-3rem)] w-[min(40rem,calc(100vw-3rem))] overflow-y-auto rounded-[14px] border bg-card px-[22px] pt-5 pb-[18px] text-card-foreground shadow-[0_20px_50px_oklch(0_0_0/30%)] backdrop:bg-[oklch(0.12_0.02_15/60%)]"
>
  {#if open}
    <div class="mb-[18px] flex items-start gap-3">
      <div class="flex-1">
        <h2 id={titleId} class="text-lg font-semibold">{title}</h2>
        {#if description}
          <p id={descriptionId} class="mt-0.5 text-sm text-muted-foreground">{description}</p>
        {/if}
      </div>
      <button
        type="button"
        onclick={onClose}
        aria-label={t("common.close")}
        class="grid size-8 place-items-center rounded-md hover:bg-accent"
      >
        <X aria-hidden="true" class="size-4" />
      </button>
    </div>
    {@render children()}
  {/if}
</dialog>
