<script lang="ts">
  import { t } from "../i18n.svelte.ts";
  import { toasts } from "../toast.svelte.ts";
  import ToastItem from "./ToastItem.svelte";

  /**
   * The messages for what people just did (ADR 0019), bottom right. Each message is its own live region: errors are
   * announced at once (role alert), everything else politely (role status). Nothing here takes focus; the close buttons
   * and links are reached with Tab, or with Alt+Shift+T, which moves to the first message.
   */
  let root: HTMLElement | undefined = $state();

  $effect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey && event.shiftKey && event.code === "KeyT") {
        event.preventDefault();
        root?.querySelector<HTMLElement>("[data-toast-close]")?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });
</script>

<section
  bind:this={root}
  aria-label={t("toast.region")}
  class="pointer-events-none fixed right-4 bottom-4 z-50 grid w-[min(24rem,calc(100vw-2rem))] gap-2"
>
  {#each toasts().visible as x (x.id)}
    <ToastItem toast={x} />
  {/each}
</section>
