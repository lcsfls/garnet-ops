<script lang="ts">
  import { safeAppLink } from "@garnetops/core/user-notifications";
  import { CircleAlert, CircleCheck, Info, X } from "@lucide/svelte";
  import { goto } from "$app/navigation";
  import { cn } from "../cn.ts";
  import { t } from "../i18n.svelte.ts";
  import { toast as store } from "../toast.svelte.ts";
  import type { Toast, ToastKind } from "../toast-queue.ts";

  const ICON = { success: CircleCheck, error: CircleAlert, info: Info } as const;
  /**
   * Kind is carried by an icon and a word for screen readers, never by colour alone. Success is neutral: green means
   * proof only (AGENTS.md rule 6), and a saved setting proves nothing.
   */
  const TONE: Record<ToastKind, string> = {
    success: "border-border",
    error: "border-destructive/50",
    info: "border-info/50",
  };
  const ICON_TONE: Record<ToastKind, string> = {
    success: "text-foreground",
    error: "text-destructive-text",
    info: "text-info-text",
  };

  /**
   * One message. It closes by itself after its time (errors never do); hovering it or moving focus into it pauses the
   * timer, and leaving continues with the time that was left.
   */
  let { toast }: { toast: Toast } = $props();
  let paused = $state(false);
  // svelte-ignore state_referenced_locally
  let left: number | null = toast.durationMs;
  // svelte-ignore state_referenced_locally
  let revision = toast.revision;
  let started = 0;
  const Icon = $derived(ICON[toast.kind]);
  let item: HTMLDivElement | undefined = $state();

  // Hovering or focusing the message pauses its timer. Listeners instead of attributes: the item is a live region, not
  // an interactive element, and focus events bubble as focusin/focusout.
  $effect(() => {
    const node = item;
    if (!node) return;
    const pause = () => (paused = true);
    const resume = () => (paused = false);
    const leaveFocus = (event: FocusEvent) => {
      if (!node.contains(event.relatedTarget as Node | null)) paused = false;
    };
    node.addEventListener("mouseenter", pause);
    node.addEventListener("mouseleave", resume);
    node.addEventListener("focusin", pause);
    node.addEventListener("focusout", leaveFocus);
    return () => {
      node.removeEventListener("mouseenter", pause);
      node.removeEventListener("mouseleave", resume);
      node.removeEventListener("focusin", pause);
      node.removeEventListener("focusout", leaveFocus);
    };
  });

  $effect(() => {
    // A repeat of the message (a new revision) gives it its full time again.
    if (revision !== toast.revision) {
      revision = toast.revision;
      left = toast.durationMs;
    }
    if (paused || left === null) return;
    started = Date.now();
    const id = toast.id;
    const timer = setTimeout(() => store.dismiss(id), left);
    return () => {
      clearTimeout(timer);
      // Pausing keeps what is left of the time.
      if (left !== null) left = Math.max(0, left - (Date.now() - started));
    };
  });

  const href = $derived(toast.action ? safeAppLink(toast.action.href) : null);
</script>

<div
  bind:this={item}
  data-toast={toast.kind}
  role={toast.kind === "error" ? "alert" : "status"}
  aria-live={toast.kind === "error" ? "assertive" : "polite"}
  class={cn(
    "toast-in pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-card p-3 text-sm text-card-foreground shadow-xs",
    TONE[toast.kind],
  )}
>
  <Icon aria-hidden="true" class={cn("mt-0.5 size-4 flex-none", ICON_TONE[toast.kind])} />
  <div class="min-w-0 flex-1">
    <span class="sr-only">{t(`toast.${toast.kind}`)}: </span>
    <span class="break-words">{toast.message}</span>
    {#if toast.action && href}
      <a
        {href}
        onclick={(event) => {
          if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
          event.preventDefault();
          void goto(href);
          store.dismiss(toast.id);
        }}
        class="mt-1 block w-fit font-medium text-primary-text underline underline-offset-4"
      >
        {toast.action.label}
      </a>
    {/if}
  </div>
  <button
    type="button"
    data-toast-close
    aria-label={t("toast.close")}
    onclick={() => store.dismiss(toast.id)}
    class="-m-1 grid size-7 flex-none place-items-center rounded-md hover:bg-accent"
  >
    <X aria-hidden="true" class="size-4" />
  </button>
</div>
