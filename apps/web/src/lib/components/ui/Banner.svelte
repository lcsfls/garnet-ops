<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import { type IconName, TONE_CLASSES, type TokenTone } from "../../severity-meta.ts";
  import StateIcon from "./StateIcon.svelte";

  type BannerTone = Exclude<TokenTone, "low"> | "neutral";
  /**
   * A page-level notice that needs attention (mockup .alert): title, one sentence, one action. It takes the tone of what it
   * talks about (severity-meta.ts), with that tone's icon, so the tone never depends on colour alone; no side bar.
   * Neutral is for a plain fact that needs no action and proves nothing (green is for proof).
   */
  let {
    title,
    tone = "medium",
    children,
    action,
    class: className,
  }: { title: string; tone?: BannerTone; children?: Snippet; action?: Snippet; class?: string } = $props();
  const ICON: Record<BannerTone, IconName> = {
    critical: "flame",
    high: "triangle-alert",
    medium: "triangle-alert",
    info: "info",
    success: "circle-check",
    neutral: "info",
  };
</script>

<div
  role="status"
  data-tone={tone}
  class={cn(
    "mb-5 flex flex-wrap items-center gap-3.5 rounded-xl border px-[18px] py-3.5",
    TONE_CLASSES[tone].callout,
    className,
  )}
>
  <StateIcon name={ICON[tone]} class={cn("size-[18px] flex-none", TONE_CLASSES[tone].text)} />
  <div class="min-w-0 flex-[1_1_20rem]">
    <b class="block font-semibold">{title}</b>
    {#if children}<span class="text-muted-foreground">{@render children()}</span>{/if}
  </div>
  {#if action}<div class="ml-auto">{@render action()}</div>{/if}
</div>
