<script lang="ts">
  import { CircleAlert, Info } from "@lucide/svelte";
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";

  /** An inline message. Errors are announced to screen readers; information is polite. */
  let { tone, children }: { tone: "error" | "info"; children: Snippet } = $props();
  const Icon = $derived(tone === "error" ? CircleAlert : Info);
</script>

<div
  role={tone === "error" ? "alert" : "status"}
  class={cn(
    "flex gap-2.5 rounded-md border px-3 py-2.5 text-sm",
    tone === "error" ? "border-destructive/40 text-destructive-text" : "border-info/40 text-info-text",
  )}
>
  <Icon aria-hidden="true" class="mt-0.5 size-4 flex-none" />
  <div>{@render children()}</div>
</div>
