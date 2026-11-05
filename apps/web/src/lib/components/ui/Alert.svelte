<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import { TONE_CLASSES } from "../../severity-meta.ts";
  import StateIcon from "./StateIcon.svelte";

  /**
   * An inline message. Errors are announced to screen readers and take the critical tokens; information is polite and
   * steel blue. Fixed token colours (severity-meta.ts), no alpha mixes.
   */
  let { tone, children }: { tone: "error" | "info"; children: Snippet } = $props();
  const look = $derived(tone === "error" ? TONE_CLASSES.critical : TONE_CLASSES.info);
</script>

<div
  role={tone === "error" ? "alert" : "status"}
  class={cn("flex gap-2.5 rounded-md border px-3 py-2.5 text-sm text-foreground", look.callout)}
>
  <StateIcon name={tone === "error" ? "circle-alert" : "info"} class={cn("mt-0.5 size-4 flex-none", look.text)} />
  <div>{@render children()}</div>
</div>
