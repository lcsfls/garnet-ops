<script lang="ts">
  import type { HTMLAnchorAttributes } from "svelte/elements";
  import { type ButtonVariant, buttonClass } from "./Button.svelte";

  /**
   * A link that looks like a button: for an action that leads to another page or downloads a file. It counts towards the
   * one primary action of a page like a Button does (AGENTS.md rule 6).
   */
  let {
    variant = "secondary",
    class: className,
    children,
    ...rest
  }: HTMLAnchorAttributes & { variant?: ButtonVariant } = $props();
</script>

<a class={buttonClass(variant, className as string)} {...rest}>
  {@render children?.()}
</a>
