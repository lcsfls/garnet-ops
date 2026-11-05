<script lang="ts" module>
  import { cn } from "../../cn.ts";

  /**
   * Button looks (AGENTS.md rule 6). A page has exactly one primary action; every other action is secondary, ghost (quiet
   * actions in a toolbar or a row, never a consequential one), destructive (removes or revokes something) or link. A
   * dialog is a surface of its own and may have its own primary action.
   */
  export const BUTTON_VARIANTS = {
    /** The one primary action of a page or dialog: the only burgundy besides the logo. */
    primary: "bg-primary text-primary-foreground shadow-xs hover:bg-primary-hover",
    /** Every other action: a bordered button on the card surface. The default. */
    secondary: "border border-input bg-card shadow-xs hover:bg-accent",
    /** A quiet action that changes nothing lasting (close, hide, show more). Never for remove, revoke or accept. */
    ghost: "hover:bg-accent",
    /** Removes, revokes or declines something; vermilion text on the card surface keeps the contrast in both themes. */
    destructive: "border border-critical-border bg-card text-critical shadow-xs hover:bg-critical-bg",
    /** A neutral link that looks like the other links (.link in app.css): text colour, underlined. */
    link: "link h-auto px-0",
  } as const;
  export type ButtonVariant = keyof typeof BUTTON_VARIANTS;

  /** The classes of a button, for an element that has to stay an anchor (ButtonLink) or a native control. */
  export function buttonClass(variant: ButtonVariant = "secondary", extra?: string): string {
    return cn(
      "inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-base font-medium whitespace-nowrap transition-colors",
      "disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50",
      BUTTON_VARIANTS[variant],
      extra,
    );
  }
</script>

<script lang="ts">
  import type { HTMLButtonAttributes } from "svelte/elements";

  let {
    variant = "secondary",
    class: className,
    type = "button",
    children,
    ref = $bindable(null),
    ...rest
  }: HTMLButtonAttributes & { variant?: ButtonVariant; ref?: HTMLButtonElement | null } = $props();
</script>

<button bind:this={ref} {type} class={buttonClass(variant, className as string)} {...rest}>
  {@render children?.()}
</button>
