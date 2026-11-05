<script lang="ts" module>
  export const BUTTON_VARIANTS = {
    /** The one primary action of a view: the only burgundy besides the logo (AGENTS.md rule 6). */
    primary: "bg-primary text-primary-foreground shadow-xs hover:bg-primary-hover",
    outline: "border border-input bg-card shadow-xs hover:bg-accent",
    ghost: "hover:bg-accent",
    /** Irreversible actions; vermilion text on the card surface keeps the contrast in both themes. */
    destructive: "border border-critical-border bg-card text-critical shadow-xs hover:bg-critical-bg",
    /** A neutral link that looks like the other links (.link in app.css): text colour, underlined. */
    link: "link h-auto px-0",
  } as const;
  export type ButtonVariant = keyof typeof BUTTON_VARIANTS;
</script>

<script lang="ts">
  import type { HTMLButtonAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";

  let {
    variant = "primary",
    class: className,
    type = "button",
    children,
    ref = $bindable(null),
    ...rest
  }: HTMLButtonAttributes & { variant?: ButtonVariant; ref?: HTMLButtonElement | null } = $props();
</script>

<button
  bind:this={ref}
  {type}
  class={cn(
    "inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-base font-medium whitespace-nowrap transition-colors",
    "disabled:pointer-events-none disabled:opacity-50",
    BUTTON_VARIANTS[variant],
    className as string,
  )}
  {...rest}
>
  {@render children?.()}
</button>
