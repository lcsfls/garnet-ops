<script lang="ts" module>
  import type { LucideIcon } from "@lucide/svelte";

  export interface MenuAction {
    label: string;
    icon: LucideIcon;
    onSelect: () => void;
    disabled?: boolean;
    destructive?: boolean;
  }
</script>

<script lang="ts">
  import { Ellipsis } from "@lucide/svelte";
  import { tick } from "svelte";
  import { cn } from "../../cn.ts";

  /**
   * The "…" button of a table row (mockup) with the row's less frequent actions. A WAI-ARIA menu button: arrow keys move
   * between items, Escape and a click outside close it and return focus to the button.
   */
  let { label, actions }: { label: string; actions: MenuAction[] } = $props();

  let open = $state(false);
  const menuId = $props.id();
  let root: HTMLDivElement | undefined = $state();
  let button: HTMLButtonElement | undefined = $state();
  const items: (HTMLButtonElement | null)[] = $state([]);

  $effect(() => {
    if (!open) return;
    void tick().then(() => items.find((item) => item && !item.disabled)?.focus());
    const onPointer = (event: PointerEvent) => {
      if (!root?.contains(event.target as Node)) open = false;
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  });

  function close() {
    open = false;
    button?.focus();
  }

  function onKeyDown(event: KeyboardEvent) {
    const enabled = items.filter((item): item is HTMLButtonElement => Boolean(item && !item.disabled));
    const index = enabled.indexOf(document.activeElement as HTMLButtonElement);
    if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      close();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      enabled[(index + step + enabled.length) % enabled.length]?.focus();
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      (event.key === "Home" ? enabled[0] : enabled[enabled.length - 1])?.focus();
    }
  }
</script>

{#if actions.length > 0}
  <div bind:this={root} class="relative inline-block">
    <button
      bind:this={button}
      type="button"
      aria-label={label}
      title={label}
      aria-haspopup="menu"
      aria-expanded={open}
      aria-controls={open ? menuId : undefined}
      onclick={() => (open = !open)}
      class="grid size-9 place-items-center rounded-md hover:bg-accent"
    >
      <Ellipsis aria-hidden="true" class="size-4" />
    </button>
    {#if open}
      <div
        id={menuId}
        role="menu"
        tabindex="-1"
        aria-label={label}
        onkeydown={onKeyDown}
        class="absolute top-full right-0 z-30 mt-1 grid min-w-48 rounded-lg border bg-card p-1 text-card-foreground shadow-xs"
      >
        {#each actions as action, i (action.label)}
          <button
            bind:this={items[i]}
            type="button"
            role="menuitem"
            tabindex="-1"
            disabled={action.disabled}
            onclick={() => {
              open = false;
              action.onSelect();
            }}
            class={cn(
              "flex h-9 items-center gap-2.5 rounded-md px-2.5 text-left whitespace-nowrap hover:bg-accent focus-visible:bg-accent disabled:opacity-50",
              action.destructive && "text-destructive-text",
            )}
          >
            <action.icon aria-hidden="true" class="size-4" />
            {action.label}
          </button>
        {/each}
      </div>
    {/if}
  </div>
{/if}
