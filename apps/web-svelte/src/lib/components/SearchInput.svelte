<script lang="ts">
  import { Search } from "@lucide/svelte";
  import { cn } from "../cn.ts";

  /** Text filter that writes to the URL after a short pause, not on every keystroke. */
  let {
    label,
    value,
    onChange,
    class: className,
  }: { label: string; value: string; onChange: (value: string) => void; class?: string } = $props();

  // svelte-ignore state_referenced_locally
  let draft = $state(value);
  // A new value from outside (back button, a link) replaces the draft.
  $effect.pre(() => {
    draft = value;
  });
  $effect(() => {
    const next = draft.trim();
    if (next === value) return;
    const timer = setTimeout(() => onChange(next), 300);
    return () => clearTimeout(timer);
  });
</script>

<div class={cn("relative w-full max-w-[280px]", className)}>
  <Search
    aria-hidden="true"
    class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
  />
  <input
    type="search"
    aria-label={label}
    placeholder={label}
    bind:value={draft}
    class="h-10 w-full rounded-lg border border-input bg-card pr-3 pl-8 text-base shadow-xs placeholder:text-muted-foreground"
  />
</div>
