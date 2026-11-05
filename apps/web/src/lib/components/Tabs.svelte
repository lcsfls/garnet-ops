<script lang="ts" generics="T extends string">
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";
  import type { Severity } from "../types.ts";
  import SeverityIcon from "./ui/SeverityIcon.svelte";

  /**
   * Tabs (WAI-ARIA tabs pattern): one tab stop, arrow keys move between the tabs and open them, Home and End jump to the
   * ends. A tab may carry the worst severity of what it holds (its icon, with the word for screen readers) or a count. The
   * caller renders the panel as `role="tabpanel"` with id `${idPrefix}-panel`, labelled by `${idPrefix}-tab-${value}`.
   */
  let {
    label,
    value,
    tabs,
    onChange,
    idPrefix,
    class: className = "",
  }: {
    label: string;
    value: T;
    tabs: {
      value: T;
      label: string;
      severity?: Severity | null;
      count?: number | null;
      countLabel?: string;
    }[];
    onChange: (value: T) => void;
    idPrefix: string;
    class?: string;
  } = $props();

  const buttons: HTMLButtonElement[] = $state([]);

  /** The spoken name: the label, then the severity or what the count means ("Ports, Critical", "Report, 4 need a look"). */
  function spoken(tab: (typeof tabs)[number]): string {
    const parts = [tab.label];
    if (tab.severity) parts.push(t(`severity.${tab.severity}`));
    if (tab.count) parts.push(tab.countLabel ?? formatNumber(tab.count));
    return parts.join(", ");
  }

  function move(event: KeyboardEvent, index: number) {
    const last = tabs.length - 1;
    const next =
      event.key === "ArrowRight"
        ? index === last
          ? 0
          : index + 1
        : event.key === "ArrowLeft"
          ? index === 0
            ? last
            : index - 1
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? last
              : null;
    if (next === null) return;
    event.preventDefault();
    const target = tabs[next];
    if (!target) return;
    onChange(target.value);
    buttons[next]?.focus();
  }
</script>

<div role="tablist" aria-label={label} class={cn("flex flex-wrap gap-x-1 border-b", className)}>
  {#each tabs as tab, i (tab.value)}
    {@const selected = tab.value === value}
    <button
      bind:this={buttons[i]}
      type="button"
      role="tab"
      id={`${idPrefix}-tab-${tab.value}`}
      aria-selected={selected}
      aria-controls={`${idPrefix}-panel`}
      aria-label={spoken(tab)}
      tabindex={selected ? 0 : -1}
      onclick={() => onChange(tab.value)}
      onkeydown={(e) => move(e, i)}
      class={cn(
        "-mb-px inline-flex h-10 items-center gap-1.5 border-b-2 px-3 text-sm whitespace-nowrap focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ring",
        selected
          ? "border-foreground font-semibold text-foreground"
          : "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
      )}
    >
      {tab.label}
      {#if tab.severity}
        <SeverityIcon severity={tab.severity} colored class="size-4" />
      {/if}
      {#if tab.count !== undefined && tab.count !== null && tab.count > 0}
        <span
          class="rounded-md bg-muted px-1.5 text-xs leading-5 font-semibold text-foreground tabular-nums"
          >{formatNumber(tab.count)}</span
        >
      {/if}
    </button>
  {/each}
</div>
