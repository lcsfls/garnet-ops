<script lang="ts">
  import { Download, FileSpreadsheet, FileText, FileType } from "@lucide/svelte";
  import { language, t } from "../i18n.svelte.ts";
  import { toQuery } from "../search.ts";

  const FORMATS = [
    { format: "csv", icon: FileSpreadsheet },
    { format: "xlsx", icon: FileSpreadsheet },
    { format: "pdf", icon: FileType },
    { format: "txt", icon: FileText },
  ] as const;

  /** The browser's zone: dates in the file are the user's own calendar days (ADR 0005). */
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  /**
   * Downloads the findings list as CSV, Excel, PDF or text, with exactly the filters that are set (and only one
   * repository on a repository's page). The server builds the file; the link carries the filters, so the download
   * matches what the user sees.
   */
  let { filters }: { filters: Record<string, string | number | undefined> } = $props();
  let open = $state(false);
  const panelId = $props.id();
  let root: HTMLDivElement | undefined = $state();
  let button: HTMLButtonElement | undefined = $state();

  $effect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root?.contains(event.target as Node)) open = false;
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      open = false;
      button?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  });

  const href = (format: string) =>
    `/api/v1/findings/export${toQuery({ ...filters, format, tz: timeZone, lang: language() })}`;
</script>

<div bind:this={root} class="relative">
  <button
    bind:this={button}
    type="button"
    aria-expanded={open}
    aria-controls={panelId}
    onclick={() => (open = !open)}
    class="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
  >
    <Download aria-hidden="true" class="size-4" />
    {t("export.button")}
  </button>
  {#if open}
    <div
      id={panelId}
      class="absolute top-full right-0 z-30 mt-2 w-64 rounded-lg border bg-card p-2 text-card-foreground shadow-xs"
    >
      <p class="px-2 pt-1 pb-2 text-sm text-muted-foreground">{t("export.hint")}</p>
      <ul aria-label={t("export.menu")} class="grid gap-0.5">
        {#each FORMATS as { format, icon: Icon } (format)}
          <li>
            <a
              href={href(format)}
              download
              onclick={() => (open = false)}
              class="flex h-9 items-center gap-2.5 rounded-md px-2 hover:bg-accent"
            >
              <Icon aria-hidden="true" class="size-4 text-muted-foreground" />
              {t(`export.${format}`)}
            </a>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>
