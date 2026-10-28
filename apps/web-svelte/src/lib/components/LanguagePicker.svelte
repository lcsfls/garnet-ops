<script lang="ts">
  import { LANGUAGE_NAMES, LANGUAGES, type Language } from "@garnetops/i18n";
  import { Languages } from "@lucide/svelte";
  import { language, setLanguage, t } from "../i18n.svelte.ts";
  import Select from "./ui/Select.svelte";

  /** Explicit language choice; English is the default for everyone. */
  let { onChanged }: { onChanged?: (language: Language) => void } = $props();
  const id = $props.id();
</script>

<div class="flex items-center gap-1.5">
  <label for={id} class="text-muted-foreground">
    <Languages aria-hidden="true" class="size-4" />
    <span class="sr-only">{t("common.language")}</span>
  </label>
  <Select
    {id}
    value={language()}
    onchange={(e) => {
      const next = e.currentTarget.value as Language;
      void setLanguage(next);
      onChanged?.(next);
    }}
    class="h-9 text-sm"
  >
    {#each LANGUAGES as l (l)}<option value={l} lang={l}>{LANGUAGE_NAMES[l]}</option>{/each}
  </Select>
</div>
