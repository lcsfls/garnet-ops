<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";

  /** An instant as a relative time with the exact one on hover; `never` text if there is none. */
  let { value }: { value: string | null } = $props();
</script>

{#if !value}
  {t("systemStatus.never")}
{:else}
  <time datetime={value} title={formatDateTime(value)}>{formatRelative(value)}</time>
{/if}
