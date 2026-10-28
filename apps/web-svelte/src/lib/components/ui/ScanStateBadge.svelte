<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { ScanState } from "../../types.ts";
  import Badge from "./Badge.svelte";
  import { scanStateTone } from "./tones.ts";

  let { state }: { state: ScanState | null } = $props();
</script>

{#if !state}
  <Badge tone="neutral">{t("scanState.never")}</Badge>
{:else}
  <Badge tone={scanStateTone(state)}>{t(`scanState.${state}`)}</Badge>
{/if}
