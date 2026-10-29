<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { stage1Key, stage1Tone, stage2Key, stage2Tone, type WebsiteAsset } from "../../websites.ts";
  import Badge from "../ui/Badge.svelte";

  /** What stage 1 or stage 2 is doing for a website, as a word. */
  let { asset, stage }: { asset: Pick<WebsiteAsset, "stage1" | "stage2">; stage: 1 | 2 } = $props();
</script>

{#if stage === 1}
  {@const key = stage1Key(asset)}
  <Badge tone={stage1Tone(key)}>{t(`websites.stage1State.${key}`)}</Badge>
{:else}
  {@const key = stage2Key(asset)}
  <Badge tone={stage2Tone(key)}>{t(`websites.stage2State.${key}`)}</Badge>
{/if}
