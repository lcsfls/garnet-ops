<script lang="ts">
  import { TriangleAlert } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { VERIFICATION_TONE, verificationKey, type WebsiteAsset } from "../../websites.ts";
  import Badge from "../ui/Badge.svelte";

  /** A word, never a colour alone. Blue and grey, never green: a proof of control is no security result. */
  let { asset }: { asset: Pick<WebsiteAsset, "verification"> } = $props();
  const key = $derived(verificationKey(asset));
</script>

<Badge tone={VERIFICATION_TONE[key]}>
  {#if key === "lost"}<TriangleAlert aria-hidden="true" />{/if}
  {t(`websites.verification.${key}`)}
</Badge>
