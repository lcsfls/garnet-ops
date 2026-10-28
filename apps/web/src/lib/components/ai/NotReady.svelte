<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { Me } from "../../session.ts";
  import { href } from "../../url.ts";

  let { state, me }: { state: "not-configured" | "disabled"; me: Me } = $props();
</script>

<div class="grid gap-2 px-5 py-4">
  <p>{state === "disabled" ? t("ai.disabled") : t("ai.notConfigured")}</p>
  {#if isAdmin(me)}
    <a href={href("/settings", { section: "ai" })} class="text-primary-text hover:underline">{t("ai.openSettings")}</a>
  {:else}
    <p class="text-sm text-muted-foreground">{t("ai.askAdmin")}</p>
  {/if}
</div>
