<script lang="ts">
  import { PowerOff } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";

  /** What a page of website monitoring shows while the module is off (ADR 0033): why, and where to switch it on. */
  let { canSwitch }: { canSwitch: boolean } = $props();
</script>

<Card>
  <div class="grid gap-2 px-5 py-6" data-testid="websites-module-off">
    <h2 class="flex items-center gap-2 font-medium">
      <PowerOff aria-hidden="true" class="size-4 text-muted-foreground" />{t("websites.moduleOffTitle")}
    </h2>
    <p class="text-muted-foreground">{t("websites.moduleOffText")}</p>
    {#if canSwitch}
      <a class="w-fit text-primary-text hover:underline" href={href("/settings", { section: "modules" })}>
        {t("websites.moduleOffLink")}
      </a>
    {/if}
  </div>
</Card>
