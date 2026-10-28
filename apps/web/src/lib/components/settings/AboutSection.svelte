<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { t } from "../../i18n.svelte.ts";
  import { systemQuery } from "../../shell.ts";
  import { displayVersion } from "../../version.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";

  /** Public source repository; AGPL-3.0 section 13 asks us to offer the source to every user. */
  const SOURCE_REPOSITORY = "https://github.com/lcsfls/garnet-ops";

  /** Version, licence and where the source code of this version is (AGPL-3.0, section 13). */
  const system = createQuery(() => systemQuery);
  const version = $derived(system.data?.version);
  const sourceUrl = $derived(version ? `${SOURCE_REPOSITORY}/tree/v${version}` : SOURCE_REPOSITORY);
</script>

<Card>
  <CardHeader title={t("settings.aboutTitle")} description={t("settings.aboutDescription")} />
  {#if system.data}
    <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 px-5 py-5">
      <dt class="text-muted-foreground">{t("settings.aboutVersion")}</dt>
      <dd class="font-mono">{version ? displayVersion(version, t("shell.alpha")) : null}</dd>
      <dt class="text-muted-foreground">{t("settings.aboutLicense")}</dt>
      <dd>{t("settings.aboutLicenseValue")}</dd>
      <dt class="text-muted-foreground">{t("settings.aboutSource")}</dt>
      <dd class="break-all">
        <a
          href={sourceUrl}
          target="_blank"
          rel="noopener noreferrer"
          class="text-primary-text underline-offset-4 hover:underline"
        >
          {sourceUrl}
        </a>
      </dd>
    </dl>
  {:else}
    <QueryStatus query={system} />
  {/if}
</Card>
