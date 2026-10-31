<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import VulnDbBuildKey, { type VulnDbBuildKeyState } from "./VulnDbBuildKey.svelte";

  /**
   * The two optional, installation-wide keys of the own vulnerability database build: a GitHub token (GitHub Advisory
   * Database, sent only to api.github.com) and an NVD API key (sent only to services.nvd.nist.gov). Owners and admins only;
   * the API never returns a key. Whether the build runs is the operator's choice in the Compose file, not a switch here.
   */
  let { me }: { me: Me } = $props();
  const admin = $derived(isAdmin(me));
  const stepUp = new StepUp();

  const query = createQuery(() => ({
    queryKey: ["vulndb-build"],
    queryFn: () => api<{ github: VulnDbBuildKeyState; nvd: VulnDbBuildKeyState }>("/vulndb-build"),
    enabled: admin,
  }));
</script>

{#if admin && query.data}
  <Card>
    <CardHeader
      title={t("settings.vulnDbBuild.title")}
      description={t("settings.vulnDbBuild.description", {
        profile: "vulndb",
        setting: "GARNETOPS_GRYPE_DB_UPDATE=build",
      })}
    />
    <p class="px-5 pb-4 text-sm text-muted-foreground">
      {t("settings.vulnDbBuild.statusHint")}
      <a href="/system" class="font-medium text-foreground underline underline-offset-2">{t("settings.vulnDbBuild.statusLink")}</a>.
    </p>
    <div data-testid="vulndb-build-section">
      <VulnDbBuildKey kind="github" current={query.data.github} canEdit={admin} {stepUp} />
      <VulnDbBuildKey kind="nvd" current={query.data.nvd} canEdit={admin} {stepUp} />
    </div>
  </Card>
  <StepUpPrompt {stepUp} email={me.user.email} />
{/if}
