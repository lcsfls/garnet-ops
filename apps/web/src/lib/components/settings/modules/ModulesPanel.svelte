<script lang="ts">
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import ModuleCard from "./ModuleCard.svelte";

  /**
   * Settings, Modules (ADR 0033): parts of GarnetOps an organisation switches on. Website monitoring (it connects to public hosts an
   * admin names) and hosts and containers (agents on the organisation's servers report to it, ADR 0034) are off by default.
   * Switching is audited; switching off keeps the data.
   */
  let { me }: { me: Me } = $props();
  const canEdit = $derived(isAdmin(me));
  const websites = $derived(me.organization.modules?.websites === true);
  const hosts = $derived(me.organization.modules?.hosts === true);
</script>

<Card>
  <CardHeader title={t("settings.modulesTitle")} description={t("settings.modulesDescription")} />
  <div class="grid gap-3 px-5 pb-5">
    {#if !canEdit}<Alert tone="info">{t("settings.modulesViewerHint")}</Alert>{/if}
    <ModuleCard module="websites" on={websites} {canEdit} openHref="/websites" />
    <ModuleCard module="hosts" on={hosts} {canEdit} openHref="/hosts" />
  </div>
</Card>

<p class="mt-4 text-sm text-muted-foreground">
  {t("settings.modulesExternalHint")} <a href="/settings?section=external" class="text-primary-text hover:underline"
    >{t("settings.sectionExternal")}</a
  >
</p>
