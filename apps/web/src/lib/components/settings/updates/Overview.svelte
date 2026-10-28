<script lang="ts">
  import { type AdminMessages, describeCode, type Messages } from "@restow-backup/cicd-updater/messages";
  import type { StateView } from "@restow-backup/cicd-updater/protocol";
  import { t } from "../../../i18n.svelte.ts";
  import Alert from "../../ui/Alert.svelte";

  let {
    state,
    messages,
    texts,
    offline,
  }: { state: StateView; messages: Messages; texts: AdminMessages; offline: boolean } = $props();

  // Unsigned mode has its own, stronger notice above; the same warning is not listed twice.
  const warnings = $derived(state.capabilities.warnings.filter((w) => w.code !== "trust_mode_none"));
</script>

{#if offline}<Alert tone="info">{texts.offline}</Alert>{/if}
<dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2">
  <dt class="text-muted-foreground">{texts.runningVersion}</dt>
  <dd class="font-mono">{state.running.version ?? texts.unknownVersion}</dd>
  <dt class="text-muted-foreground">{t("settings.updatesTrust")}</dt>
  <dd>{t(`settings.updatesTrustMode.${state.trust.mode}`)}</dd>
  <dt class="text-muted-foreground">{t("settings.updatesUpdater")}</dt>
  <dd class="font-mono">{state.updater.version}</dd>
</dl>
{#if state.trust.mode === "none"}<Alert tone="error">{messages.ui.trustModeNone}</Alert>{/if}
{#if state.capabilities.blockers.length > 0}
  <Alert tone="error">
    <p>{texts.blocked}</p>
    <ul class="mt-1 list-disc pl-5">
      {#each state.capabilities.blockers as b (b.code)}
        <li>{describeCode(messages, "blockers", b.code)}</li>
      {/each}
    </ul>
  </Alert>
{/if}
{#if warnings.length > 0}
  <Alert tone="info">
    <p>{texts.warnings}</p>
    <ul class="mt-1 list-disc pl-5">
      {#each warnings as w (w.code)}
        <li>{describeCode(messages, "warnings", w.code)}</li>
      {/each}
    </ul>
  </Alert>
{/if}
