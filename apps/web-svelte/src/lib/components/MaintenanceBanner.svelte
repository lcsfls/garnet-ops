<script lang="ts">
  import { formatMessage, interpolate, messagesFor } from "@restow-backup/cicd-updater/messages";
  import {
    formatCountdown,
    MaintenanceTracker,
    type MaintenanceSnapshot,
    pollMaintenance,
  } from "@restow-backup/cicd-updater/maintenance";
  import { CircleCheck, CircleX, Clock, LoaderCircle } from "@lucide/svelte";
  import { cn } from "../cn.ts";
  import { language } from "../i18n.svelte.ts";
  import { fetchMaintenance, fetchPublicStatus, maintenanceChanged } from "../updates.ts";

  /**
   * The update banner every signed-in user sees (ADR 0007): a countdown while an update is scheduled, progress while it
   * runs, the result when it ended. Nothing while idle or when the installation has no update sidecar. After a
   * successful update the page reloads once, so everyone gets the new web app.
   *
   * Texts of phases, steps and results come from the cicd-updater catalogs (English, German) in the UI language. Only
   * the phase line is a live region; the ticking countdown sits outside it, so screen readers do not announce every
   * second.
   */
  let snapshot = $state<MaintenanceSnapshot>(new MaintenanceTracker().snapshot);
  // A fresh poller after an action in this browser, so the banner follows at once.
  let generation = $state(0);

  $effect(() => {
    const bump = () => generation++;
    maintenanceChanged.addEventListener("change", bump);
    return () => maintenanceChanged.removeEventListener("change", bump);
  });

  $effect(() => {
    void generation;
    snapshot = new MaintenanceTracker().snapshot;
    return pollMaintenance({
      fetchMaintenance,
      fetchPublicStatus,
      onChange: (next) => (snapshot = next),
      onReload: () => window.location.reload(),
    });
  });

  const view = $derived(snapshot.view);
  const messages = $derived(messagesFor(language()));
  const phase = $derived(snapshot.phase);
  const failed = $derived(phase === "failed" || (view?.outcome != null && view.outcome !== "succeeded"));
  const succeeded = $derived(phase === "succeeded" && view?.outcome === "succeeded");
  const Icon = $derived(
    phase === "scheduled" ? Clock : phase === "running" ? LoaderCircle : failed ? CircleX : CircleCheck,
  );
  const title = $derived(
    phase === "scheduled"
      ? messages.ui.updateScheduled
      : phase === "running"
        ? messages.ui.updateRunning
        : failed
          ? messages.ui.updateFailed
          : messages.ui.updateSucceeded,
  );
  const detail = $derived(
    view ? (view.outcome ? messages.outcomes[view.outcome] : formatMessage(messages, view.message)) : "",
  );
</script>

{#if view && phase !== "idle"}
  <div
    data-state={phase}
    class={cn(
      "mb-5 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border bg-card px-4 py-3 shadow-xs",
      // Green means proof: only a finished, healthy update is shown as success (AGENTS.md rule 6).
      succeeded ? "border-success/50" : failed ? "border-destructive/50" : "border-info/40",
    )}
  >
    <Icon
      aria-hidden="true"
      class={cn(
        "size-5 flex-none",
        succeeded ? "text-success-text" : failed ? "text-destructive-text" : "text-info-text",
        phase === "running" && "motion-safe:animate-spin",
      )}
    />
    <div role="status" class="min-w-0 flex-[1_1_18rem]">
      <span class="font-semibold">{title}</span> <span class="text-muted-foreground">{detail}</span>
      {#if succeeded}<span class="text-muted-foreground"> {messages.ui.reloadHint}</span>{/if}
    </div>
    {#if phase === "scheduled"}
      <span class="font-mono tabular-nums">
        {snapshot.countdownSeconds && snapshot.countdownSeconds > 0
          ? interpolate(messages.ui.startsIn, { time: formatCountdown(snapshot.countdownSeconds) })
          : messages.ui.startingNow}
      </span>
    {/if}
    {#if phase === "running"}
      <div class="flex w-full items-center gap-3 @xl:w-72">
        <progress
          max={100}
          value={view.progress}
          aria-label={interpolate(messages.ui.progress, { progress: view.progress })}
          class="h-2 flex-1 overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info"
        ></progress>
        <span class="text-sm whitespace-nowrap tabular-nums">
          {interpolate(messages.ui.progress, { progress: view.progress })}
        </span>
      </div>
    {/if}
  </div>
{/if}
