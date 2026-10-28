<script lang="ts">
  import { countdownOf, formatCountdown } from "@restow-backup/cicd-updater/maintenance";
  import {
    type AdminMessages,
    describeCode,
    formatMessage,
    interpolate,
    type Messages,
  } from "@restow-backup/cicd-updater/messages";
  import type { StateView } from "@restow-backup/cicd-updater/protocol";
  import { cn } from "../../../cn.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import AttentionGuide from "./AttentionGuide.svelte";

  let {
    state: current,
    messages,
    texts,
    busy,
    onCancel,
    onAcknowledge,
  }: {
    state: StateView;
    messages: Messages;
    texts: AdminMessages;
    busy: boolean;
    onCancel: (runId: string) => void;
    onAcknowledge: (runId: string) => void;
  } = $props();

  const run = $derived(current.run);
  const offsetMs = $derived(Date.parse(current.serverTime) - Date.now());
  // The countdown ticks every second while an update is scheduled (useCountdown in the React app).
  const startsAt = $derived(current.phase === "scheduled" ? (run?.startsAt ?? null) : null);
  let now = $state(Date.now());
  $effect(() => {
    if (!startsAt) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });
  const countdown = $derived(startsAt ? countdownOf(startsAt, offsetMs, now) : null);
  const finished = $derived(current.phase === "succeeded" || current.phase === "failed");
  const detail = $derived(
    run?.outcome
      ? messages.outcomes[run.outcome]
      : current.phase === "scheduled" || !run
        ? ""
        : formatMessage(messages, run.message),
  );
</script>

{#if run}
  <Card>
    <CardHeader title={texts.currentRun} />
    <div class="grid gap-3 px-5 py-5">
      <p aria-live="polite">
        <span class="font-semibold">{messages.phases[current.phase]}</span>
        <span class="text-muted-foreground">{detail}</span>
      </p>
      {#if current.phase === "scheduled"}
        <p class="font-mono tabular-nums">
          {countdown && countdown > 0
            ? interpolate(messages.ui.startsIn, { time: formatCountdown(countdown) })
            : messages.ui.startingNow}
        </p>
      {/if}
      <p class="text-sm text-muted-foreground">
        {interpolate(texts.versions, {
          from: run.fromVersion ?? texts.unknownVersion,
          to: run.targetVersion,
        })}. {interpolate(texts.requestedBy, { label: run.requestedBy.label })}.
      </p>
      {#if current.phase === "running"}
        <progress
          max={100}
          value={run.progress}
          aria-label={texts.progressLabel}
          class="h-2 w-full overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info"
        ></progress>
        <ol class="flex flex-wrap gap-1.5">
          {#each run.steps.filter((step) => step.status !== "skipped") as step (step.id)}
            <li>
              <Badge
                class={cn(
                  step.status === "done" && "bg-muted text-foreground",
                  step.status === "running" && "bg-info/15 text-info-text",
                  step.status === "failed" && "bg-destructive/15 text-destructive-text",
                  step.status === "pending" && "bg-muted text-muted-foreground",
                )}
              >
                {messages.steps[step.id]}
              </Badge>
            </li>
          {/each}
        </ol>
      {/if}
      {#if run.abortRequestedAt}<p>{texts.abortRequested}</p>{/if}
      {#if run.failure}
        <Alert tone="error">{describeCode(messages, "failures", run.failure.code)}</Alert>
      {/if}
      {#if run.outcome === "needs_attention"}<AttentionGuide {run} {texts} />{/if}
      <div class="flex gap-2">
        {#if (current.phase === "scheduled" || current.phase === "running") && !run.abortRequestedAt}
          <Button variant="destructive" disabled={busy} onclick={() => onCancel(run.id)}>
            {texts.cancel}
          </Button>
        {/if}
        {#if finished}
          <Button variant="outline" disabled={busy} onclick={() => onAcknowledge(run.id)}>
            {texts.acknowledge}
          </Button>
        {/if}
      </div>
    </div>
  </Card>
{/if}
