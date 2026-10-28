<script lang="ts">
  import {
    adminMessagesFor,
    describeCode,
    interpolate,
    messagesFor,
  } from "@restow-backup/cicd-updater/messages";
  import type { StateView } from "@restow-backup/cicd-updater/protocol";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { language, t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { notifyMaintenanceChanged, updatesApi } from "../../updates.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import { explain } from "./updates/explain.ts";
  import NoSidecar from "./updates/NoSidecar.svelte";
  import Overview from "./updates/Overview.svelte";
  import ReleasePanel from "./updates/ReleasePanel.svelte";
  import RunPanel from "./updates/RunPanel.svelte";

  /**
   * The Updates section of the settings (owners and admins). Shows the running version, what blocks updates, the next
   * release with its notes, a schedule form, the live state of a run with cancel, and the result with acknowledge.
   * Without the optional sidecar it shows how to update by hand.
   */
  let { me }: { me: Me } = $props();

  const messages = $derived(messagesFor(language()));
  const texts = $derived(adminMessagesFor(language()));
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let notice = $state("");
  let actionError = $state<string | null>(null);

  const status = createQuery(() => ({
    queryKey: ["updates"],
    queryFn: updatesApi.status,
    // Follow a scheduled or running update closely; otherwise check now and then.
    refetchInterval: (q) => {
      const phase = q.state.data?.state?.phase;
      return phase === "scheduled" || phase === "running" || q.state.status === "error" ? 3_000 : 30_000;
    },
    retry: false,
  }));
  const updateState = $derived(status.data?.state ?? null);
  const releases = createQuery(() => ({
    queryKey: ["updates", "releases", updateState?.running.version ?? null],
    queryFn: () => updatesApi.releases(false),
    enabled: updateState !== null,
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 5 * 60_000,
  }));

  const refresh = async (next: StateView | null) => {
    if (next) queryClient.setQueryData(["updates"], { ...status.data, state: next });
    await queryClient.invalidateQueries({ queryKey: ["updates"] });
  };

  const action = createMutation(() => ({
    mutationFn: (run: () => Promise<StateView>) => run(),
    onMutate: () => {
      actionError = null;
      notice = "";
    },
  }));
  const act = (run: () => Promise<StateView>, done: string): void =>
    action.mutate(run, {
      onSuccess: async (next) => {
        notice = done;
        notifyMaintenanceChanged();
        await refresh(next);
      },
      onError: (error) => {
        // Confirm the sign-in, then try the same action again.
        if (stepUp.handled(error, () => act(run, done))) return;
        actionError = explain(error, messages, texts);
      },
    });
</script>

<Card>
  <CardHeader title={texts.title} description={t("settings.updatesDescription")} />
  <div class="grid gap-4 px-5 py-5">
    <output aria-live="polite" class={notice ? "text-sm text-muted-foreground" : "sr-only"}>
      {notice}
    </output>
    {#if actionError}<Alert tone="error">{actionError}</Alert>{/if}
    {#if status.isError && !status.data}
      <Alert tone="error">{explain(status.error, messages, texts)}</Alert>
    {:else if !status.data}
      <p role="status" class="text-muted-foreground">
        {texts.loading}
      </p>
    {:else if !updateState}
      <NoSidecar {texts} />
    {:else}
      <Overview state={updateState} {messages} {texts} offline={status.isError} />
    {/if}
  </div>
</Card>

{#if updateState?.run && updateState.phase !== "idle"}
  <RunPanel
    state={updateState}
    {messages}
    {texts}
    busy={action.isPending}
    onCancel={(runId) => act(() => updatesApi.cancel(runId), texts.cancelled)}
    onAcknowledge={(runId) => act(() => updatesApi.acknowledge(runId), texts.acknowledged)}
  />
{/if}

{#if updateState}
  {@const current = updateState}
  <ReleasePanel
    releases={releases.data ?? null}
    error={releases.isError ? explain(releases.error, messages, texts) : null}
    checking={releases.isFetching}
    leadTimes={status.data?.leadTimes ?? []}
    blockedReason={current.phase === "scheduled" || current.phase === "running"
      ? texts.busyRun
      : current.capabilities.ready
        ? null
        : describeCode(messages, "problems", "blocked")}
    {messages}
    {texts}
    busy={action.isPending}
    onRefresh={() =>
      queryClient.fetchQuery({
        queryKey: ["updates", "releases", current.running.version],
        queryFn: () => updatesApi.releases(true),
      })}
    onSchedule={(input) =>
      act(() => updatesApi.schedule(input), interpolate(texts.scheduled, { version: input.version }))}
  />
{/if}

<StepUpPrompt {stepUp} email={me.user.email} />
