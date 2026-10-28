<script lang="ts">
  import { ExternalLink, RefreshCw } from "@lucide/svelte";
  import {
    type AdminMessages,
    describeCode,
    formatLeadTime,
    interpolate,
    type Messages,
  } from "@restow-backup/cicd-updater/messages";
  import type { ReleasesView } from "@restow-backup/cicd-updater/protocol";
  import { untrack } from "svelte";
  import { cn } from "../../../cn.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import FormField from "../../ui/FormField.svelte";
  import FormRow from "../../ui/FormRow.svelte";
  import Select from "../../ui/Select.svelte";

  let {
    releases,
    error,
    checking,
    leadTimes,
    blockedReason,
    messages,
    texts,
    busy,
    onRefresh,
    onSchedule,
  }: {
    releases: ReleasesView | null;
    error: string | null;
    checking: boolean;
    leadTimes: readonly number[];
    blockedReason: string | null;
    messages: Messages;
    texts: AdminMessages;
    busy: boolean;
    onRefresh: () => void;
    onSchedule: (input: { version: string; leadSeconds: number; releaseSha256: string }) => void;
  } = $props();

  const installable = $derived(
    (releases?.releases ?? []).filter((r) => r.refusals.length === 0 && r.releaseSha256 !== null),
  );
  const refused = $derived(
    (releases?.releases ?? []).filter((r) => r.refusals.length > 0 && !r.refusals.includes("not_newer")),
  );
  let version = $state("");
  let leadSeconds = $state(untrack(() => (leadTimes.includes(900) ? 900 : (leadTimes[0] ?? 0))));
  const chosen = $derived(
    installable.find((r) => r.version === version) ??
      installable.find((r) => r.version === releases?.nextInstallable) ??
      installable[0],
  );

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (chosen?.releaseSha256) {
      onSchedule({ version: chosen.version, leadSeconds, releaseSha256: chosen.releaseSha256 });
    }
  }
</script>

<Card>
  <CardHeader title={texts.available}>
    {#snippet actions()}
      <Button variant="outline" class="h-9" disabled={busy || checking} onclick={onRefresh}>
        <RefreshCw aria-hidden="true" class={cn("size-4", checking && "motion-safe:animate-spin")} />
        {texts.checkAgain}
      </Button>
    {/snippet}
  </CardHeader>
  <div class="grid gap-4 px-5 py-5">
    {#if error}
      <Alert tone="error">{error}</Alert>
    {:else if !releases}
      <p role="status" class="text-muted-foreground">
        {texts.checking}
      </p>
    {:else if !chosen}
      <p>{refused.length === 0 ? texts.newest : texts.nothingInstallable}</p>
    {:else}
      {@const current = chosen}
      <form class="grid gap-4" onsubmit={submit}>
        <FormRow columns={2} from="md">
          <FormField id="update-version" label={texts.version}>
            {#snippet children(control)}
              <Select {...control} bind:value={() => current.version, (value) => (version = value)}>
                {#each installable as r (r.version)}
                  <option value={r.version}>{r.version}</option>
                {/each}
              </Select>
            {/snippet}
          </FormField>
          <FormField id="update-start" label={texts.start}>
            {#snippet children(control)}
              <Select {...control} bind:value={() => leadSeconds, (value) => (leadSeconds = Number(value))}>
                {#each leadTimes as seconds (seconds)}
                  <option value={seconds}>{formatLeadTime(texts, seconds)}</option>
                {/each}
              </Select>
            {/snippet}
          </FormField>
        </FormRow>
        <p class="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
          {#if current.notesUrl}
            <a
              href={current.notesUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1.5 text-primary-text underline-offset-4 hover:underline"
            >
              {texts.notes}
              <ExternalLink aria-hidden="true" class="size-3.5" />
            </a>
          {/if}
          {#if current.releaseSha256}
            <span class="font-mono">
              {interpolate(texts.releaseDigest, { sha: current.releaseSha256.slice(0, 16) })}
            </span>
          {/if}
        </p>
        <div class="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={busy || blockedReason !== null}>
            {texts.schedule}
          </Button>
          {#if blockedReason}<span class="text-sm text-muted-foreground">{blockedReason}</span>{/if}
        </div>
      </form>
    {/if}
    {#if refused.length > 0}
      <ul class="grid gap-1 text-sm text-muted-foreground">
        {#each refused as r (r.version)}
          <li>
            <span class="font-mono text-foreground">{r.version}</span>: {r.refusals
              .map((code) => describeCode(messages, "refusals", code))
              .join(" ")}
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</Card>
