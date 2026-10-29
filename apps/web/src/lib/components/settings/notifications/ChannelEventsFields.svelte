<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Page, RepositoryRow } from "../../../types.ts";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Radio from "../../ui/Radio.svelte";
  import Select from "../../ui/Select.svelte";
  import { type ChannelEvent, EVENTS, eventKey, MIN_SEVERITIES, type MinSeverity } from "./channels.ts";

  /**
   * What a channel is sent: its events, from which severity on it hears of new findings, and which
   * repositories it is about (null: all, also the ones added later). Shared by adding and editing.
   */
  let {
    events = $bindable(),
    minSeverity = $bindable(),
    repositoryIds = $bindable(),
    error,
  }: {
    events: ChannelEvent[];
    minSeverity: MinSeverity;
    repositoryIds: string[] | null;
    error?: string;
  } = $props();

  const id = $props.id();
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
</script>

<fieldset class="grid gap-2">
  <legend class="mb-1.5 text-sm font-medium">{t("settings.channelEvents")}</legend>
  {#each EVENTS as e (e)}
    <label class="flex items-center gap-2.5">
      <Checkbox
        checked={events.includes(e)}
        onchange={(x) => {
          const checked = x.currentTarget.checked;
          events = checked ? [...events, e] : events.filter((v) => v !== e);
        }}
      />
      {t(`settings.event.${eventKey(e)}`)}
    </label>
  {/each}
</fieldset>
{#if events.includes("finding.new") || events.includes("advisory.new")}
  <label class="grid gap-1.5">
    <span class="text-sm font-medium">{t("settings.channelMinSeverity")}</span>
    <Select bind:value={minSeverity}>
      {#each MIN_SEVERITIES as s (s)}
        <option value={s}>{t(`settings.minSeverity.${s}`)}</option>
      {/each}
    </Select>
  </label>
{/if}
<fieldset class="grid gap-2" aria-describedby={error ? `${id}-error` : undefined}>
  <legend class="mb-1.5 text-sm font-medium">{t("settings.channelRepositories")}</legend>
  <label class="flex items-center gap-2.5">
    <Radio
      name={`${id}-scope`}
      checked={repositoryIds === null}
      onchange={() => (repositoryIds = null)}
    />
    {t("settings.channelAllRepositories")}
  </label>
  <label class="flex items-center gap-2.5">
    <Radio
      name={`${id}-scope`}
      checked={repositoryIds !== null}
      onchange={() => (repositoryIds = repositoryIds ?? [])}
    />
    {t("settings.channelSomeRepositories")}
  </label>
  {#if repositoryIds !== null}
    <div class="ml-6 grid max-h-48 gap-1.5 overflow-y-auto rounded-md border p-2.5">
      {#each repositories.data?.items ?? [] as repo (repo.id)}
        <label class="flex items-center gap-2.5 text-sm">
          <Checkbox
            checked={repositoryIds.includes(repo.id)}
            onchange={(x) => {
              const checked = x.currentTarget.checked;
              const current = repositoryIds ?? [];
              repositoryIds = checked ? [...current, repo.id] : current.filter((v) => v !== repo.id);
            }}
          />
          <span class="min-w-0 break-all">{repo.name}</span>
        </label>
      {:else}
        <p class="text-sm text-muted-foreground">{t("settings.channelNoRepositories")}</p>
      {/each}
    </div>
  {/if}
  {#if error}
    <p id={`${id}-error`} class="text-sm text-destructive-text">{error}</p>
  {/if}
</fieldset>
