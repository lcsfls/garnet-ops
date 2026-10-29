<script lang="ts">
  import { Pencil, Plus, Send, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { toast } from "../../toast.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import AddChannelDialog from "./notifications/AddChannelDialog.svelte";
  import { type Channel, EVENTS, eventKey, target } from "./notifications/channels.ts";
  import EditChannelDialog from "./notifications/EditChannelDialog.svelte";
  import EnabledSwitch from "./notifications/EnabledSwitch.svelte";

  /** Settings → Notifications (owners and admins). */
  let { me }: { me: Me } = $props();

  const queryClient = useQueryClient();
  const channels = createQuery(() => ({
    queryKey: ["notification-channels"],
    queryFn: () => api<Channel[]>("/notifications/channels"),
    // A test result arrives a moment after it was queued.
    refetchInterval: 5000,
  }));
  let adding = $state(false);
  let deleting = $state<Channel | null>(null);
  let editing = $state<Channel | null>(null);

  /** "New findings from High · 2 repositories": the filters in one line. */
  function filterSummary(channel: Channel): string {
    const parts = [];
    if (channel.events.includes("finding.new") || channel.events.includes("advisory.new")) {
      parts.push(t(`settings.minSeverity.${channel.filters.minSeverity ?? "high"}`));
    }
    const repos = channel.filters.repositoryIds?.length ?? 0;
    parts.push(
      repos > 0
        ? t("settings.channelRepositoryCount", { count: repos })
        : t("settings.channelAllRepositories"),
    );
    return parts.join(" · ");
  }
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
  const patch = createMutation(() => ({
    mutationFn: (input: { id: string; body: Partial<Pick<Channel, "enabled" | "events">> }) =>
      api(`/notifications/channels/${input.id}`, { method: "PATCH", body: input.body }),
    // The switch moves at once; a failure puts it back when the list reloads.
    onMutate: (input: { id: string; body: Partial<Pick<Channel, "enabled" | "events">> }) => {
      queryClient.setQueryData<Channel[]>(["notification-channels"], (list) =>
        list?.map((x) => (x.id === input.id ? { ...x, ...input.body } : x)),
      );
    },
    onSettled: refresh,
  }));
  const test = createMutation(() => ({
    mutationFn: (id: string) => api(`/notifications/channels/${id}/test`, { method: "POST" }),
    onSuccess: () => toast.success(t("settings.testQueued")),
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) => api(`/notifications/channels/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      deleting = null;
      await refresh();
    },
  }));
</script>

<Card>
  <CardHeader title={t("settings.notificationsTitle")} description={t("settings.notificationsDescription")}>
    {#snippet actions()}
      <Button variant="outline" onclick={() => (adding = true)}>
        <Plus aria-hidden="true" class="size-4" />
        {t("settings.addChannel")}
      </Button>
    {/snippet}
  </CardHeader>
  <p class="px-5 pb-3 text-sm text-muted-foreground">
    {t("settings.notificationsRelation")}
    <a
      href={href("/account", { section: "notifications" })}
      class="font-medium text-primary-text underline underline-offset-4"
    >
      {t("settings.notificationsPersonalLink")}
    </a>
  </p>
  <QueryStatus query={channels} />
  {#if patch.isError}
    <div class="px-5 pb-3">
      <Alert tone="error">{t("errors.actionFailed")}</Alert>
    </div>
  {/if}
  {#if channels.data && channels.data.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("settings.notificationsEmpty")}</p>
  {/if}
  <ul>
    {#each channels.data ?? [] as channel (channel.id)}
      <li class="grid gap-2 border-t px-5 py-3">
        <div class="flex flex-wrap items-start gap-3">
          <div class="min-w-0 flex-[1_1_16rem]">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium">{channel.name}</span>
              <Badge tone="neutral">
                {channel.kind === "webhook" && channel.format
                  ? t(`settings.format.${channel.format}`)
                  : t(`settings.kind.${channel.kind}`)}
              </Badge>
            </div>
            <div class="text-sm break-all text-muted-foreground">{target(channel)}</div>
            <div class="text-[13px] text-muted-foreground">
              {EVENTS.filter((e) => channel.events.includes(e))
                .map((e) => t(`settings.event.${eventKey(e)}`))
                .join(" · ")}
            </div>
            <div class="text-[13px] text-muted-foreground" data-testid="channel-filters">{filterSummary(channel)}</div>
            <div class="mt-1 text-[13px]">
              {#if channel.lastDelivery}
                {#if channel.lastDelivery.status === "sent"}
                  <span class="text-muted-foreground">
                    {t("settings.lastSent", { when: formatRelative(channel.lastDelivery.createdAt) })}
                  </span>
                {:else}
                  <span class="text-destructive-text">
                    {t("settings.lastFailed", {
                      when: formatRelative(channel.lastDelivery.createdAt),
                      reason: channel.lastDelivery.error ?? "",
                    })}
                  </span>
                {/if}
              {:else}
                <span class="text-muted-foreground">{t("settings.neverSent")}</span>
              {/if}
            </div>
          </div>
          {#key `${channel.id}-${channel.enabled}`}
            <EnabledSwitch
              label={`${t("settings.channelEnabled")}: ${channel.name}`}
              text={t("settings.channelEnabled")}
              enabled={channel.enabled}
              onChange={(enabled) => patch.mutate({ id: channel.id, body: { enabled } })}
            />
          {/key}
          <Button variant="outline" class="h-9" disabled={test.isPending} onclick={() => test.mutate(channel.id)}>
            <Send aria-hidden="true" class="size-4" />
            {t("settings.sendTest")}
          </Button>
          <Button
            variant="ghost"
            class="h-9 px-2.5"
            aria-label={`${t("settings.editChannel")}: ${channel.name}`}
            onclick={() => (editing = channel)}
          >
            <Pencil aria-hidden="true" class="size-4" />
          </Button>
          <Button
            variant="ghost"
            class="h-9 px-2.5"
            aria-label={`${t("settings.deleteChannel")}: ${channel.name}`}
            onclick={() => (deleting = channel)}
          >
            <Trash2 aria-hidden="true" class="size-4" />
          </Button>
        </div>
      </li>
    {/each}
  </ul>
  <AddChannelDialog {me} open={adding} onClose={() => (adding = false)} />
  {#if editing}
    {#key editing.id}
      <EditChannelDialog channel={editing} onClose={() => (editing = null)} />
    {/key}
  {/if}
  <ConfirmDialog
    open={deleting !== null}
    title={t("settings.deleteChannelTitle", { name: deleting?.name ?? "" })}
    description={t("settings.deleteChannelDescription")}
    confirmLabel={t("settings.deleteChannel")}
    pending={remove.isPending}
    error={remove.isError ? t("errors.actionFailed") : null}
    onConfirm={() => {
      if (deleting) remove.mutate(deleting.id);
    }}
    onClose={() => (deleting = null)}
  />
</Card>
