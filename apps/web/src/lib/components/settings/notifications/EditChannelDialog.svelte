<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import ChannelEventsFields from "./ChannelEventsFields.svelte";
  import { type Channel, type ChannelEvent, filtersBody, type MinSeverity } from "./channels.ts";

  /** Changes what an existing channel is sent: its events and filters. Where it sends to stays as it is. */
  let { channel, onClose }: { channel: Channel; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  // The dialog is created for one channel and starts from its saved choice.
  // svelte-ignore state_referenced_locally
  let events = $state<ChannelEvent[]>([...channel.events]);
  // svelte-ignore state_referenced_locally
  let minSeverity = $state<MinSeverity>(channel.filters.minSeverity ?? "high");
  // svelte-ignore state_referenced_locally
  let repositoryIds = $state<string[] | null>(channel.filters.repositoryIds ?? null);
  let error = $state<string | null>(null);
  let filtersError = $state<string | undefined>(undefined);

  const save = createMutation(() => ({
    mutationFn: () =>
      api(`/notifications/channels/${channel.id}`, {
        method: "PATCH",
        body: { events, filters: filtersBody(minSeverity, repositoryIds) },
      }),
    onMutate: () => {
      error = null;
      filtersError = undefined;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      onClose();
    },
    onError: (e: Error) => {
      if (e instanceof ApiError && e.status === 422) {
        filtersError = e.problem?.errors?.find((x) => x.path.startsWith("filters"))?.message;
        error = t("repositories.errorInvalid");
        return;
      }
      error = t("errors.actionFailed");
    },
  }));
</script>

<Dialog
  open
  onClose={onClose}
  title={t("settings.editChannelTitle", { name: channel.name })}
  description={t("settings.editChannelDescription")}
>
  <form
    class="grid gap-4"
    onsubmit={(e) => {
      e.preventDefault();
      save.mutate();
    }}
  >
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <ChannelEventsFields bind:events bind:minSeverity bind:repositoryIds error={filtersError} />
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>
        {t("common.cancel")}
      </Button>
      <Button type="submit" disabled={save.isPending || events.length === 0 || repositoryIds?.length === 0}>
        {save.isPending ? t("common.loading") : t("settings.channelUpdate")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
