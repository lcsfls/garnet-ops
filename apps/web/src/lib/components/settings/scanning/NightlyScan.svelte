<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { ApiError, api } from "../../../api.ts";
  import { type MessageKey, t } from "../../../i18n.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Field from "../../ui/Field.svelte";
  import FormField from "../../ui/FormField.svelte";
  import FormRow from "../../ui/FormRow.svelte";
  import Select from "../../ui/Select.svelte";
  import { type Organization, timeZonesWith } from "./organization.ts";

  let { org, canEdit }: { org: Organization; canEdit: boolean } = $props();

  const queryClient = useQueryClient();
  const schedule = $derived(org.scanSchedule);
  // The form starts from the stored schedule and keeps what is typed while the organisation reloads.
  let enabled = $state(untrack(() => org.scanSchedule.enabled));
  let timeZone = $state(untrack(() => org.scanSchedule.timeZone));
  const initialTime = untrack(() => org.scanSchedule.localTime.slice(0, 5));
  let error = $state<MessageKey | null>(null);
  const zones = $derived(timeZonesWith(schedule.timeZone));

  const save = createMutation(() => ({
    mutationFn: (body: { enabled: boolean; localTime: string; timeZone: string }) =>
      api("/organization/scan-schedule", { method: "PUT", body }),
    onSuccess: async () => {
      toast.success(t("settings.saved"));
      // The repositories page shows the schedule from the session status.
      await queryClient.invalidateQueries({ queryKey: ["organization"] });
      await queryClient.invalidateQueries({ queryKey: ["status"] });
    },
    onError: (e: Error) => {
      error =
        e instanceof ApiError && e.code === "unsupported-time-zone" ? "settings.errorZone" : "errors.generic";
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    error = null;
    // A disabled field is not part of the form: switching the nightly scan off keeps the stored time.
    const time = form.get("localTime");
    save.mutate({ enabled, localTime: typeof time === "string" && time ? time : initialTime, timeZone });
  }
</script>

<Card>
  <CardHeader title={t("settings.nightlyTitle")} description={t("settings.nightlyDescription")} />
  <form class="grid gap-5 px-5 py-5" onsubmit={submit}>
    {#if !canEdit}<Alert tone="info">{t("settings.readOnly")}</Alert>{/if}
    {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
    <label class="flex items-center gap-2.5">
      <Checkbox bind:checked={enabled} disabled={!canEdit} />
      {t("settings.enabled")}
    </label>
    <FormRow columns={["10rem", "1fr"]} from="md">
      <Field
        id="nightly-time"
        label={t("settings.time")}
        name="localTime"
        type="time"
        required
        step={60}
        disabled={!canEdit || !enabled}
        value={initialTime}
      />
      <FormField id="nightly-zone" label={t("settings.timeZone")} hint={t("settings.timeZoneHint")}>
        {#snippet children(control)}
          <Select {...control} bind:value={timeZone} disabled={!canEdit || !enabled}>
            {#each zones as zone (zone)}
              <option value={zone}>{zone}</option>
            {/each}
          </Select>
        {/snippet}
      </FormField>
    </FormRow>
    <p class="text-sm text-muted-foreground">{t("settings.timeHint")}</p>
    {#if canEdit}
      <div class="flex items-center gap-3">
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? t("common.loading") : t("settings.save")}
        </Button>
      </div>
    {/if}
  </form>
</Card>
