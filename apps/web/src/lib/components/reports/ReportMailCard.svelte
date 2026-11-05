<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { REPORT_FREQUENCIES, type ReportFrequency, type ReportMailSettings } from "../../reports.ts";
  import { toast } from "../../toast.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Radio from "../ui/Radio.svelte";

  /**
   * The security report by email (ADR 0047), on Account → Notifications: off unless the person chooses daily, weekly or
   * monthly. It needs the organisation's mail channel, like personal mail in the matrix (ADR 0019); without one the choice
   * is disabled and says why. The mail comes at 07:00 in the person's own zone.
   */
  let { canManageChannels }: { canManageChannels: boolean } = $props();
  const queryClient = useQueryClient();
  const id = $props.id();
  const query = createQuery(() => ({
    queryKey: ["report-mail"],
    queryFn: () => api<ReportMailSettings>("/me/report-mail"),
  }));
  const data = $derived(query.data);

  type Choice = ReportFrequency | "off";
  // The draft follows the server until the person changes it.
  let frequency = $derived<Choice>(data?.frequency ?? "off");
  let attachPdf = $derived(data?.attachPdf ?? true);
  const dirty = $derived(
    data !== undefined && ((data.frequency ?? "off") !== frequency || data.attachPdf !== attachPdf),
  );

  const save = createMutation(() => ({
    mutationFn: () =>
      api<ReportMailSettings>("/me/report-mail", {
        method: "PUT",
        body: { frequency: frequency === "off" ? null : frequency, attachPdf },
      }),
    onSuccess: async () => {
      toast.success(t("reports.mail.saved"));
      await queryClient.invalidateQueries({ queryKey: ["report-mail"] });
    },
    onError: (error: Error) => {
      toast.error(
        error instanceof ApiError && error.status === 422
          ? t("reports.mail.unavailable")
          : t("errors.actionFailed"),
      );
      void queryClient.invalidateQueries({ queryKey: ["report-mail"] });
    },
  }));
  const choices: Choice[] = ["off", ...REPORT_FREQUENCIES];
</script>

<Card id="report-mail">
  <CardHeader
    title={t("reports.mail.title")}
    description={data ? t("reports.mail.description", { zone: data.timeZone }) : undefined}
  />
  {#if !data}
    <QueryStatus {query} />
  {:else}
    <form
      class="grid gap-4 px-5 pb-5"
      onsubmit={(event) => {
        event.preventDefault();
        save.mutate();
      }}
    >
      {#if !data.mailAvailable}
        <p class="text-sm text-muted-foreground" data-testid="report-mail-unavailable">
          {t("reports.mail.unavailable")}
          {#if canManageChannels}
            <a class="text-primary-text hover:underline" href={href("/settings", { section: "notifications" })}
              >{t("reports.mail.unavailableAdmin")}</a
            >
          {/if}
        </p>
      {/if}
      <fieldset class="grid gap-2" disabled={!data.mailAvailable}>
        <legend class="mb-1.5 text-sm font-medium">{t("reports.mail.frequency")}</legend>
        {#each choices as choice (choice)}
          <div class="flex items-center gap-2.5">
            <Radio id={`${id}-${choice}`} name={`${id}-frequency`} value={choice} bind:group={frequency} />
            <label for={`${id}-${choice}`}>{t(`reports.mail.${choice}`)}</label>
          </div>
        {/each}
      </fieldset>
      <div class="flex items-start gap-2.5">
        <Checkbox
          id={`${id}-attach`}
          bind:checked={attachPdf}
          disabled={!data.mailAvailable || frequency === "off"}
          aria-describedby={`${id}-attach-hint`}
          class="mt-1"
        />
        <div>
          <label for={`${id}-attach`}>{t("reports.mail.attach")}</label>
          <span id={`${id}-attach-hint`} class="block text-sm text-muted-foreground">{t("reports.mail.attachHint")}</span>
        </div>
      </div>
      <div>
        <Button type="submit" disabled={!dirty || save.isPending || !data.mailAvailable}>{t("reports.mail.save")}</Button>
      </div>
    </form>
  {/if}
</Card>
