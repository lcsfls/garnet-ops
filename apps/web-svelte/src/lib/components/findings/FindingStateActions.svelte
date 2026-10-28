<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { addLocalDays, endOfLocalDay, localDateInput } from "../../dates.ts";
  import { formatDate } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { FindingDetail } from "../../types.ts";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  let { data }: { data: FindingDetail } = $props();
  const queryClient = useQueryClient();
  let errors = $state<Record<string, string>>({});
  let accepting = $state(false);
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["findings"] }),
      queryClient.invalidateQueries({ queryKey: ["finding", data.id] }),
      queryClient.invalidateQueries({ queryKey: ["overview"] }),
      queryClient.invalidateQueries({ queryKey: ["finding-counts"] }),
    ]);

  const accept = createMutation(() => ({
    mutationFn: (body: { reason: string; until: string }) =>
      api(`/findings/${data.id}/accept`, { method: "POST", body }),
    onSuccess: async () => {
      accepting = false;
      await refresh();
    },
    onError: (e: Error) => {
      if (e instanceof ApiError && e.status === 422) {
        errors = Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path, x.message]));
      }
    },
  }));
  const reopen = createMutation(() => ({
    mutationFn: () => api(`/findings/${data.id}/reopen`, { method: "POST" }),
    onSuccess: refresh,
  }));

  // Calendar days in the browser's zone; never UTC dates (which are a day off around midnight).
  // Taken when the dialog opens, so a page left open over midnight still offers the right days.
  const days = $derived.by(() => {
    void accepting;
    const today = new Date();
    return {
      defaultUntil: localDateInput(addLocalDays(today, 90)),
      minUntil: localDateInput(addLocalDays(today, 1)),
      maxUntil: localDateInput(addLocalDays(today, 365)),
    };
  });

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    errors = {};
    // "Until 19 January" means through the whole of that local day, sent as an exact instant.
    accept.mutate({
      reason: String(form.get("reason")).trim(),
      until: endOfLocalDay(String(form.get("until"))).toISOString(),
    });
  }
</script>

{#if data.state === "accepted"}
  <div class="grid gap-3 border-t pt-4">
    <p class="text-sm">
      <span class="font-medium">
        {t("findings.acceptedBy", {
          // The stored instant is the first moment after the chosen day; show the day itself.
          date: data.acceptedUntil ? formatDate(new Date(new Date(data.acceptedUntil).getTime() - 1)) : "",
        })}
      </span>
      {#if data.acceptedReason}<span class="mt-1 block whitespace-pre-line">{data.acceptedReason}</span>{/if}
    </p>
    <Button variant="outline" class="justify-self-start" disabled={reopen.isPending} onclick={() => reopen.mutate()}>
      {t("findings.reopen")}
    </Button>
  </div>
{:else if data.state === "open"}
  <div class="border-t pt-4">
    <Button variant="ghost" onclick={() => (accepting = true)}>{t("findings.acceptOpen")}</Button>
    <Dialog
      open={accepting}
      onClose={() => (accepting = false)}
      title={t("findings.acceptTitle", { id: data.vulnerability.id })}
      description={t("findings.acceptDescription")}
    >
      <form class="grid gap-4" onsubmit={submit}>
        <div class="grid gap-1.5">
          <label for="accept-reason" class="text-sm font-medium">{t("findings.acceptReason")}</label>
          <textarea
            id="accept-reason"
            name="reason"
            required
            minlength={10}
            maxlength={1000}
            rows={3}
            aria-describedby="accept-reason-hint"
            class="rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs"
          ></textarea>
          <p id="accept-reason-hint" class="text-sm text-muted-foreground">
            {errors.reason ?? t("findings.acceptReasonHint")}
          </p>
        </div>
        <Field
          label={t("findings.acceptUntil")}
          hint={t("findings.acceptUntilHint")}
          error={errors.until}
          name="until"
          type="date"
          required
          value={days.defaultUntil}
          min={days.minUntil}
          max={days.maxUntil}
        />
        <DialogFooter>
          <Button variant="outline" onclick={() => (accepting = false)}>{t("common.cancel")}</Button>
          <Button type="submit" disabled={accept.isPending}>{t("findings.accept")}</Button>
        </DialogFooter>
      </form>
    </Dialog>
  </div>
{/if}
