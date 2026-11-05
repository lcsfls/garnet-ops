<script lang="ts">
  import { Download, FileText } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { REPORT_RANGES, reportPdfHref } from "../../reports.ts";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Radio from "../ui/Radio.svelte";

  /**
   * The organisation's security report as PDF (ADR 0047): one button, a short dialog to pick the period (the last 7 or 30
   * days in the person's own zone), and the download. The server builds it with the person's access, so a member never
   * gets another member's private repositories.
   */
  let open = $state(false);
  let days = $state<number>(REPORT_RANGES[0]);
  const id = $props.id();
</script>

<Button variant="outline" onclick={() => (open = true)} data-testid="organization-report-open">
  <FileText aria-hidden="true" class="size-4" />
  {t("reports.organization.button")}
</Button>

<Dialog
  {open}
  onClose={() => (open = false)}
  title={t("reports.organization.dialogTitle")}
  description={t("reports.organization.dialogDescription")}
>
  <fieldset class="grid gap-2">
    <legend class="mb-1.5 text-sm font-medium">{t("reports.organization.period")}</legend>
    {#each REPORT_RANGES as range (range)}
      <div class="flex items-center gap-2.5">
        <Radio id={`${id}-${range}`} name={`${id}-days`} value={range} bind:group={days} />
        <label for={`${id}-${range}`}>{t(range === 7 ? "reports.organization.last7" : "reports.organization.last30")}</label>
      </div>
    {/each}
  </fieldset>
  <DialogFooter>
    <Button variant="outline" onclick={() => (open = false)}>{t("common.cancel")}</Button>
    <a
      href={reportPdfHref("/reports/organization", { days })}
      download
      onclick={() => (open = false)}
      data-testid="organization-report-download"
      class="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground shadow-xs hover:bg-primary-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
    >
      <Download aria-hidden="true" class="size-4" />
      {t("reports.download")}
    </a>
  </DialogFooter>
</Dialog>
