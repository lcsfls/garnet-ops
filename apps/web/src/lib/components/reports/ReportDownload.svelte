<script lang="ts">
  import { Download } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";

  /**
   * Downloads a report as PDF. A plain link: the server builds the file with the signed-in person's access, so there is
   * nothing to wait for on the page. `label` names what is downloaded for screen readers when the text alone is not enough.
   */
  let { href, label, testid }: { href: string; label?: string; testid?: string } = $props();
</script>

<a
  {href}
  download
  aria-label={label}
  data-testid={testid}
  class="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium whitespace-nowrap shadow-xs hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
>
  <Download aria-hidden="true" class="size-4" />
  {t("reports.download")}
</a>
