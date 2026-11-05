<script lang="ts">
  import { Download } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import ButtonLink from "../ui/ButtonLink.svelte";

  /**
   * Downloads a report as PDF. A plain link: the server builds the file with the signed-in person's access, so there is
   * nothing to wait for on the page. `label` names what is downloaded for screen readers when the text alone is not enough.
   */
  let { href, label, testid }: { href: string; label?: string; testid?: string } = $props();
</script>

<ButtonLink {href} download aria-label={label} data-testid={testid}>
  <Download aria-hidden="true" class="size-4" />
  {t("reports.download")}
</ButtonLink>
