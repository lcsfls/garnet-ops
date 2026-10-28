<script lang="ts">
  import type { DirectoryServerView } from "../../../directory.ts";
  import { t } from "../../../i18n.svelte.ts";
  import Badge from "../../ui/Badge.svelte";

  let { server }: { server: DirectoryServerView } = $props();
  const status = $derived(server.certificate?.status);
</script>

{#if status}
  <Badge tone={status === "changed" ? "critical" : status === "pending" ? "medium" : "neutral"}>
    {t(`directory.certStatus.${status}`)}
  </Badge>
{/if}
