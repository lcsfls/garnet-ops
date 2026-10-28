<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import Card from "../../Card.svelte";
  import QueryStatus from "../../QueryStatus.svelte";
  import LastRuns from "./LastRuns.svelte";
  import NightlyScan from "./NightlyScan.svelte";
  import type { Organization } from "./organization.ts";

  /** Settings, Scanning: the nightly scan and its last runs. */
  let { canEdit }: { canEdit: boolean } = $props();

  const query = createQuery(() => ({
    queryKey: ["organization"],
    queryFn: () => api<Organization>("/organization"),
  }));
</script>

{#if !query.data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  <NightlyScan org={query.data} {canEdit} />
  <LastRuns runs={query.data.lastRuns} />
{/if}
