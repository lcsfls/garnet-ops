<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import type { Me } from "../../session.ts";
  import type { AiSettings } from "../../types.ts";
  import Card from "../Card.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import AiForm from "./ai/AiForm.svelte";

  /** Settings, AI (owners and admins): the model endpoint, its limits, and the switch (ADR 0013). */
  let { me }: { me: Me } = $props();

  const query = createQuery(() => ({
    queryKey: ["ai-settings"],
    queryFn: () => api<AiSettings>("/ai/settings"),
  }));
</script>

{#if !query.data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  <AiForm stored={query.data.configured ? query.data : null} {me} />
{/if}
