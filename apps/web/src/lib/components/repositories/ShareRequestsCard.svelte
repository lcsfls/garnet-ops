<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ShareRequest } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Button from "../ui/Button.svelte";

  /**
   * Private repositories whose owners asked to share them with the organisation (ADR 0030), for owners and admins.
   * Only the name and who asks are shown: what is in a private repository stays with its owner until it is shared.
   * Hidden while nothing waits.
   */
  const queryClient = useQueryClient();
  const requests = createQuery(() => ({
    queryKey: ["share-requests"],
    queryFn: () => api<ShareRequest[]>("/share-requests"),
  }));
  const decide = createMutation(() => ({
    mutationFn: (input: { id: string; decision: "approve" | "decline" }) =>
      api(`/share-requests/${input.id}/${input.decision}`, { method: "POST" }),
    onSuccess: async (_: unknown, input: { id: string; decision: "approve" | "decline" }) => {
      if (input.decision === "approve") toast.success(t("connections.sharedToast"));
      await queryClient.invalidateQueries();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

{#if requests.data && requests.data.length > 0}
  <Card class="mb-4" id="share-requests">
    <CardHeader title={t("connections.requestsTitle")} description={t("connections.requestsDescription")} />
    <ul>
      {#each requests.data as r (r.id)}
        <li class="flex flex-wrap items-center gap-3 border-t px-5 py-2.5">
          <div class="min-w-0 flex-1">
            <div class="font-medium">{r.name}</div>
            <div class="text-sm text-muted-foreground">
              {t("connections.requestedBy", { name: r.requestedBy ?? "–", when: formatRelative(r.requestedAt) })}
            </div>
          </div>
          <Button
            variant="outline"
            class="h-9"
            disabled={decide.isPending}
            onclick={() => decide.mutate({ id: r.id, decision: "approve" })}
          >
            {t("connections.approve")}
          </Button>
          <Button
            variant="ghost"
            class="h-9"
            disabled={decide.isPending}
            onclick={() => decide.mutate({ id: r.id, decision: "decline" })}
          >
            {t("connections.decline")}
          </Button>
        </li>
      {/each}
    </ul>
  </Card>
{/if}
