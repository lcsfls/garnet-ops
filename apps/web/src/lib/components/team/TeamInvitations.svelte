<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDate } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import type { Invitation } from "./team.ts";

  /** Open invitations of the organisation; each can be revoked. */
  const queryClient = useQueryClient();
  const invitations = createQuery(() => ({
    queryKey: ["team-invitations"],
    queryFn: () => api<Invitation[]>("/team/invitations"),
  }));
  const revoke = createMutation(() => ({
    mutationFn: (id: string) => api(`/team/invitations/${id}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team-invitations"] }),
  }));
</script>

<Card>
  <CardHeader title={t("team.invitationsTitle")} />
  <QueryStatus query={invitations} />
  {#if invitations.data && invitations.data.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("team.invitationsEmpty")}</p>
  {/if}
  <ul class="px-5 pb-3">
    {#each invitations.data ?? [] as invitation (invitation.id)}
      <li class="flex items-start gap-3 border-t py-3 first:border-t-0">
        <div class="min-w-0 flex-1">
          <div class="font-medium break-all">{invitation.email}</div>
          <div class="text-[13px] text-muted-foreground">
            {t(`team.roles.${invitation.role}`)} · {t("team.expires", {
              date: formatDate(invitation.expiresAt),
            })}{invitation.invitedBy ? ` · ${t("team.invitedBy", { name: invitation.invitedBy })}` : ""}
          </div>
        </div>
        <Button
          variant="ghost"
          class="h-9 px-2.5"
          disabled={revoke.isPending}
          aria-label={t("team.revokeAction", { email: invitation.email })}
          onclick={() => revoke.mutate(invitation.id)}
        >
          {t("team.revoke")}
        </Button>
      </li>
    {/each}
  </ul>
  {#if revoke.isError}
    <div class="px-5 pb-4">
      <Alert tone="error">{t("errors.actionFailed")}</Alert>
    </div>
  {/if}
</Card>
