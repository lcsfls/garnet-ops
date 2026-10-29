<script lang="ts">
  import { Lock, Users } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { Me } from "../../session.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import Button from "../ui/Button.svelte";

  /**
   * Who sees a repository (ADR 0030). Its owner sees "Private" with Share (owners and admins share at once, members
   * ask); an admin can make a shared repository that came from a connected account private again for its owner.
   */
  let { repo, me }: { repo: RepositoryDetail; me: Me } = $props();

  const queryClient = useQueryClient();
  const admin = $derived(isAdmin(me));
  const change = createMutation(() => ({
    mutationFn: (action: "share" | "unshare") =>
      api<{ visibility: string; shareRequested: boolean }>(`/repositories/${repo.id}/${action}`, {
        method: "POST",
      }),
    onSuccess: async (result: { visibility: string; shareRequested: boolean }) => {
      toast.success(
        result.visibility === "organization"
          ? t("connections.sharedToast")
          : result.shareRequested
            ? t("connections.requestedToast")
            : t("connections.unsharedToast"),
      );
      await queryClient.invalidateQueries();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

{#if repo.visibility === "private"}
  <div class="flex flex-wrap items-center gap-3 rounded-xl border bg-card px-5 py-3" data-testid="repository-sharing">
    <Lock aria-hidden="true" class="size-4 text-muted-foreground" />
    <div class="min-w-0 flex-1">
      <div class="font-medium">{t("connections.private")}</div>
      <div class="text-sm text-muted-foreground">{t("connections.privateHint")}</div>
    </div>
    {#if repo.mine && me.role !== "viewer"}
      {#if repo.shareRequested && !admin}
        <Button variant="outline" disabled>{t("connections.shareRequested")}</Button>
      {:else}
        <Button variant="outline" disabled={change.isPending} onclick={() => change.mutate("share")}>
          <Users aria-hidden="true" class="size-4" />
          {admin ? t("connections.share") : t("connections.askToShare")}
        </Button>
      {/if}
    {/if}
  </div>
{:else if admin && repo.authKind === "connection"}
  <div class="flex justify-end">
    <Button variant="ghost" class="h-9" disabled={change.isPending} onclick={() => change.mutate("unshare")}>
      <Lock aria-hidden="true" class="size-4" />
      {t("connections.unshare")}
    </Button>
  </div>
{/if}
