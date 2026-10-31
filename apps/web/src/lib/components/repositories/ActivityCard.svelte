<script lang="ts">
  import { Archive } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { Me } from "../../session.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  /**
   * Setting a repository aside (ADR 0043): not used or maintained at the moment. Admins, and the owner of a private repository,
   * can do it and take it back. While set aside it shows what that means, so nobody wonders why it is quiet.
   */
  let { repo, me }: { repo: RepositoryDetail; me: Me } = $props();
  const queryClient = useQueryClient();
  const canChange = $derived(
    isAdmin(me) || (repo.mine && repo.visibility === "private" && me.role !== "viewer"),
  );
  let asking = $state(false);
  let reason = $state("");

  const change = createMutation(() => ({
    mutationFn: (active: boolean) =>
      api(`/repositories/${repo.id}/activity`, {
        method: "PUT",
        body: active ? { active } : { active, reason: reason.trim() || undefined },
      }),
    onSuccess: async (_: unknown, active: boolean) => {
      asking = false;
      reason = "";
      toast.success(t(active ? "repository.activity.reactivated" : "repository.activity.deactivated"));
      await queryClient.invalidateQueries();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

{#if repo.inactive}
  <div class="grid gap-2 rounded-xl border bg-muted/40 px-5 py-4" data-testid="repository-inactive">
    <div class="flex flex-wrap items-center gap-3">
      <Archive aria-hidden="true" class="size-5 text-muted-foreground" />
      <p class="font-medium">
        {t("repository.activity.since", { when: formatDateTime(repo.inactive.since) })}
      </p>
      {#if canChange}
        <Button variant="outline" class="ml-auto h-9" disabled={change.isPending} onclick={() => change.mutate(true)}>
          {t("repository.activity.reactivate")}
        </Button>
      {/if}
    </div>
    {#if repo.inactive.reason}
      <p class="text-sm break-words">{t("repository.activity.reason", { reason: repo.inactive.reason })}</p>
    {/if}
    <p class="text-sm text-muted-foreground">{t("repository.activity.meaning")}</p>
  </div>
{:else if canChange}
  <div class="flex justify-end">
    <Button variant="ghost" class="h-9 text-sm text-muted-foreground" onclick={() => (asking = true)}>
      <Archive aria-hidden="true" class="size-4" />
      {t("repository.activity.deactivate")}
    </Button>
  </div>
{/if}

{#if asking}
  <Dialog
    open
    onClose={() => (asking = false)}
    title={t("repository.activity.askTitle", { name: repo.name })}
    description={t("repository.activity.meaning")}
  >
    <form
      class="grid gap-4"
      onsubmit={(e) => {
        e.preventDefault();
        change.mutate(false);
      }}
    >
      <Field
        label={t("repository.activity.reasonLabel")}
        hint={t("repository.activity.reasonHint")}
        name="inactive-reason"
        bind:value={reason}
        maxlength={200}
      />
      <DialogFooter>
        <Button type="button" variant="outline" onclick={() => (asking = false)}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={change.isPending}>{t("repository.activity.deactivate")}</Button>
      </DialogFooter>
    </form>
  </Dialog>
{/if}
