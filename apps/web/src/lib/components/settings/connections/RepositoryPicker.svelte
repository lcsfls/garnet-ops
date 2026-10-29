<script lang="ts">
  import { Lock } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { ConnectionRepository, ForgeConnection } from "../../../types.ts";
  import QueryStatus from "../../QueryStatus.svelte";
  import SearchInput from "../../SearchInput.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";

  /** At most this many repositories in one request (the API's limit). */
  const PICK_LIMIT = 100;

  /**
   * The repositories a connected account can see, each with a checkbox (ADR 0030). Ones that are already monitored
   * cannot be picked again. The chosen ones are added private to the person and scanned at once.
   */
  let { connection, onClose }: { connection: ForgeConnection; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  let filter = $state("");
  let chosen = $state(new Set<string>());
  const list = createQuery(() => ({
    queryKey: ["forge-connection-repositories", connection.id],
    queryFn: () =>
      api<{ connection: ForgeConnection; items: ConnectionRepository[] }>(
        `/forge-connections/${connection.id}/repositories`,
      ),
  }));
  const shown = $derived(
    (list.data?.items ?? []).filter((r) => {
      const q = filter.trim().toLowerCase();
      return !q || r.fullName.toLowerCase().includes(q) || (r.description ?? "").toLowerCase().includes(q);
    }),
  );
  const free = $derived(shown.filter((r) => r.added === null));

  function toggle(id: string, on: boolean) {
    const next = new Set(chosen);
    if (on) next.add(id);
    else next.delete(id);
    chosen = next;
  }

  const add = createMutation(() => ({
    mutationFn: () =>
      api<{ created: { id: string; name: string }[]; skipped: unknown[] }>(
        `/forge-connections/${connection.id}/repositories`,
        { method: "POST", body: { forgeIds: [...chosen] } },
      ),
    onSuccess: async (result: { created: { id: string; name: string }[] }) => {
      toast.success(t("connections.addedToast", { count: result.created.length }));
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["repositories"] }),
        queryClient.invalidateQueries({ queryKey: ["forge-connection-repositories", connection.id] }),
      ]);
      onClose();
    },
  }));
</script>

<Dialog
  open
  {onClose}
  title={t("connections.pickerTitle")}
  description={t("connections.pickerDescription")}
>
  <form
    class="grid gap-3"
    onsubmit={(e) => {
      e.preventDefault();
      if (chosen.size > 0) add.mutate();
    }}
  >
    {#if add.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
    <div class="flex flex-wrap items-center gap-2">
      <SearchInput label={t("connections.filter")} value={filter} onChange={(q) => (filter = q)} />
      <Button
        variant="ghost"
        class="h-9"
        disabled={free.length === 0}
        onclick={() => (chosen = new Set([...chosen, ...free.slice(0, PICK_LIMIT).map((r) => r.forgeId)]))}
      >
        {t("connections.selectShown")}
      </Button>
      <Button variant="ghost" class="h-9" disabled={chosen.size === 0} onclick={() => (chosen = new Set())}>
        {t("connections.clearSelection")}
      </Button>
    </div>
    <QueryStatus query={list} />
    {#if list.data}
      {#if list.data.items.length === 0}
        <p class="text-muted-foreground">{t("connections.nothingListed")}</p>
      {:else if shown.length === 0}
        <p class="text-muted-foreground">{t("connections.noMatch")}</p>
      {/if}
      {#if list.data.connection.truncated}<Alert tone="info">{t("connections.truncated")}</Alert>{/if}
      <ul class="max-h-[min(28rem,55dvh)] overflow-y-auto rounded-md border" data-testid="repository-picker">
        {#each shown as r (r.forgeId)}
          <li class="border-t first:border-t-0">
            <label
              class="flex cursor-pointer items-start gap-3 px-3 py-2.5 has-[:disabled]:cursor-default hover:bg-muted/50"
            >
              <Checkbox
                class="mt-0.5"
                checked={r.added !== null || chosen.has(r.forgeId)}
                disabled={r.added !== null || (!chosen.has(r.forgeId) && chosen.size >= PICK_LIMIT)}
                onchange={(e) => toggle(r.forgeId, e.currentTarget.checked)}
              />
              <span class="min-w-0 flex-1">
                <span class="flex flex-wrap items-center gap-2">
                  <span class="font-mono text-[14px] break-all">{r.fullName}</span>
                  {#if r.private}
                    <Badge tone="neutral"><Lock aria-hidden="true" />{t("connections.privateOnForge")}</Badge>
                  {/if}
                  {#if r.archived}<Badge tone="neutral">{t("connections.archived")}</Badge>{/if}
                  {#if r.added && "repositoryId" in r.added}
                    <Badge tone="info">{t("connections.added")}</Badge>
                  {:else if r.added}
                    <Badge tone="neutral" class="cursor-help">
                      <span title={t("connections.monitoredHint")}>{t("connections.monitored")}</span>
                    </Badge>
                  {/if}
                </span>
                {#if r.description}
                  <span class="block truncate text-[13px] text-muted-foreground">{r.description}</span>
                {/if}
              </span>
            </label>
          </li>
        {/each}
      </ul>
    {/if}
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
      <Button type="submit" disabled={add.isPending || chosen.size === 0}>
        {add.isPending ? t("connections.adding") : t("connections.addSelected", { count: chosen.size })}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
