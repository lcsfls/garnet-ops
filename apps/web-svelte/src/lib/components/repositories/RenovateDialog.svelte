<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import QueryStatus from "../QueryStatus.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";

  /** A renovate.json for teams that run their own Renovate. GarnetOps never runs or bundles it. */
  let { repositoryId, open, onClose }: { repositoryId: string; open: boolean; onClose: () => void } = $props();

  const query = createQuery(() => ({
    queryKey: ["renovate-config", repositoryId],
    queryFn: () => api<{ packages: number; json: string }>(`/repositories/${repositoryId}/renovate-config`),
    enabled: open,
  }));
</script>

<Dialog {open} {onClose} title={t("repository.renovate.title")} description={t("repository.renovate.description")}>
  <div class="grid gap-3">
    {#if query.isError}<Alert tone="error">{t("repository.renovate.failed")}</Alert>{/if}
    {#if query.data}
      <p class="text-sm text-muted-foreground">
        {query.data.packages === 0
          ? t("repository.renovate.empty")
          : t("repository.renovate.packages", { count: query.data.packages })}
      </p>
      <textarea
        readonly
        rows={14}
        spellcheck={false}
        aria-label={t("repository.renovate.title")}
        value={query.data.json}
        class="max-h-72 w-full resize-none rounded-md border bg-muted/40 p-3 font-mono text-[13px]"
      ></textarea>
    {:else}
      <QueryStatus {query} class="min-h-0 px-0 py-2" />
    {/if}
    <DialogFooter>
      {#if query.data}<CopyButton text={query.data.json} />{/if}
      <Button variant="outline" onclick={onClose}>{t("common.close")}</Button>
    </DialogFooter>
  </div>
</Dialog>
