<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { InventorySystem } from "../../inventory.ts";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";

  /** Everything the inventory holds about one system (ADR 0053): its fields and its whole software list. */
  let {
    system,
    canEdit,
    onEdit,
    onClose,
  }: { system: InventorySystem; canEdit: boolean; onEdit: () => void; onClose: () => void } = $props();
</script>

<Dialog open onClose={onClose} title={system.name}>
  <div class="grid gap-4" data-testid="inventory-details">
    <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
      <dt class="text-muted-foreground">{t("inventory.fieldKey")}</dt>
      <dd class="font-mono break-all">{system.key}</dd>
      <dt class="text-muted-foreground">{t("inventory.fieldKind")}</dt>
      <dd>{t(`inventory.kind.${system.kind}`)}</dd>
      {#if system.environment}
        <dt class="text-muted-foreground">{t("inventory.fieldEnvironment")}</dt>
        <dd>{system.environment}</dd>
      {/if}
      {#if system.tags.length > 0}
        <dt class="text-muted-foreground">{t("inventory.fieldTags")}</dt>
        <dd class="flex flex-wrap gap-1">
          {#each system.tags as tag (tag)}<Badge tone="outline">{tag}</Badge>{/each}
        </dd>
      {/if}
      <dt class="text-muted-foreground">{t("inventory.columnSource")}</dt>
      <dd>
        {t(`inventory.source.${system.source}`)}{#if system.reportedAt}, <span title={formatDateTime(system.reportedAt)}
            >{t("inventory.reported", { when: formatRelative(system.reportedAt) })}</span
          >{/if}
      </dd>
      <dt class="text-muted-foreground">{t("inventory.columnChanged")}</dt>
      <dd>{formatDateTime(system.updatedAt)}</dd>
    </dl>
    {#if system.notes}
      <div>
        <h3 class="mb-1 text-sm font-medium">{t("inventory.fieldNotes")}</h3>
        <p class="text-sm whitespace-pre-line">{system.notes}</p>
      </div>
    {/if}
    <div>
      <h3 class="mb-1 text-sm font-medium">{t("inventory.softwareAll", { count: system.software.length })}</h3>
      {#if system.software.length === 0}
        <p class="text-sm text-muted-foreground">{t("inventory.noSoftware")}</p>
      {:else}
        <div class="max-h-72 overflow-y-auto rounded-md border">
          <table class="w-full text-left text-sm">
            <thead class="sr-only">
              <tr><th>{t("inventory.columnSoftwareName")}</th><th>{t("inventory.columnVersion")}</th></tr>
            </thead>
            <tbody>
              {#each system.software as item (`${item.name} ${item.version}`)}
                <tr class="border-b last:border-0">
                  <td class="px-3 py-1.5 font-mono break-all">{item.name}</td>
                  <td class="px-3 py-1.5 font-mono break-all text-muted-foreground">{item.version}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="mt-2 text-sm text-muted-foreground">{t("inventory.notChecked")}</p>
    </div>
    <DialogFooter>
      {#if canEdit}<Button variant="secondary" onclick={onEdit}>{t("inventory.edit", { name: system.name })}</Button>{/if}
      <Button variant="primary" onclick={onClose}>{t("common.close")}</Button>
    </DialogFooter>
  </div>
</Dialog>
