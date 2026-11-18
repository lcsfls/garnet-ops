<script lang="ts">
  import {
    INVENTORY_KINDS,
    INVENTORY_LIMITS,
    type InventoryKind,
    inventoryKeyOf,
    inventoryKeySchema,
    parseSoftwareLines,
    softwareLines,
  } from "@garnetops/core/inventory";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { InventorySystem } from "../../inventory.ts";
  import { toast } from "../../toast.svelte.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import FormField from "../ui/FormField.svelte";
  import FormRow from "../ui/FormRow.svelte";
  import Select from "../ui/Select.svelte";
  import TextAreaField from "../ui/TextAreaField.svelte";

  /**
   * Adds a system to the inventory, or changes one (ADR 0053). Mounted fresh each time it opens, so the fields start from
   * `system`. The software is typed one per line; nothing here is checked against anything.
   */
  let { system, onClose }: { system: InventorySystem | null; onClose: () => void } = $props();
  const queryClient = useQueryClient();

  // svelte-ignore state_referenced_locally
  const start = system;
  let name = $state(start?.name ?? "");
  let key = $state(start?.key ?? "");
  /** A new system's key follows its name until somebody types a key. */
  let keyTyped = $state(start !== null);
  let kind = $state<InventoryKind>(start?.kind ?? "server");
  let environment = $state(start?.environment ?? "");
  let tags = $state((start?.tags ?? []).join(", "));
  let notes = $state(start?.notes ?? "");
  let software = $state(softwareLines(start?.software ?? []));
  let error = $state<string | null>(null);
  let keyError = $state<string | null>(null);
  let softwareError = $state<string | null>(null);

  $effect(() => {
    if (!keyTyped) key = inventoryKeyOf(name);
  });

  type Input = Omit<InventorySystem, "id" | "source" | "reportedAt" | "updatedAt">;
  const save = createMutation(() => ({
    mutationFn: (input: Input) =>
      start
        ? api<{ id: string }>(`/inventory/${start.id}`, { method: "PUT", body: input })
        : api<{ id: string }>("/inventory", { method: "POST", body: input }),
    onSuccess: async () => {
      toast.success(t("inventory.saved"));
      await queryClient.invalidateQueries({ queryKey: ["inventory"] });
      onClose();
    },
    onError: (e: Error) => {
      const code = e instanceof ApiError ? e.code : null;
      if (code === "inventory-key-taken") keyError = t("inventory.keyTaken");
      else error = code === "inventory-full" ? t("inventory.full") : t("errors.actionFailed");
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    keyError = inventoryKeySchema.safeParse(key).success ? null : t("inventory.keyInvalid");
    const list = parseSoftwareLines(software);
    softwareError =
      list.length > INVENTORY_LIMITS.software
        ? t("inventory.tooMuchSoftware", { max: INVENTORY_LIMITS.software })
        : null;
    if (keyError || softwareError) return;
    save.mutate({
      key,
      name,
      kind,
      environment: environment.trim() || null,
      notes: notes.trim() || null,
      tags: tags
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean),
      software: list,
    });
  }
</script>

<Dialog open onClose={onClose} title={start ? t("inventory.editTitle") : t("inventory.addTitle")}>
  <form class="grid gap-4" onsubmit={submit} data-testid="inventory-form">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {#if start?.source === "script"}<Alert tone="info">{t("inventory.scriptNote")}</Alert>{/if}
    <FormRow>
      <Field label={t("inventory.fieldName")} bind:value={name} required maxlength={INVENTORY_LIMITS.name} autocomplete="off" />
      <Field
        label={t("inventory.fieldKey")}
        hint={t("inventory.keyHint")}
        error={keyError}
        bind:value={key}
        oninput={() => (keyTyped = true)}
        required
        maxlength={INVENTORY_LIMITS.key}
        autocomplete="off"
        spellcheck={false}
        class="font-mono"
      />
    </FormRow>
    <FormRow>
      <FormField label={t("inventory.fieldKind")}>
        {#snippet children(c)}
          <Select {...c} bind:value={kind} class="w-full">
            {#each INVENTORY_KINDS as k (k)}
              <option value={k}>{t(`inventory.kind.${k}`)}</option>
            {/each}
          </Select>
        {/snippet}
      </FormField>
      <Field
        label={t("inventory.fieldEnvironment")}
        hint={t("inventory.environmentHint")}
        bind:value={environment}
        maxlength={INVENTORY_LIMITS.environment}
        autocomplete="off"
      />
    </FormRow>
    <Field label={t("inventory.fieldTags")} hint={t("inventory.tagsHint")} bind:value={tags} maxlength={600} autocomplete="off" />
    <TextAreaField
      label={t("inventory.fieldSoftware")}
      hint={t("inventory.softwareHint")}
      error={softwareError}
      bind:value={software}
      rows={7}
      spellcheck={false}
      class="font-mono text-sm"
    />
    <TextAreaField label={t("inventory.fieldNotes")} bind:value={notes} rows={3} maxlength={INVENTORY_LIMITS.notes} />
    <DialogFooter>
      <Button variant="secondary" onclick={onClose}>{t("inventory.cancel")}</Button>
      <Button variant="primary" type="submit" disabled={save.isPending}>
        {save.isPending ? t("common.loading") : t("inventory.save")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
