<script lang="ts">
  import {
    DIRECTORY_LIMITS,
    DIRECTORY_ROLES,
    type DirectoryRole,
    type GroupRole,
  } from "@garnetops/core/directory";
  import { Plus, Trash2 } from "@lucide/svelte";
  import { t } from "../../../i18n.svelte.ts";
  import Button from "../../ui/Button.svelte";
  import Select from "../../ui/Select.svelte";

  let {
    rows,
    onChange,
    error,
    invalid,
  }: {
    rows: GroupRole[];
    onChange: (rows: GroupRole[]) => void;
    error: string | null;
    invalid: number[];
  } = $props();

  const update = (index: number, patch: Partial<GroupRole>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
</script>

<div class="grid gap-2">
  <span class="text-sm font-medium">{t("directory.groupRoles")}</span>
  <p class="text-sm text-muted-foreground">{t("directory.groupRolesHint")}</p>
  {#if error}<p class="text-sm text-destructive-text">{error}</p>{/if}
  <ul class="grid gap-2">
    <!-- Rows have no identity of their own and are only edited in place, so they are keyed by position. -->
    {#each rows as row, index (index)}
      <li class="flex flex-wrap items-center gap-2" data-testid="group-role">
        <input
          aria-label={t("directory.groupDn", { number: index + 1 })}
          aria-invalid={invalid.includes(index) ? true : undefined}
          bind:value={() => row.dn, (value) => update(index, { dn: value })}
          placeholder="CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan"
          autocapitalize="off"
          autocomplete="off"
          spellcheck={false}
          class="h-10 min-w-0 flex-[1_1_16rem] rounded-md border border-input bg-card px-3 font-mono text-sm shadow-xs aria-invalid:border-destructive"
        />
        <Select
          aria-label={t("directory.groupRole", { number: index + 1 })}
          bind:value={() => row.role, (value) => update(index, { role: value as DirectoryRole })}
          class="w-36 flex-none"
        >
          {#each DIRECTORY_ROLES as role (role)}
            <option value={role}>{t(`team.roles.${role}`)}</option>
          {/each}
        </Select>
        <Button
          variant="ghost"
          class="h-9 px-2.5"
          disabled={rows.length <= 1}
          aria-label={t("directory.removeGroup", { number: index + 1 })}
          onclick={() => onChange(rows.filter((_, i) => i !== index))}
        >
          <Trash2 aria-hidden="true" class="size-4" />
        </Button>
      </li>
    {/each}
  </ul>
  <div>
    <Button
      variant="outline"
      class="h-9"
      disabled={rows.length >= DIRECTORY_LIMITS.maxGroupRoles}
      onclick={() => onChange([...rows, { dn: "", role: "member" }])}
    >
      <Plus aria-hidden="true" class="size-4" />
      {t("directory.addGroup")}
    </Button>
  </div>
</div>
