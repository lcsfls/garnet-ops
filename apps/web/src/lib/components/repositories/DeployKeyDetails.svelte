<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { RepositoryRow } from "../../types.ts";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import DeployKeyInstructions from "./DeployKeyInstructions.svelte";

  /** The public deploy key with instructions, and the pinned host keys. */
  let { repo, canReset }: { repo: RepositoryRow; canReset: boolean } = $props();

  const queryClient = useQueryClient();
  let confirmReset = $state(false);
  const reset = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}/ssh-host-keys`, { method: "DELETE" }),
    onSuccess: async () => {
      confirmReset = false;
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
    },
  }));
</script>

<div class="grid gap-5">
  <DeployKeyInstructions publicKey={repo.deployPublicKey ?? ""} />
  <section class="grid gap-2" aria-labelledby="host-keys-{repo.id}">
    <h3 id="host-keys-{repo.id}" class="text-sm font-medium">{t("repositories.hostKeys")}</h3>
    {#if repo.sshHostKeys}
      <ul class="grid gap-1">
        {#each repo.sshHostKeys.keys as key (key.fingerprint)}
          <li class="break-all font-mono text-sm">{key.type} {key.fingerprint}</li>
        {/each}
      </ul>
      <p class="text-sm text-muted-foreground">
        {t("repositories.hostKeysPinned", { when: formatDateTime(repo.sshHostKeys.pinnedAt) })}
      </p>
      {#if canReset}
        <div>
          <Button
            variant="outline"
            disabled={reset.isPending}
            onclick={() => {
              reset.reset();
              confirmReset = true;
            }}
          >
            {t("repositories.hostKeysReset")}
          </Button>
          <ConfirmDialog
            open={confirmReset}
            title={t("repositories.hostKeysResetTitle")}
            description={t("repositories.hostKeysResetDescription")}
            confirmLabel={t("repositories.hostKeysReset")}
            pending={reset.isPending}
            error={reset.isError ? t("errors.actionFailed") : null}
            onConfirm={() => reset.mutate()}
            onClose={() => (confirmReset = false)}
          />
        </div>
      {/if}
    {:else}
      <p class="text-sm text-muted-foreground">{t("repositories.hostKeysNone")}</p>
    {/if}
  </section>
</div>
