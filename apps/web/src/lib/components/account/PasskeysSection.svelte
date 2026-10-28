<script lang="ts">
  import { Fingerprint, Pencil, Plus, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { accountQuery, type PasskeyRow } from "../../account.ts";
  import { ApiError, api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { passkeysSupported } from "../../passkeys.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import AddPasskeyDialog from "./AddPasskeyDialog.svelte";
  import RenamePasskeyDialog from "./RenamePasskeyDialog.svelte";

  /** Account → Passkeys: list, add (recent sign-in), rename, remove (recent sign-in; never the last factor). */
  let { email }: { email: string } = $props();
  const queryClient = useQueryClient();
  const query = createQuery(() => accountQuery);
  const stepUp = new StepUp();
  let adding = $state(false);
  let renaming = $state<PasskeyRow | null>(null);
  let removing = $state<PasskeyRow | null>(null);
  let removeError = $state<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["account"] });

  const remove = createMutation(() => ({
    mutationFn: (id: string) => api(`/account/passkeys/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      removing = null;
      toast.success(t("account.passkeys.removed"));
      await refresh();
    },
    onError: (e: Error, id: string): void => {
      if (stepUp.handled(e, () => remove.mutate(id))) return;
      removeError =
        e instanceof ApiError && e.code === "last-second-factor"
          ? t("account.passkeys.errorLast")
          : t("errors.generic");
    },
  }));
</script>

{#if !query.data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  {@const { passkeys, passkeysAvailable, relyingParty } = query.data.secondFactor}
  {@const usable = passkeysAvailable && passkeysSupported()}
  <Card>
    <CardHeader title={t("account.passkeys.title")} description={t("account.passkeys.description")}>
      {#snippet actions()}
        {#if usable}
          <Button onclick={() => (adding = true)}>
            <Plus aria-hidden="true" class="size-4" />
            {t("account.passkeys.add")}
          </Button>
        {/if}
      {/snippet}
    </CardHeader>
    <div class="grid gap-4 px-5 pb-5">
      {#if !passkeysAvailable}<Alert tone="info">{t("account.passkeys.unavailable")}</Alert>{/if}
      {#if passkeysAvailable && !passkeysSupported()}
        <Alert tone="info">{t("account.passkeys.errorUnsupported")}</Alert>
      {/if}
      {#if passkeys.length === 0}
        <p class="text-muted-foreground">{t("account.passkeys.empty")}</p>
      {:else}
        <ul class="grid gap-2">
          {#each passkeys as p (p.id)}
            <li
              data-testid="passkey"
              class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border px-3 py-2.5"
            >
              <Fingerprint aria-hidden="true" class="size-5 flex-none text-muted-foreground" />
              <div class="min-w-0 flex-[1_1_14rem]">
                <div class="truncate font-medium">{p.name ?? t("account.passkeys.unnamed")}</div>
                <div class="text-sm text-muted-foreground">
                  {p.createdAt ? t("account.passkeys.created", { date: formatDateTime(p.createdAt) }) : ""}{" · "}{p.lastUsedAt
                    ? t("account.passkeys.lastUsed", { date: formatDateTime(p.lastUsedAt) })
                    : t("account.passkeys.neverUsed")}
                </div>
              </div>
              <Badge tone="neutral">
                {p.backedUp ? t("account.passkeys.synced") : t("account.passkeys.deviceBound")}
              </Badge>
              <div class="flex gap-1.5">
                <Button variant="outline" class="h-9 px-3 text-sm" onclick={() => (renaming = p)}>
                  <Pencil aria-hidden="true" class="size-3.5" />
                  {t("account.passkeys.rename")}
                </Button>
                <Button
                  variant="destructive"
                  class="h-9 px-3 text-sm"
                  onclick={() => {
                    removeError = null;
                    removing = p;
                  }}
                >
                  <Trash2 aria-hidden="true" class="size-3.5" />
                  {t("account.passkeys.remove")}
                </Button>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
      {#if passkeysAvailable}
        <p class="text-sm text-muted-foreground">
          {t("account.passkeys.bound", { domain: relyingParty })}
        </p>
      {/if}
    </div>
  </Card>

  <AddPasskeyDialog
    open={adding}
    {stepUp}
    onClose={() => (adding = false)}
    onAdded={async () => {
      adding = false;
      toast.success(t("account.passkeys.added"));
      await refresh();
    }}
  />
  <RenamePasskeyDialog
    passkey={renaming}
    onClose={() => (renaming = null)}
    onRenamed={async () => {
      renaming = null;
      await refresh();
    }}
  />
  <ConfirmDialog
    open={removing !== null}
    title={t("account.passkeys.removeTitle")}
    description={t("account.passkeys.removeText", {
      name: removing?.name ?? t("account.passkeys.unnamed"),
    })}
    confirmLabel={t("account.passkeys.removeConfirm")}
    pending={remove.isPending}
    error={removeError}
    onConfirm={() => removing && remove.mutate(removing.id)}
    onClose={() => (removing = null)}
  />
  <StepUpPrompt {stepUp} {email} />
{/if}
