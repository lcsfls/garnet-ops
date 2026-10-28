<script lang="ts">
  import { KeyRound, RefreshCw } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { accountQuery } from "../../account.ts";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
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
  import BackupCodesDialog from "./BackupCodesDialog.svelte";
  import ReplaceAuthenticatorDialog from "./ReplaceAuthenticatorDialog.svelte";

  /** Account → Authenticator app: replace it (never switch it off) and renew the backup codes. */
  let { email }: { email: string } = $props();
  const queryClient = useQueryClient();
  const query = createQuery(() => accountQuery);
  const stepUp = new StepUp();
  let replacing = $state(false);
  let confirmingCodes = $state(false);
  let codes = $state<string[] | null>(null);
  let error = $state<string | null>(null);

  const renew = createMutation(() => ({
    mutationFn: () => api<{ codes: string[] }>("/account/backup-codes", { method: "POST" }),
    onSuccess: async (result: { codes: string[] }) => {
      confirmingCodes = false;
      codes = result.codes;
      await queryClient.invalidateQueries({ queryKey: ["account"] });
    },
    onError: (e: Error): void => {
      if (stepUp.handled(e, () => renew.mutate())) return;
      error = t("errors.generic");
    },
  }));
</script>

{#if !query.data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  {@const totp = query.data.secondFactor.totp}
  <Card>
    <CardHeader title={t("account.authenticator.title")} description={t("account.authenticator.description")} />
    <div class="grid gap-4 px-5 py-5">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <div class="flex flex-wrap items-center gap-3">
        <Badge tone={totp.enrolled ? "neutral" : "critical"}>
          {totp.enrolled ? t("account.authenticator.statusOn") : t("account.authenticator.statusOff")}
        </Badge>
        <Button variant="outline" onclick={() => (replacing = true)}>
          <RefreshCw aria-hidden="true" class="size-4" />
          {t("account.authenticator.replace")}
        </Button>
      </div>
      <p class="text-sm text-muted-foreground">{t("account.authenticator.required")}</p>
    </div>
  </Card>
  <Card>
    <CardHeader
      title={t("account.authenticator.codesTitle")}
      description={t("account.authenticator.codesDescription")}
    />
    <div class="flex flex-wrap items-center gap-3 px-5 py-5">
      <span data-testid="codes-left">
        {t("account.authenticator.codesLeft", { count: totp.backupCodesRemaining })}
      </span>
      <Button
        variant="outline"
        class="ml-auto"
        onclick={() => {
          error = null;
          confirmingCodes = true;
        }}
      >
        <KeyRound aria-hidden="true" class="size-4" />
        {t("account.authenticator.codesCreate")}
      </Button>
    </div>
  </Card>

  <ReplaceAuthenticatorDialog
    open={replacing}
    managed={query.data.profile.source === "directory"}
    {stepUp}
    onClose={() => (replacing = false)}
    onReplaced={async () => {
      replacing = false;
      toast.success(t("account.authenticator.replaced"));
      await queryClient.invalidateQueries({ queryKey: ["account"] });
    }}
  />
  <ConfirmDialog
    open={confirmingCodes}
    title={t("account.authenticator.codesConfirmTitle")}
    description={t("account.authenticator.codesConfirmText")}
    confirmLabel={t("account.authenticator.codesConfirm")}
    pending={renew.isPending}
    onConfirm={() => renew.mutate()}
    onClose={() => (confirmingCodes = false)}
  />
  <BackupCodesDialog {codes} onClose={() => (codes = null)} />
  <StepUpPrompt {stepUp} {email} />
{/if}
