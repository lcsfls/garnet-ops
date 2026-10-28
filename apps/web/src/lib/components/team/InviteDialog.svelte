<script lang="ts">
  import { ROLES, type Role } from "@garnetops/core";
  import { canAssignRole } from "@garnetops/core/team";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDate } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import Radio from "../ui/Radio.svelte";
  import { explainTeamError } from "./team.ts";

  type InviteInput = { email: string; role: Role };

  /** Creates an invitation link for an address and a role the inviter may assign. */
  let { me, open, onClose }: { me: Me; open: boolean; onClose: () => void } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const roles = $derived(ROLES.filter((r) => canAssignRole(me.role, r)));
  let role = $state<Role>("member");
  let result = $state<{ link: string; email: string; expiresAt: string } | null>(null);
  let error = $state<string | null>(null);
  const create = createMutation(() => ({
    mutationFn: (input: InviteInput) =>
      api<{ link: string; expiresAt: string }>("/team/invitations", { method: "POST", body: input }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async (data: { link: string; expiresAt: string }, input: InviteInput) => {
      result = { link: data.link, email: input.email, expiresAt: data.expiresAt };
      toast.success(t("toast.invitationCreated"));
      await queryClient.invalidateQueries({ queryKey: ["team-invitations"] });
    },
    onError: (e: Error, input: InviteInput): void => {
      if (!stepUp.handled(e, () => create.mutate(input))) error = explainTeamError(e);
    },
  }));
  function close() {
    result = null;
    error = null;
    role = "member";
    onClose();
  }
  function submit(event: SubmitEvent) {
    event.preventDefault();
    const email = String(new FormData(event.currentTarget as HTMLFormElement).get("email") ?? "")
      .trim()
      .toLowerCase();
    create.mutate({ email, role });
  }
</script>

<Dialog {open} onClose={close} title={t("team.inviteTitle")} description={t("team.inviteDescription")}>
  {#if result}
    <div class="grid gap-3">
      <label for="invite-link" class="text-sm font-medium">
        {t("team.inviteLink")}
      </label>
      <textarea
        id="invite-link"
        readonly
        rows={3}
        value={result.link}
        onfocus={(e) => e.currentTarget.select()}
        class="w-full resize-none break-all rounded-md border border-input bg-muted px-3 py-2 font-mono text-sm"
      ></textarea>
      <div>
        <CopyButton text={result.link} />
      </div>
      <p class="text-sm text-muted-foreground">
        {t("team.inviteLinkHint", { email: result.email, date: formatDate(result.expiresAt) })}
      </p>
      <DialogFooter>
        <Button onclick={close}>{t("common.close")}</Button>
      </DialogFooter>
    </div>
  {:else}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Field label={t("team.inviteEmail")} name="email" type="email" required autocomplete="off" maxlength={254} />
      <fieldset class="grid gap-2">
        <legend class="mb-1.5 text-sm font-medium">{t("team.inviteRole")}</legend>
        {#each roles as r (r)}
          <div class="flex items-start gap-2.5">
            <Radio
              id={`invite-role-${r}`}
              name="role"
              value={r}
              bind:group={role}
              aria-describedby={`invite-role-${r}-hint`}
              class="mt-1"
            />
            <div>
              <label for={`invite-role-${r}`}>{t(`team.roles.${r}`)}</label>
              <span id={`invite-role-${r}-hint`} class="block text-sm text-muted-foreground">
                {t(`team.roleHint.${r}`)}
              </span>
            </div>
          </div>
        {/each}
      </fieldset>
      <DialogFooter>
        <Button variant="outline" onclick={close}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? t("common.loading") : t("team.inviteSubmit")}
        </Button>
      </DialogFooter>
    </form>
  {/if}
</Dialog>
<StepUpPrompt {stepUp} email={me.user.email} />
