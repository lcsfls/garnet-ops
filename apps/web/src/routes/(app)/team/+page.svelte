<script lang="ts">
  import { UserPlus, Users } from "@lucide/svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import InviteDialog from "#lib/components/team/InviteDialog.svelte";
  import TeamInvitations from "#lib/components/team/TeamInvitations.svelte";
  import TeamMembers from "#lib/components/team/TeamMembers.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import type { PageData } from "./$types";

  /** Members, roles and invitations (ADR 0009). */
  let { data }: { data: PageData } = $props();
  let inviting = $state(false);
</script>

<div class="mx-auto max-w-[72rem] @wide:max-w-[96rem]">
  <PageHeader icon={Users} title={t("team.title")} description={t("team.description")}>
    {#snippet actions()}
      <Button onclick={() => (inviting = true)}>
        <UserPlus aria-hidden="true" class="size-4" />
        {t("team.invite")}
      </Button>
    {/snippet}
  </PageHeader>
  <div class="grid items-start gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,24rem)]">
    <TeamMembers me={data.me} />
    <TeamInvitations />
  </div>
  <InviteDialog me={data.me} open={inviting} onClose={() => (inviting = false)} />
</div>
