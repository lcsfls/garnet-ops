<script lang="ts">
  import { ROLES, type Role } from "@garnetops/core";
  import { canAssignRole, canManageMember } from "@garnetops/core/team";
  import { Link2, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { directoryQuery } from "../../directory.ts";
  import { formatDate, formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import Select from "../ui/Select.svelte";
  import LinkDirectoryDialog from "./LinkDirectoryDialog.svelte";
  import { explainTeamError, type Member } from "./team.ts";

  /** The members of the organisation with their roles (ADR 0009). */
  let { me }: { me: Me } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const members = createQuery(() => ({
    queryKey: ["team-members"],
    queryFn: () => api<Member[]>("/team/members"),
  }));
  let removing = $state<Member | null>(null);
  let linking = $state<Member | null>(null);
  let error = $state<string | null>(null);
  // A refused role change leaves the role as it was; a native select keeps what was picked, so it is mounted afresh.
  let roleResets = $state(0);
  // Only owners see the directory settings, and only they may link an account (ADR 0020).
  const directory = createQuery(() => ({ ...directoryQuery, enabled: me.role === "owner" }));
  const canLink = $derived(me.role === "owner" && directory.data?.settings?.enabled === true);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["team-members"] });

  const changeRole = createMutation(() => ({
    mutationFn: (input: { userId: string; role: Role }) =>
      api(`/team/members/${input.userId}`, { method: "PATCH", body: { role: input.role } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => refresh(),
    onError: (e: Error, input: { userId: string; role: Role }): void => {
      if (!stepUp.handled(e, () => changeRole.mutate(input))) error = explainTeamError(e);
      roleResets += 1;
      void refresh();
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: (userId: string) => api(`/team/members/${userId}`, { method: "DELETE" }),
    onSuccess: async () => {
      removing = null;
      await refresh();
    },
    onError: (e: Error, userId: string): void => {
      if (stepUp.handled(e, () => remove.mutate(userId))) removing = null;
    },
  }));
</script>

<Card>
  <CardHeader title={t("team.membersTitle")} description={t("team.membersDescription")} />
  <QueryStatus query={members} />
  {#if error}
    <div class="px-5 pb-3">
      <Alert tone="error">{error}</Alert>
    </div>
  {/if}
  {#if members.data}
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("team.columnPerson")}</th>
          <th class="px-3 py-2.5 font-medium">{t("team.columnRole")}</th>
          <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("team.columnSource")}</th>
          <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">
            {t("team.columnSecondFactor")}
          </th>
          <th class="hidden px-3 py-2.5 font-medium @5xl:table-cell">{t("team.columnLastSignIn")}</th>
          <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("team.columnJoined")}</th>
          <th class="w-14 px-5 py-2.5">
            <span class="sr-only">{t("repositories.columnActions")}</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {#each members.data as member (member.userId)}
          {@const self = member.userId === me.user.id}
          {@const managed = member.source === "directory"}
          <!-- A directory account's role and access come from its groups; changing them here would be undone at the next sign-in. -->
          {@const manageable = !self && !managed && canManageMember(me.role, member.role)}
          <tr class="border-b align-top last:border-0">
            <td class="px-5 py-3">
              <div class="font-medium">
                {member.name}{#if self}<span class="ml-1.5 font-normal text-muted-foreground"
                    >({t("team.you")})</span
                  >{/if}
              </div>
              <div class="text-sm break-all text-muted-foreground">{member.email}</div>
              <!-- Narrow screens: the source and the second factor move here instead of disappearing. -->
              <div class="mt-1 flex flex-wrap gap-1.5 @3xl:hidden">
                <Badge tone={managed ? "info" : "neutral"}>
                  {managed ? t("team.sourceDirectory") : t("team.sourceLocal")}
                </Badge>
                {#if !member.twoFactorEnabled}
                  <Badge tone="medium">{t("team.secondFactorPending")}</Badge>
                {/if}
              </div>
            </td>
            <td class="px-3 py-3">
              {#if manageable}
                {#key roleResets}
                  <Select
                    aria-label={t("team.roleOf", { name: member.name })}
                    value={member.role}
                    disabled={changeRole.isPending}
                    onchange={(e) =>
                      changeRole.mutate({ userId: member.userId, role: e.currentTarget.value as Role })}
                    class="max-w-40"
                  >
                    {#each ROLES.filter((r) => canAssignRole(me.role, r)) as r (r)}
                      <option value={r}>{t(`team.roles.${r}`)}</option>
                    {/each}
                  </Select>
                {/key}
              {:else if managed}
                <!-- Read only: the groups in the directory decide, and the next sign-in would undo a change. -->
                <Select
                  aria-label={t("team.roleOf", { name: member.name })}
                  aria-describedby={`role-from-groups-${member.userId}`}
                  value={member.role}
                  disabled
                  class="max-w-40"
                >
                  <option value={member.role}>{t(`team.roles.${member.role}`)}</option>
                </Select>
                <div
                  id={`role-from-groups-${member.userId}`}
                  class="mt-1 max-w-48 text-[13px] text-muted-foreground"
                  data-testid="role-from-groups"
                >
                  {t("team.roleFromGroups")}
                </div>
              {:else}
                <Badge tone="neutral">{t(`team.roles.${member.role}`)}</Badge>
              {/if}
            </td>
            <td class="hidden px-3 py-3 @3xl:table-cell">
              <Badge tone={managed ? "info" : "neutral"}>
                {managed ? t("team.sourceDirectory") : t("team.sourceLocal")}
              </Badge>
            </td>
            <td class="hidden px-3 py-3 @3xl:table-cell">
              <Badge tone={member.twoFactorEnabled ? "neutral" : "medium"}>
                {member.twoFactorEnabled ? t("team.secondFactorOn") : t("team.secondFactorPending")}
              </Badge>
            </td>
            <td class="hidden px-3 py-3 text-sm @5xl:table-cell">
              {#if member.lastSignInAt}
                <time datetime={member.lastSignInAt} title={formatDateTime(member.lastSignInAt)} class="dash-time"
                  >{formatRelative(member.lastSignInAt)}</time
                >
              {:else}
                <span class="text-muted-foreground">{t("team.never")}</span>
              {/if}
            </td>
            <td class="hidden px-3 py-3 text-sm @wide:table-cell">{formatDate(member.joinedAt)}</td>
            <td class="px-5 py-2 text-right whitespace-nowrap">
              {#if canLink && !self && !managed && member.role !== "owner"}
                <Button
                  variant="ghost"
                  class="h-9 px-2.5"
                  aria-label={t("team.linkAction", { name: member.name })}
                  title={t("team.link")}
                  onclick={() => (linking = member)}
                >
                  <Link2 aria-hidden="true" class="size-4" />
                </Button>
              {/if}
              {#if manageable}
                <Button
                  variant="ghost"
                  class="h-9 px-2.5"
                  aria-label={t("team.removeAction", { name: member.name })}
                  title={t("team.remove")}
                  onclick={() => {
                    remove.reset();
                    removing = member;
                  }}
                >
                  <Trash2 aria-hidden="true" class="size-4" />
                </Button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
  <ConfirmDialog
    open={removing !== null}
    title={t("team.removeTitle", { name: removing?.name ?? "" })}
    description={t("team.removeDescription")}
    confirmLabel={t("team.remove")}
    pending={remove.isPending}
    error={remove.isError && !(remove.error instanceof ApiError && remove.error.code === "step-up-required")
      ? explainTeamError(remove.error)
      : null}
    onConfirm={() => removing && remove.mutate(removing.userId)}
    onClose={() => (removing = null)}
  />
  <LinkDirectoryDialog member={linking} currentUserEmail={me.user.email} onClose={() => (linking = null)} />
  <StepUpPrompt {stepUp} email={me.user.email} />
</Card>
