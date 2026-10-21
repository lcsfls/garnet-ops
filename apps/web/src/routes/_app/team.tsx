import { ROLES, type Role } from "@garnetops/core";
import { canAssignRole, canManageMember } from "@garnetops/core/team";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { Trash2, UserPlus, Users } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { Badge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Radio } from "../../components/ui/checkbox.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { CopyButton } from "../../components/ui/copy-button.tsx";
import { Dialog, DialogFooter } from "../../components/ui/dialog.tsx";
import { Field } from "../../components/ui/field.tsx";
import { Select } from "../../components/ui/select.tsx";
import { useStepUp } from "../../components/use-step-up.tsx";
import { ApiError, api } from "../../lib/api.ts";
import { formatDate, formatDateTime, formatRelative } from "../../lib/format.ts";
import type { Me } from "../../lib/session.ts";

export const Route = createFileRoute("/_app/team")({
  // Owners and admins only; the API enforces the same rule.
  beforeLoad: ({ context }) => {
    if (context.me.role !== "owner" && context.me.role !== "admin")
      throw redirect({ to: "/", replace: true });
  },
  component: TeamPage,
});

interface Member {
  userId: string;
  role: Role;
  name: string;
  email: string;
  twoFactorEnabled: boolean;
  lastSignInAt: string | null;
  joinedAt: string;
}
interface Invitation {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  expiresAt: string;
  invitedBy: string | null;
}

function useTeamError() {
  const { t } = useTranslation();
  return (error: unknown) => {
    if (!(error instanceof ApiError)) return t("errors.network");
    if (error.code === "already-member") return t("team.errorAlreadyMember");
    if (error.code === "last-owner") return t("team.errorLastOwner");
    if (error.status === 403) return t("team.errorForbidden");
    return t("errors.actionFailed");
  };
}

/** Members, roles and invitations (ADR 0009). */
function TeamPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const [inviting, setInviting] = useState(false);
  return (
    <div className="mx-auto max-w-[72rem] @wide:max-w-[96rem]">
      <PageHeader
        icon={Users}
        title={t("team.title")}
        description={t("team.description")}
        actions={
          <Button onClick={() => setInviting(true)}>
            <UserPlus aria-hidden="true" className="size-4" />
            {t("team.invite")}
          </Button>
        }
      />
      <div className="grid items-start gap-4 @wide:grid-cols-[minmax(0,1fr)_minmax(0,24rem)]">
        <Members me={me} />
        <Invitations />
      </div>
      <InviteDialog me={me} open={inviting} onClose={() => setInviting(false)} />
    </div>
  );
}

function Members({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const explain = useTeamError();
  const stepUp = useStepUp(me.user.email);
  const members = useQuery({ queryKey: ["team-members"], queryFn: () => api<Member[]>("/team/members") });
  const [removing, setRemoving] = useState<Member | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["team-members"] });

  const changeRole = useMutation({
    mutationFn: (input: { userId: string; role: Role }) =>
      api(`/team/members/${input.userId}`, { method: "PATCH", body: { role: input.role } }),
    onMutate: () => setError(null),
    onSuccess: refresh,
    onError: (e, input) => {
      if (!stepUp.handled(e, () => changeRole.mutate(input))) setError(explain(e));
      void refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (userId: string) => api(`/team/members/${userId}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(null);
      await refresh();
    },
    onError: (e, userId) => {
      if (stepUp.handled(e, () => remove.mutate(userId))) setRemoving(null);
    },
  });

  return (
    <Card>
      <CardHeader title={t("team.membersTitle")} description={t("team.membersDescription")} />
      <QueryStatus query={members} />
      {error ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{error}</Alert>
        </div>
      ) : null}
      {members.data ? (
        <table className="w-full text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("team.columnPerson")}</th>
              <th className="px-3 py-2.5 font-medium">{t("team.columnRole")}</th>
              <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
                {t("team.columnSecondFactor")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @5xl:table-cell">{t("team.columnLastSignIn")}</th>
              <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("team.columnJoined")}</th>
              <th className="w-14 px-5 py-2.5">
                <span className="sr-only">{t("repositories.columnActions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {members.data.map((member) => {
              const self = member.userId === me.user.id;
              const manageable = !self && canManageMember(me.role, member.role);
              return (
                <tr key={member.userId} className="border-b align-top last:border-0">
                  <td className="px-5 py-3">
                    <div className="font-medium">
                      {member.name}
                      {self ? (
                        <span className="ml-1.5 font-normal text-muted-foreground">({t("team.you")})</span>
                      ) : null}
                    </div>
                    <div className="text-sm break-all text-muted-foreground">{member.email}</div>
                    {/* Narrow screens: the second factor moves here instead of disappearing. */}
                    {!member.twoFactorEnabled ? (
                      <div className="mt-1 @3xl:hidden">
                        <Badge tone="medium">{t("team.secondFactorPending")}</Badge>
                      </div>
                    ) : null}
                  </td>
                  <td className="px-3 py-3">
                    {manageable ? (
                      <Select
                        aria-label={t("team.roleOf", { name: member.name })}
                        value={member.role}
                        disabled={changeRole.isPending}
                        onChange={(e) =>
                          changeRole.mutate({ userId: member.userId, role: e.target.value as Role })
                        }
                        className="max-w-40"
                      >
                        {ROLES.filter((r) => canAssignRole(me.role, r)).map((r) => (
                          <option key={r} value={r}>
                            {t(`team.roles.${r}`)}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Badge tone="neutral">{t(`team.roles.${member.role}`)}</Badge>
                    )}
                  </td>
                  <td className="hidden px-3 py-3 @3xl:table-cell">
                    <Badge tone={member.twoFactorEnabled ? "neutral" : "medium"}>
                      {member.twoFactorEnabled ? t("team.secondFactorOn") : t("team.secondFactorPending")}
                    </Badge>
                  </td>
                  <td className="hidden px-3 py-3 text-sm @5xl:table-cell">
                    {member.lastSignInAt ? (
                      <time
                        dateTime={member.lastSignInAt}
                        title={formatDateTime(member.lastSignInAt)}
                        className="dash-time"
                      >
                        {formatRelative(member.lastSignInAt)}
                      </time>
                    ) : (
                      <span className="text-muted-foreground">{t("team.never")}</span>
                    )}
                  </td>
                  <td className="hidden px-3 py-3 text-sm @wide:table-cell">{formatDate(member.joinedAt)}</td>
                  <td className="px-5 py-2 text-right">
                    {manageable ? (
                      <Button
                        variant="ghost"
                        className="h-9 px-2.5"
                        aria-label={t("team.removeAction", { name: member.name })}
                        title={t("team.remove")}
                        onClick={() => {
                          remove.reset();
                          setRemoving(member);
                        }}
                      >
                        <Trash2 aria-hidden="true" className="size-4" />
                      </Button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : null}
      <ConfirmDialog
        open={removing !== null}
        title={t("team.removeTitle", { name: removing?.name ?? "" })}
        description={t("team.removeDescription")}
        confirmLabel={t("team.remove")}
        pending={remove.isPending}
        error={
          remove.isError && !(remove.error instanceof ApiError && remove.error.code === "step-up-required")
            ? explain(remove.error)
            : null
        }
        onConfirm={() => removing && remove.mutate(removing.userId)}
        onClose={() => setRemoving(null)}
      />
      {stepUp.dialog}
    </Card>
  );
}

function Invitations() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const invitations = useQuery({
    queryKey: ["team-invitations"],
    queryFn: () => api<Invitation[]>("/team/invitations"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/team/invitations/${id}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["team-invitations"] }),
  });
  return (
    <Card>
      <CardHeader title={t("team.invitationsTitle")} />
      <QueryStatus query={invitations} />
      {invitations.data && invitations.data.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("team.invitationsEmpty")}</p>
      ) : null}
      <ul className="px-5 pb-3">
        {invitations.data?.map((invitation) => (
          <li key={invitation.id} className="flex items-start gap-3 border-t py-3 first:border-t-0">
            <div className="min-w-0 flex-1">
              <div className="font-medium break-all">{invitation.email}</div>
              <div className="text-[13px] text-muted-foreground">
                {t(`team.roles.${invitation.role}`)} ·{" "}
                {t("team.expires", { date: formatDate(invitation.expiresAt) })}
                {invitation.invitedBy ? ` · ${t("team.invitedBy", { name: invitation.invitedBy })}` : ""}
              </div>
            </div>
            <Button
              variant="ghost"
              className="h-9 px-2.5"
              disabled={revoke.isPending}
              aria-label={t("team.revokeAction", { email: invitation.email })}
              onClick={() => revoke.mutate(invitation.id)}
            >
              {t("team.revoke")}
            </Button>
          </li>
        ))}
      </ul>
      {revoke.isError ? (
        <div className="px-5 pb-4">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
    </Card>
  );
}

function InviteDialog({ me, open, onClose }: { me: Me; open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const explain = useTeamError();
  const stepUp = useStepUp(me.user.email);
  const roles = ROLES.filter((r) => canAssignRole(me.role, r));
  const [role, setRole] = useState<Role>("member");
  const [result, setResult] = useState<{ link: string; email: string; expiresAt: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: (input: { email: string; role: Role }) =>
      api<{ link: string; expiresAt: string }>("/team/invitations", { method: "POST", body: input }),
    onMutate: () => setError(null),
    onSuccess: async (data, input) => {
      setResult({ link: data.link, email: input.email, expiresAt: data.expiresAt });
      await queryClient.invalidateQueries({ queryKey: ["team-invitations"] });
    },
    onError: (e, input) => {
      if (!stepUp.handled(e, () => create.mutate(input))) setError(explain(e));
    },
  });
  function close() {
    setResult(null);
    setError(null);
    setRole("member");
    onClose();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const email = String(new FormData(event.currentTarget).get("email") ?? "")
      .trim()
      .toLowerCase();
    create.mutate({ email, role });
  }
  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        title={t("team.inviteTitle")}
        description={t("team.inviteDescription")}
      >
        {result ? (
          <div className="grid gap-3">
            <label htmlFor="invite-link" className="text-sm font-medium">
              {t("team.inviteLink")}
            </label>
            <textarea
              id="invite-link"
              readOnly
              rows={3}
              value={result.link}
              onFocus={(e) => e.currentTarget.select()}
              className="w-full resize-none break-all rounded-md border border-input bg-muted px-3 py-2 font-mono text-sm"
            />
            <div>
              <CopyButton text={result.link} />
            </div>
            <p className="text-sm text-muted-foreground">
              {t("team.inviteLinkHint", { email: result.email, date: formatDate(result.expiresAt) })}
            </p>
            <DialogFooter>
              <Button onClick={close}>{t("common.close")}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form className="grid gap-4" onSubmit={submit}>
            {error ? <Alert tone="error">{error}</Alert> : null}
            <Field
              label={t("team.inviteEmail")}
              name="email"
              type="email"
              required
              autoComplete="off"
              maxLength={254}
            />
            <fieldset className="grid gap-2">
              <legend className="mb-1.5 text-sm font-medium">{t("team.inviteRole")}</legend>
              {roles.map((r) => (
                <div key={r} className="flex items-start gap-2.5">
                  <Radio
                    id={`invite-role-${r}`}
                    name="role"
                    value={r}
                    checked={role === r}
                    onChange={() => setRole(r)}
                    aria-describedby={`invite-role-${r}-hint`}
                    className="mt-1"
                  />
                  <div>
                    <label htmlFor={`invite-role-${r}`}>{t(`team.roles.${r}`)}</label>
                    <span id={`invite-role-${r}-hint`} className="block text-sm text-muted-foreground">
                      {t(`team.roleHint.${r}`)}
                    </span>
                  </div>
                </div>
              ))}
            </fieldset>
            <DialogFooter>
              <Button variant="outline" onClick={close}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? t("common.loading") : t("team.inviteSubmit")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
