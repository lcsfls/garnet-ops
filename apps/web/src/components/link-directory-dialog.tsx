import type { DirectoryRole } from "@garnetops/core/directory";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { toast } from "../lib/toast.ts";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";

interface Lookup {
  outcome: string;
  problem: string | null;
  person: {
    dn: string;
    email: string | null;
    name: string | null;
    groups: string[];
    role: DirectoryRole | null;
  } | null;
  emailMatches: boolean;
  alreadyLinked: boolean;
  account: { email: string; name: string; role: string };
}

/**
 * Links an existing local account to its directory entry (ADR 0020). Nothing is linked by mail
 * address on its own: an owner looks the person up, sees what the directory says, and confirms.
 * The account then signs in with the directory, takes its role from its groups and loses its
 * local password; its authenticator app stays.
 */
export function LinkDirectoryDialog({
  member,
  currentUserEmail,
  onClose,
}: {
  member: { userId: string; name: string; email: string } | null;
  currentUserEmail: string;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(currentUserEmail);
  const [username, setUsername] = useState("");
  const [error, setError] = useState<string | null>(null);

  const lookup = useMutation({
    mutationFn: (name: string) =>
      api<Lookup>("/directory/lookup", { method: "POST", body: { userId: member?.userId, username: name } }),
    onMutate: () => setError(null),
    onError: (e) =>
      setError(
        e instanceof ApiError && e.status === 422
          ? t("directory.fieldError.username_invalid")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : e instanceof ApiError && e.status === 503
              ? t("errors.directoryUnavailable")
              : t("errors.actionFailed"),
      ),
  });
  const link = useMutation({
    mutationFn: (name: string) =>
      api<{ role: DirectoryRole }>("/directory/link", {
        method: "POST",
        body: { userId: member?.userId, username: name },
      }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      toast.success(t("directory.linked", { name: member?.name ?? "" }));
      await queryClient.invalidateQueries({ queryKey: ["team-members"] });
      close();
    },
    onError: (e, name) => {
      if (stepUp.handled(e, () => link.mutate(name))) return;
      const code = e instanceof ApiError ? e.code : null;
      setError(
        code === "email-mismatch"
          ? t("directory.linkEmailMismatch")
          : code === "not-allowed"
            ? t("directory.linkNotAllowed")
            : code === "already-linked"
              ? t("directory.linkAlreadyLinked")
              : t("errors.actionFailed"),
      );
    },
  });

  function close() {
    lookup.reset();
    link.reset();
    setUsername("");
    setError(null);
    onClose();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    link.reset();
    lookup.mutate(username.trim());
  }

  const found = lookup.data;
  const person = found?.person ?? null;
  const ready = Boolean(found && person?.role && found.emailMatches && !found.alreadyLinked);

  return (
    <>
      <Dialog
        open={member !== null}
        onClose={close}
        title={t("directory.linkTitle", { name: member?.name ?? "" })}
        description={t("directory.linkDescription", { email: member?.email ?? "" })}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          <form className="flex flex-wrap items-end gap-3" onSubmit={submit} noValidate>
            <div className="min-w-0 flex-[1_1_14rem]">
              <Field
                label={t("directory.linkUsername")}
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  lookup.reset();
                }}
                required
                maxLength={128}
                autoCapitalize="off"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button type="submit" variant="outline" disabled={lookup.isPending || username.trim() === ""}>
              {lookup.isPending ? t("common.loading") : t("directory.linkLookup")}
            </Button>
          </form>
          {found ? (
            <div className="grid gap-3" data-testid="link-result">
              {person ? (
                <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 rounded-md border px-3 py-3 text-sm">
                  <dt className="text-muted-foreground">{t("directory.testDn")}</dt>
                  <dd className="font-mono break-all">{person.dn}</dd>
                  <dt className="text-muted-foreground">{t("directory.testEmail")}</dt>
                  <dd className="break-all">
                    {person.email ?? t("directory.testNoEmail")}{" "}
                    <Badge tone={found.emailMatches ? "neutral" : "critical"}>
                      {found.emailMatches ? t("directory.linkEmailSame") : t("directory.linkEmailOther")}
                    </Badge>
                  </dd>
                  <dt className="text-muted-foreground">{t("directory.testGroups")}</dt>
                  <dd className="font-mono break-all">
                    {person.groups.length > 0 ? person.groups.join("; ") : t("directory.testNoGroups")}
                  </dd>
                  <dt className="text-muted-foreground">{t("directory.testRole")}</dt>
                  <dd>
                    {person.role ? (
                      <Badge tone="neutral">{t(`team.roles.${person.role}`)}</Badge>
                    ) : (
                      <span className="text-destructive-text">{t("directory.testNoRole")}</span>
                    )}
                  </dd>
                </dl>
              ) : (
                <Alert tone="error">{t("directory.linkNotFound")}</Alert>
              )}
              {found.alreadyLinked ? <Alert tone="error">{t("directory.linkAlreadyLinked")}</Alert> : null}
              {person && !found.emailMatches ? (
                <Alert tone="error">{t("directory.linkEmailMismatch")}</Alert>
              ) : null}
              {person && !person.role ? <Alert tone="error">{t("directory.linkNotAllowed")}</Alert> : null}
              {ready ? <Alert tone="info">{t("directory.linkConsequences")}</Alert> : null}
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button disabled={!ready || link.isPending} onClick={() => link.mutate(username.trim())}>
              {link.isPending ? t("common.loading") : t("directory.linkConfirm")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
