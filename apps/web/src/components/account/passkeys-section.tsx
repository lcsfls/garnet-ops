import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { accountQuery, type PasskeyRow } from "../../lib/account.ts";
import { ApiError, api } from "../../lib/api.ts";
import { formatDateTime } from "../../lib/format.ts";
import { PASSKEY_FAILURE_KEYS, passkeysSupported, registerPasskey } from "../../lib/passkeys.ts";
import { toast } from "../../lib/toast.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { QueryStatus } from "../query-state.tsx";
import { Alert } from "../ui/alert.tsx";
import { Badge } from "../ui/badge.tsx";
import { Button } from "../ui/button.tsx";
import { ConfirmDialog } from "../ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "../ui/dialog.tsx";
import { Field } from "../ui/field.tsx";
import { useStepUp } from "../use-step-up.tsx";

const NAME_MAX = 60;
/** What the step-up hook recognises, for the ceremony that is not an API call of ours. */
const STEP_UP = new ApiError(403, {
  type: "https://garnetops.com/problems/step-up-required",
  title: "Sign in again to confirm it is you",
  status: 403,
});

/** Account → Passkeys: list, add (recent sign-in), rename, remove (recent sign-in; never the last factor). */
export function PasskeysSection({ email }: { email: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const query = useQuery(accountQuery);
  const stepUp = useStepUp(email);
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<PasskeyRow | null>(null);
  const [removing, setRemoving] = useState<PasskeyRow | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["account"] });

  const remove = useMutation({
    mutationFn: (id: string) => api(`/account/passkeys/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRemoving(null);
      toast.success(t("account.passkeys.removed"));
      await refresh();
    },
    onError: (e, id) => {
      if (stepUp.handled(e, () => remove.mutate(id))) return;
      setRemoveError(
        e instanceof ApiError && e.code === "last-second-factor"
          ? t("account.passkeys.errorLast")
          : t("errors.generic"),
      );
    },
  });

  if (!query.data) {
    return (
      <Card>
        <QueryStatus query={query} />
      </Card>
    );
  }
  const { passkeys, passkeysAvailable, relyingParty } = query.data.secondFactor;
  const usable = passkeysAvailable && passkeysSupported();

  return (
    <>
      <Card>
        <CardHeader
          title={t("account.passkeys.title")}
          description={t("account.passkeys.description")}
          actions={
            usable ? (
              <Button onClick={() => setAdding(true)}>
                <Plus aria-hidden="true" className="size-4" />
                {t("account.passkeys.add")}
              </Button>
            ) : undefined
          }
        />
        <div className="grid gap-4 px-5 pb-5">
          {!passkeysAvailable ? <Alert tone="info">{t("account.passkeys.unavailable")}</Alert> : null}
          {passkeysAvailable && !passkeysSupported() ? (
            <Alert tone="info">{t("account.passkeys.errorUnsupported")}</Alert>
          ) : null}
          {passkeys.length === 0 ? (
            <p className="text-muted-foreground">{t("account.passkeys.empty")}</p>
          ) : (
            <ul className="grid gap-2">
              {passkeys.map((p) => (
                <li
                  key={p.id}
                  data-testid="passkey"
                  className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border px-3 py-2.5"
                >
                  <Fingerprint aria-hidden="true" className="size-5 flex-none text-muted-foreground" />
                  <div className="min-w-0 flex-[1_1_14rem]">
                    <div className="truncate font-medium">{p.name ?? t("account.passkeys.unnamed")}</div>
                    <div className="text-sm text-muted-foreground">
                      {p.createdAt
                        ? t("account.passkeys.created", { date: formatDateTime(p.createdAt) })
                        : null}
                      {" · "}
                      {p.lastUsedAt
                        ? t("account.passkeys.lastUsed", { date: formatDateTime(p.lastUsedAt) })
                        : t("account.passkeys.neverUsed")}
                    </div>
                  </div>
                  <Badge tone="neutral">
                    {p.backedUp ? t("account.passkeys.synced") : t("account.passkeys.deviceBound")}
                  </Badge>
                  <div className="flex gap-1.5">
                    <Button variant="outline" className="h-9 px-3 text-sm" onClick={() => setRenaming(p)}>
                      <Pencil aria-hidden="true" className="size-3.5" />
                      {t("account.passkeys.rename")}
                    </Button>
                    <Button
                      variant="destructive"
                      className="h-9 px-3 text-sm"
                      onClick={() => {
                        setRemoveError(null);
                        setRemoving(p);
                      }}
                    >
                      <Trash2 aria-hidden="true" className="size-3.5" />
                      {t("account.passkeys.remove")}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {passkeysAvailable ? (
            <p className="text-sm text-muted-foreground">
              {t("account.passkeys.bound", { domain: relyingParty })}
            </p>
          ) : null}
        </div>
      </Card>

      <AddDialog
        open={adding}
        stepUp={stepUp}
        onClose={() => setAdding(false)}
        onAdded={async () => {
          setAdding(false);
          toast.success(t("account.passkeys.added"));
          await refresh();
        }}
      />
      <RenameDialog
        passkey={renaming}
        onClose={() => setRenaming(null)}
        onRenamed={async () => {
          setRenaming(null);
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
        onClose={() => setRemoving(null)}
      />
      {stepUp.dialog}
    </>
  );
}

function AddDialog({
  open,
  stepUp,
  onClose,
  onAdded,
}: {
  open: boolean;
  stepUp: ReturnType<typeof useStepUp>;
  onClose: () => void;
  onAdded: () => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function add(name: string) {
    setBusy(true);
    setError(null);
    const result = await registerPasskey(name);
    setBusy(false);
    if (result.ok) return onAdded();
    if (result.reason === "step-up" && stepUp.handled(STEP_UP, () => void add(name))) return;
    setError(t(PASSKEY_FAILURE_KEYS[result.reason]));
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void add(String(new FormData(event.currentTarget).get("name")).trim());
  }
  return (
    <Dialog
      open={open}
      onClose={() => {
        setError(null);
        onClose();
      }}
      title={t("account.passkeys.addTitle")}
      description={t("account.passkeys.addDescription")}
    >
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          label={t("account.passkeys.name")}
          hint={t("account.passkeys.nameHint")}
          name="name"
          required
          maxLength={NAME_MAX}
          autoComplete="off"
        />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" disabled={busy}>
            {busy ? t("common.loading") : t("account.passkeys.create")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}

function RenameDialog({
  passkey,
  onClose,
  onRenamed,
}: {
  passkey: PasskeyRow | null;
  onClose: () => void;
  onRenamed: () => void;
}) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const rename = useMutation({
    mutationFn: (input: { id: string; name: string }) =>
      api(`/account/passkeys/${input.id}`, { method: "PATCH", body: { name: input.name } }),
    onSuccess: onRenamed,
    onError: (e) =>
      setError(
        e instanceof ApiError && e.status === 422 ? t("account.passkeys.errorName") : t("errors.generic"),
      ),
  });
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (passkey) {
      rename.mutate({ id: passkey.id, name: String(new FormData(event.currentTarget).get("name")).trim() });
    }
  }
  return (
    <Dialog open={passkey !== null} onClose={onClose} title={t("account.passkeys.renameTitle")}>
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          label={t("account.passkeys.name")}
          name="name"
          required
          maxLength={NAME_MAX}
          autoComplete="off"
          defaultValue={passkey?.name ?? ""}
        />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" disabled={rename.isPending}>
            {rename.isPending ? t("common.loading") : t("account.passkeys.renameSave")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
