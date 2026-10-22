import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitPullRequest, RefreshCw, TriangleAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { camelCode, defaultApiBase, repoHost } from "../lib/fixes.ts";
import { formatDate, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";
import type { ForgeKind, RepositoryDetail } from "../lib/types.ts";
import { isAdmin } from "./nav.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { CopyButton } from "./ui/copy-button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { useStepUp } from "./use-step-up.tsx";

const FORGES: ForgeKind[] = ["github", "gitea", "forgejo"];

/**
 * "Fix PRs: off / on, by whom, since" on the repository page (ADR 0014): the separate write
 * token that lets GarnetOps open pull requests for this repository, and nothing else. Owners
 * and admins turn it on or off, with a recent sign-in; the token is never shown again.
 */
export function WriteAccessCard({ repo, me }: { repo: RepositoryDetail; me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const admin = isAdmin(me);
  const wa = repo.writeAccess;
  const access = wa.access;
  const [dialog, setDialog] = useState<"enable" | "replace" | null>(null);
  const [turningOff, setTurningOff] = useState(false);
  const [renovate, setRenovate] = useState(false);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["repository", repo.id] });
  const check = useMutation({
    mutationFn: () => api(`/repositories/${repo.id}/write-access/check`, { method: "POST" }),
    onSuccess: refresh,
    onError: (e) => void stepUp.handled(e, () => check.mutate()),
  });
  const turnOff = useMutation({
    mutationFn: () => api(`/repositories/${repo.id}/write-access`, { method: "DELETE" }),
    onSuccess: async () => {
      setTurningOff(false);
      await refresh();
      await queryClient.invalidateQueries({ queryKey: ["fixes"] });
    },
    onError: (e) => void stepUp.handled(e, () => turnOff.mutate()),
  });

  return (
    <Card>
      <CardHeader
        title={t("repository.writeAccess.title")}
        description={t("repository.writeAccess.description")}
        actions={
          <Button variant="outline" onClick={() => setRenovate(true)}>
            {t("repository.renovate.button")}
          </Button>
        }
      />
      <div className="grid gap-3 px-5 pb-5">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={wa.enabled ? "info" : "neutral"}>
            <GitPullRequest aria-hidden="true" />
            {wa.enabled ? t("repository.writeAccess.on") : t("repository.writeAccess.off")}
          </Badge>
          {access ? (
            <Badge tone={access.status === "failed" ? "critical" : "neutral"}>
              {t(`repository.writeAccess.status.${access.status}`)}
            </Badge>
          ) : null}
          {access?.checkedAt ? (
            <span className="text-sm text-muted-foreground">
              {t("repository.writeAccess.checkedAt", { when: formatRelative(access.checkedAt) })}
            </span>
          ) : null}
        </div>

        {access ? (
          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1.5">
            <dt className="text-muted-foreground">{t("repository.writeAccess.forge")}</dt>
            <dd>{t(`repository.writeAccess.forgeNames.${access.forgeKind}`)}</dd>
            <dt className="text-muted-foreground">{t("repository.writeAccess.apiAddress")}</dt>
            <dd className="font-mono text-sm break-all">{access.apiBaseUrl}</dd>
            <dt className="sr-only">{t("repository.writeAccess.title")}</dt>
            <dd className="col-span-2 text-sm text-muted-foreground">
              {access.enabledBy
                ? t("repository.writeAccess.enabledBy", {
                    name: access.enabledBy,
                    date: formatDate(access.enabledAt),
                  })
                : t("repository.writeAccess.enabledAt", { date: formatDate(access.enabledAt) })}
            </dd>
          </dl>
        ) : (
          <p className="text-sm text-muted-foreground">
            {wa.supported ? t("repository.writeAccess.offHint") : t("repository.writeAccess.unsupported")}
          </p>
        )}

        {access?.status === "failed" && access.statusReason ? (
          <Alert tone="error">
            {t(`fixes.failure.${camelCode(access.statusReason)}` as MessageKey, {
              defaultValue: t("fixes.failure.unexpected"),
            })}
          </Alert>
        ) : null}
        {access?.warning === "broad-token" ? (
          <div className="flex gap-2.5 rounded-md border border-warning/45 px-3 py-2.5 text-sm">
            <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 flex-none text-warning-text" />
            <span>{t("repository.writeAccess.broadToken")}</span>
          </div>
        ) : null}

        {admin ? (
          <div className="flex flex-wrap gap-2">
            {wa.enabled ? (
              <>
                <Button variant="outline" onClick={() => setDialog("replace")}>
                  {t("repository.writeAccess.replace")}
                </Button>
                <Button variant="outline" disabled={check.isPending} onClick={() => check.mutate()}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {check.isPending ? t("repository.writeAccess.checking") : t("repository.writeAccess.check")}
                </Button>
                <Button variant="destructive" onClick={() => setTurningOff(true)}>
                  {t("repository.writeAccess.turnOff")}
                </Button>
              </>
            ) : wa.supported ? (
              <Button onClick={() => setDialog("enable")}>{t("repository.writeAccess.turnOn")}</Button>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{t("repository.writeAccess.adminOnly")}</p>
        )}
      </div>

      {dialog ? (
        <WriteAccessDialog
          repo={repo}
          replacing={dialog === "replace"}
          me={me}
          onClose={() => setDialog(null)}
          onDone={async () => {
            setDialog(null);
            await refresh();
            await queryClient.invalidateQueries({ queryKey: ["fixes"] });
          }}
        />
      ) : null}
      <ConfirmDialog
        open={turningOff}
        title={t("repository.writeAccess.turnOffTitle")}
        description={t("repository.writeAccess.turnOffText")}
        confirmLabel={t("repository.writeAccess.turnOffConfirm")}
        pending={turnOff.isPending}
        error={
          turnOff.isError && !(turnOff.error instanceof ApiError && turnOff.error.code === "step-up-required")
            ? t("errors.actionFailed")
            : null
        }
        onConfirm={() => turnOff.mutate()}
        onClose={() => setTurningOff(false)}
      />
      <RenovateDialog repositoryId={repo.id} open={renovate} onClose={() => setRenovate(false)} />
      {stepUp.dialog}
    </Card>
  );
}

function WriteAccessDialog({
  repo,
  replacing,
  me,
  onClose,
  onDone,
}: {
  repo: RepositoryDetail;
  replacing: boolean;
  me: Me;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const stepUp = useStepUp(me.user.email);
  const host = repoHost(repo.url);
  const stored = repo.writeAccess.access;
  const suggested = repo.writeAccess.suggested;
  const [forge, setForge] = useState<ForgeKind | "">(stored?.forgeKind ?? suggested?.forgeKind ?? "");
  const [apiUrl, setApiUrl] = useState(stored?.apiBaseUrl ?? suggested?.apiBaseUrl ?? "");
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{ api?: string; token?: string }>({});

  const save = useMutation({
    mutationFn: () =>
      api(`/repositories/${repo.id}/write-access`, {
        method: "PUT",
        body: { token, forgeKind: forge, apiBaseUrl: apiUrl.trim() || undefined },
      }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async () => {
      setToken("");
      await onDone();
    },
    onError: (e) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      if (e instanceof ApiError && e.status === 422) {
        if (e.code === "invalid-api-address")
          return setFieldErrors({ api: t("repository.writeAccess.invalidApi") });
        if (e.code === "unsupported-repository") return setError(t("repository.writeAccess.unsupportedSave"));
        const paths = (e.problem?.errors ?? []).map((x) => x.path.split(".")[0]);
        if (paths.includes("token"))
          return setFieldErrors({ token: t("repository.writeAccess.invalidToken") });
        if (paths.includes("apiBaseUrl"))
          return setFieldErrors({ api: t("repository.writeAccess.invalidApi") });
      }
      setError(t("repository.writeAccess.failed"));
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (forge && token.length >= 8) save.mutate();
  }

  const chooseForge = (value: ForgeKind | "") => {
    setForge(value);
    // The address follows the forge until somebody edits it by hand.
    if (value && host && (apiUrl === "" || FORGES.some((k) => apiUrl === defaultApiBase(k, host)))) {
      setApiUrl(defaultApiBase(value, host));
    }
  };

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={
          replacing ? t("repository.writeAccess.dialogTitleReplace") : t("repository.writeAccess.dialogTitle")
        }
        description={t("repository.writeAccess.dialogText")}
      >
        <form className="grid gap-4" onSubmit={submit}>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <div className="grid gap-1.5">
            <label htmlFor="wa-forge" className="text-sm font-medium">
              {t("repository.writeAccess.forgeLabel")}
            </label>
            <Select
              id="wa-forge"
              value={forge}
              onChange={(e) => chooseForge(e.target.value as ForgeKind | "")}
              className="max-w-64"
            >
              <option value="">{t("repository.writeAccess.forgeUnknown")}</option>
              {FORGES.map((k) => (
                <option key={k} value={k}>
                  {t(`repository.writeAccess.forgeNames.${k}`)}
                </option>
              ))}
            </Select>
          </div>
          <Field
            label={t("repository.writeAccess.apiLabel")}
            hint={t("repository.writeAccess.apiHint")}
            error={fieldErrors.api}
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            className="font-mono text-sm"
          />
          <Field
            label={t("repository.writeAccess.tokenLabel")}
            hint={t("repository.writeAccess.tokenHint")}
            error={fieldErrors.token}
            type="password"
            name="write-token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            required
            minLength={8}
            maxLength={500}
            className="font-mono"
          />
          <div className="grid gap-1.5 rounded-md border bg-muted/40 px-3 py-2.5 text-sm">
            <b>{t("repository.writeAccess.scopesTitle")}</b>
            <p>{forge === "github" ? t("repository.writeAccess.scopesGithub") : null}</p>
            {forge === "gitea" || forge === "forgejo" ? (
              <p>{t("repository.writeAccess.scopesGitea")}</p>
            ) : null}
            {forge === "" ? (
              <>
                <p>{t("repository.writeAccess.scopesGithub")}</p>
                <p>{t("repository.writeAccess.scopesGitea")}</p>
              </>
            ) : null}
            <p className="text-muted-foreground">{t("repository.writeAccess.scopesPlain")}</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={save.isPending || !forge || token.length < 8}>
              {save.isPending ? t("repository.writeAccess.saving") : t("repository.writeAccess.save")}
            </Button>
          </DialogFooter>
        </form>
      </Dialog>
      {/* Next to the dialog, not inside it: closing the confirmation must not close this one. */}
      {stepUp.dialog}
    </>
  );
}

/** A renovate.json for teams that run their own Renovate. GarnetOps never runs or bundles it. */
function RenovateDialog({
  repositoryId,
  open,
  onClose,
}: {
  repositoryId: string;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const query = useQuery({
    queryKey: ["renovate-config", repositoryId],
    queryFn: () => api<{ packages: number; json: string }>(`/repositories/${repositoryId}/renovate-config`),
    enabled: open,
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("repository.renovate.title")}
      description={t("repository.renovate.description")}
    >
      <div className="grid gap-3">
        {query.isError ? <Alert tone="error">{t("repository.renovate.failed")}</Alert> : null}
        {query.data ? (
          <>
            <p className="text-sm text-muted-foreground">
              {query.data.packages === 0
                ? t("repository.renovate.empty")
                : t("repository.renovate.packages", { count: query.data.packages })}
            </p>
            <textarea
              readOnly
              rows={14}
              spellCheck={false}
              aria-label={t("repository.renovate.title")}
              value={query.data.json}
              className="max-h-72 w-full resize-none rounded-md border bg-muted/40 p-3 font-mono text-[13px]"
            />
          </>
        ) : (
          <QueryStatus query={query} className="min-h-0 px-0 py-2" />
        )}
        <DialogFooter>
          {query.data ? <CopyButton text={query.data.json} /> : null}
          <Button variant="outline" onClick={onClose}>
            {t("common.close")}
          </Button>
        </DialogFooter>
      </div>
    </Dialog>
  );
}
