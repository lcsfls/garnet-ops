import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Clock, GitBranch, KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { ScanStateBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Radio } from "../../components/ui/checkbox.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { CopyButton } from "../../components/ui/copy-button.tsx";
import { Dialog } from "../../components/ui/dialog.tsx";
import { Field } from "../../components/ui/field.tsx";
import { ApiError, api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { forgeOf } from "../../lib/forge.ts";
import { formatDateTime, formatNumber, formatRelative, formatWallClock } from "../../lib/format.ts";
import type { MessageKey } from "../../lib/i18n.ts";
import { useScanErrorText } from "../../lib/scan-error.ts";
import { type RepositorySearch, repositorySearch, toQuery } from "../../lib/search.ts";
import type { Page, RepositoryRow, Severity } from "../../lib/types.ts";

export const Route = createFileRoute("/_app/repositories")({
  validateSearch: repositorySearch,
  component: Repositories,
});

const STATUSES = ["all", "blocked", "attention", "clean"] as const;
/** Open findings per severity get a column each (mockup); low lives in the findings list. */
const SEVERITY_COLUMNS = ["critical", "high", "medium"] as const satisfies readonly Severity[];
const ACCESS_LABELS = {
  none: "repositories.accessPublic",
  "https-token": "repositories.accessToken",
  "ssh-deploy-key": "repositories.accessDeployKey",
} as const satisfies Record<RepositoryRow["authKind"], MessageKey>;
const SOURCE_ACCESS = {
  none: "repositories.sourcePublic",
  "https-token": "repositories.sourceToken",
  "ssh-deploy-key": "repositories.sourceDeployKey",
} as const satisfies Record<RepositoryRow["authKind"], MessageKey>;
const SEVERITY_TEXT: Record<(typeof SEVERITY_COLUMNS)[number], string> = {
  critical: "text-destructive-text",
  high: "text-high-text",
  medium: "text-warning-text",
};

function Repositories() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const canEdit = me.role !== "viewer";
  const canDelete = me.role === "owner" || me.role === "admin";

  const query = useQuery({
    queryKey: ["repositories", search],
    queryFn: () => api<Page<RepositoryRow>>(`/repositories${toQuery(search, ["add"])}`),
    placeholderData: keepPreviousData,
    // Follow running scans until they finish.
    refetchInterval: (q) =>
      q.state.data?.items.some((r) => r.lastScan && ["queued", "running"].includes(r.lastScan.state))
        ? 4000
        : false,
  });

  const counts = useQuery({
    queryKey: ["repository-counts", search.q ?? ""],
    queryFn: () =>
      api<Record<(typeof STATUSES)[number], number>>(`/repositories/counts${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
  });

  const setSearch = (patch: Partial<RepositorySearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });

  return (
    <>
      <PageHeader
        icon={GitBranch}
        title={t("repositories.title")}
        description={t("repositories.description")}
        actions={
          canEdit ? (
            <Button onClick={() => setSearch({ add: "1" })}>
              <Plus aria-hidden="true" className="size-4" />
              {t("repositories.add")}
            </Button>
          ) : null
        }
      />

      <p className="-mt-2 mb-4 flex items-center gap-1.5 text-sm text-muted-foreground">
        <Clock aria-hidden="true" className="size-4" />
        {me.organization.scanSchedule.enabled
          ? t("repositories.nightly", {
              time: formatWallClock(me.organization.scanSchedule.localTime),
              zone: me.organization.scanSchedule.timeZone,
            })
          : t("repositories.nightlyOff")}
      </p>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Segmented
          label={t("repositories.statusFilter")}
          value={search.status ?? "all"}
          options={STATUSES.map((s) => ({
            value: s,
            label: t(`repositories.status.${s}`),
            count: counts.data ? counts.data[s] : null,
          }))}
          onChange={(status) => setSearch({ status: status === "all" ? undefined : status })}
        />
        <SearchInput
          className="ml-auto"
          label={t("repositories.search")}
          value={search.q ?? ""}
          onChange={(q) => setSearch({ q: q || undefined }, true)}
        />
      </div>

      <Card>
        <table className="w-full text-left">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-b">
              <th className="px-5 py-2.5 font-medium">{t("repositories.columnName")}</th>
              <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
                {t("repositories.columnSource")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">
                {t("repositories.columnBranch")}
              </th>
              {SEVERITY_COLUMNS.map((severity) => (
                <th key={severity} className="px-3 py-2.5 text-right font-medium">
                  {t(`severity.${severity}`)}
                </th>
              ))}
              <th className="px-3 py-2.5 font-medium">{t("repositories.columnLastScan")}</th>
              <th className="px-5 py-2.5 text-right font-medium">
                <span className="sr-only">{t("repositories.columnActions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {query.data?.items.map((repo) => (
              <RepositoryRowView key={repo.id} repo={repo} canEdit={canEdit} canDelete={canDelete} />
            ))}
          </tbody>
        </table>
        <QueryStatus query={query} />
        {query.data && query.data.items.length === 0 ? (
          <p className="px-5 py-6 text-muted-foreground">{t("repositories.empty")}</p>
        ) : null}
        {query.data ? (
          <Pagination
            page={query.data}
            onCursor={(cursor) => navigate({ search: (prev) => ({ ...prev, cursor }) })}
            onPageSize={(pageSize) => setSearch({ pageSize })}
          />
        ) : null}
      </Card>

      <AddRepositoryDialog open={search.add === "1"} onClose={() => setSearch({ add: undefined }, true)} />
    </>
  );
}

function RepositoryRowView({
  repo,
  canEdit,
  canDelete,
}: {
  repo: RepositoryRow;
  canEdit: boolean;
  canDelete: boolean;
}) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["repositories"] });

  const scan = useMutation({
    mutationFn: () => api(`/repositories/${repo.id}/scans`, { method: "POST" }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: () => api(`/repositories/${repo.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setConfirmRemove(false);
      await queryClient.invalidateQueries();
    },
  });
  const [showKey, setShowKey] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const state = repo.lastScan?.state ?? null;
  const busy = state === "queued" || state === "running";
  const when = repo.lastScan?.finishedAt ?? repo.lastScanAt;

  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-5 py-3">
        <RepositoryLink id={repo.id} name={repo.name} className="font-medium" />
        <div className="max-w-[32ch] truncate font-mono text-sm text-muted-foreground" title={repo.url}>
          {repo.url}
        </div>
      </td>
      <td className="hidden px-3 py-3 @3xl:table-cell">
        <div>{forgeOf(repo.url)}</div>
        <div className="text-sm text-muted-foreground">{t(SOURCE_ACCESS[repo.authKind])}</div>
      </td>
      <td className="hidden px-3 py-3 font-mono text-sm @wide:table-cell">
        {repo.branch ?? (
          <span className="font-sans text-muted-foreground">{t("repositories.defaultBranch")}</span>
        )}
      </td>
      {SEVERITY_COLUMNS.map((severity) => {
        const n = repo.open[severity] ?? 0;
        return (
          <td key={severity} className="px-3 py-3 text-right tabular-nums">
            {n > 0 ? (
              <Link
                to="/findings"
                search={{ repositoryId: repo.id, severity }}
                aria-label={t("repositories.openOfSeverity", {
                  count: n,
                  severity: t(`severity.${severity}`),
                })}
                className={cn("font-semibold hover:underline", SEVERITY_TEXT[severity])}
              >
                {formatNumber(n)}
              </Link>
            ) : (
              <span className="text-muted-foreground">0</span>
            )}
          </td>
        );
      })}
      <td className="px-3 py-3">
        <ScanStateBadge state={state} />
        {when && !busy ? (
          <time
            dateTime={when}
            title={formatDateTime(when)}
            className="mt-1 block text-sm text-muted-foreground"
          >
            {formatRelative(when)}
          </time>
        ) : null}
        {state === "failed" && repo.lastScan?.error ? (
          <div className="mt-1 max-w-[36ch] text-sm text-destructive-text">
            {scanErrorText(repo.lastScan.error)}
          </div>
        ) : null}
      </td>
      <td className="px-5 py-3">
        <div className="flex justify-end gap-2">
          {repo.deployPublicKey ? (
            <Button
              variant="ghost"
              className="h-9 px-2.5"
              aria-label={`${t("repositories.deployKey")}: ${repo.name}`}
              title={t("repositories.deployKey")}
              onClick={() => setShowKey(true)}
            >
              <KeyRound aria-hidden="true" className="size-4" />
            </Button>
          ) : null}
          {canEdit ? (
            <Button
              variant="outline"
              className="h-9 px-2.5 @wide:px-4"
              disabled={busy || scan.isPending}
              aria-label={`${busy ? t(`scanState.${state}`) : t("repositories.scanNow")}: ${repo.name}`}
              title={busy ? t(`scanState.${state}`) : t("repositories.scanNow")}
              onClick={() => scan.mutate()}
            >
              <RefreshCw aria-hidden="true" className={cn("size-4", busy && "motion-safe:animate-spin")} />
              {/* Icon only below the wide step, so every column fits at 1080p with 150 % scaling. */}
              <span className="hidden @wide:inline">
                {busy ? t(`scanState.${state}`) : t("repositories.scanNow")}
              </span>
            </Button>
          ) : null}
          {canDelete ? (
            <Button
              variant="ghost"
              className="h-9 px-2.5"
              aria-label={`${t("repositories.delete")}: ${repo.name}`}
              disabled={remove.isPending}
              onClick={() => {
                remove.reset();
                setConfirmRemove(true);
              }}
            >
              <Trash2 aria-hidden="true" className="size-4" />
            </Button>
          ) : null}
        </div>
        {scan.isError ? (
          <p role="alert" className="mt-1.5 text-right text-sm text-destructive-text">
            {t("errors.actionFailed")}
          </p>
        ) : null}
        {canDelete ? (
          <ConfirmDialog
            open={confirmRemove}
            title={t("repositories.deleteTitle", { name: repo.name })}
            description={t("repositories.deleteDescription")}
            confirmLabel={t("repositories.delete")}
            pending={remove.isPending}
            error={remove.isError ? t("errors.actionFailed") : null}
            onConfirm={() => remove.mutate()}
            onClose={() => setConfirmRemove(false)}
          />
        ) : null}
        {repo.deployPublicKey ? (
          <Dialog
            open={showKey}
            onClose={() => setShowKey(false)}
            title={t("repositories.deployKeyTitle", { name: repo.name })}
          >
            <DeployKeyDetails repo={repo} canReset={canDelete} />
          </Dialog>
        ) : null}
      </td>
    </tr>
  );
}

/** The public deploy key with instructions, and the pinned host keys. */
function DeployKeyDetails({ repo, canReset }: { repo: RepositoryRow; canReset: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [confirmReset, setConfirmReset] = useState(false);
  const reset = useMutation({
    mutationFn: () => api(`/repositories/${repo.id}/ssh-host-keys`, { method: "DELETE" }),
    onSuccess: async () => {
      setConfirmReset(false);
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
    },
  });
  return (
    <div className="grid gap-5">
      <DeployKeyInstructions publicKey={repo.deployPublicKey ?? ""} />
      <section className="grid gap-2" aria-labelledby={`host-keys-${repo.id}`}>
        <h3 id={`host-keys-${repo.id}`} className="text-sm font-medium">
          {t("repositories.hostKeys")}
        </h3>
        {repo.sshHostKeys ? (
          <>
            <ul className="grid gap-1">
              {repo.sshHostKeys.keys.map((key) => (
                <li key={key.fingerprint} className="break-all font-mono text-sm">
                  {key.type} {key.fingerprint}
                </li>
              ))}
            </ul>
            <p className="text-sm text-muted-foreground">
              {t("repositories.hostKeysPinned", { when: formatDateTime(repo.sshHostKeys.pinnedAt) })}
            </p>
            {canReset ? (
              <div>
                <Button
                  variant="outline"
                  disabled={reset.isPending}
                  onClick={() => {
                    reset.reset();
                    setConfirmReset(true);
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
                  onClose={() => setConfirmReset(false)}
                />
              </div>
            ) : null}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">{t("repositories.hostKeysNone")}</p>
        )}
      </section>
    </div>
  );
}

function DeployKeyInstructions({ publicKey }: { publicKey: string }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-2">
      <label htmlFor="deploy-public-key" className="text-sm font-medium">
        {t("repositories.deployKeyLabel")}
      </label>
      <textarea
        id="deploy-public-key"
        readOnly
        rows={3}
        value={publicKey}
        onFocus={(e) => e.currentTarget.select()}
        className="w-full resize-none break-all rounded-md border border-input bg-muted px-3 py-2 font-mono text-sm"
      />
      <div>
        <CopyButton text={publicKey} />
      </div>
      <p className="text-sm text-muted-foreground">{t("repositories.deployKeyHowTo")}</p>
    </div>
  );
}

function AddRepositoryDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [access, setAccess] = useState<RepositoryRow["authKind"]>("none");
  /** Set after an SSH repository was added: the key the user now adds to the forge. */
  const [created, setCreated] = useState<{ id: string; deployPublicKey: string } | null>(null);
  const [error, setError] = useState<MessageKey | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const create = useMutation({
    mutationFn: (body: unknown) =>
      api<{ id: string; scanId: string | null; deployPublicKey: string | null }>("/repositories", {
        method: "POST",
        body,
      }),
    onSuccess: async (result) => {
      await queryClient.invalidateQueries();
      if (result.deployPublicKey) setCreated({ id: result.id, deployPublicKey: result.deployPublicKey });
      else onClose();
    },
    onError: (e) => {
      if (!(e instanceof ApiError)) return setError("errors.network");
      if (e.code === "duplicate") return setError("repositories.errorDuplicate");
      if (e.code === "auth-mismatch") return setError("repositories.errorAuthMismatch");
      if (e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
        return setError("repositories.errorInvalid");
      }
      setError("errors.generic");
    },
  });

  useEffect(() => {
    if (!open) {
      setError(null);
      setFieldErrors({});
      setAccess("none");
      setCreated(null);
    }
  }, [open]);

  const firstScan = useMutation({
    mutationFn: (id: string) => api(`/repositories/${id}/scans`, { method: "POST" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
      onClose();
    },
    onError: () => setError("errors.generic"),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const optional = (key: string) => String(form.get(key) ?? "").trim() || undefined;
    setError(null);
    setFieldErrors({});
    create.mutate({
      url: String(form.get("url")).trim(),
      name: optional("name"),
      branch: optional("branch"),
      auth:
        access === "https-token"
          ? { kind: "https-token", token: String(form.get("token")) }
          : { kind: access },
    });
  }

  if (created) {
    return (
      <Dialog
        open={open}
        onClose={onClose}
        title={t("repositories.deployKeyAddedTitle")}
        description={t("repositories.deployKeyAddedDescription")}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{t(error)}</Alert> : null}
          <DeployKeyInstructions publicKey={created.deployPublicKey} />
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="outline" onClick={onClose}>
              {t("repositories.later")}
            </Button>
            <Button disabled={firstScan.isPending} onClick={() => firstScan.mutate(created.id)}>
              {firstScan.isPending ? t("common.loading") : t("repositories.startFirstScan")}
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("repositories.addTitle")}
      description={t("repositories.addDescription")}
    >
      <form className="grid gap-4" onSubmit={submit}>
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        <Field
          label={t("repositories.url")}
          hint={t("repositories.urlHint")}
          error={fieldErrors.url}
          name="url"
          required
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
        <Field
          label={t("repositories.name")}
          hint={t("repositories.nameHint")}
          error={fieldErrors.name}
          name="name"
          maxLength={120}
        />
        <Field
          label={t("repositories.branch")}
          hint={t("repositories.branchHint")}
          error={fieldErrors.branch}
          name="branch"
          maxLength={200}
          spellCheck={false}
          className="font-mono"
        />
        <fieldset className="grid gap-2">
          <legend className="mb-1.5 text-sm font-medium">{t("repositories.access")}</legend>
          {(["none", "https-token", "ssh-deploy-key"] as const).map((kind) => (
            <label key={kind} className="flex items-center gap-2.5">
              <Radio name="access" value={kind} checked={access === kind} onChange={() => setAccess(kind)} />
              {t(ACCESS_LABELS[kind])}
            </label>
          ))}
        </fieldset>
        {access === "https-token" ? (
          <Field
            label={t("repositories.token")}
            hint={t("repositories.tokenHint")}
            error={fieldErrors.auth}
            name="token"
            type="password"
            required
            minLength={8}
            maxLength={500}
            autoComplete="off"
          />
        ) : null}
        <div className="mt-1 flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            {t("repositories.cancel")}
          </Button>
          <Button type="submit" disabled={create.isPending}>
            {create.isPending
              ? t("common.loading")
              : access === "ssh-deploy-key"
                ? t("repositories.submitKey")
                : t("repositories.submit")}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
