import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  Clock,
  FolderGit2,
  GitBranch,
  GitFork,
  KeyRound,
  Plus,
  RefreshCw,
  Terminal,
  Trash2,
} from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { SearchInput, Segmented } from "../../components/filters.tsx";
import { GateBadge } from "../../components/gate-badge.tsx";
import { Card, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { type SortDir, SortHeader } from "../../components/sort-header.tsx";
import { Sparkline } from "../../components/sparkline.tsx";
import { ActionMenu, type MenuAction } from "../../components/ui/action-menu.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { BADGE_TONE, Badge, ScanStateBadge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Radio } from "../../components/ui/checkbox.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { CopyButton } from "../../components/ui/copy-button.tsx";
import { Dialog, DialogFooter } from "../../components/ui/dialog.tsx";
import { Field, TextAreaField } from "../../components/ui/field.tsx";
import { ApiError, api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { forgeOf } from "../../lib/forge.ts";
import { formatDateTime, formatNumber, formatRelative, formatWallClock } from "../../lib/format.ts";
import type { MessageKey } from "../../lib/i18n.ts";
import { BULK_LIMIT, parseUrlList } from "../../lib/repo-urls.ts";
import { rowClick } from "../../lib/row-link.ts";
import { useScanErrorText } from "../../lib/scan-error.ts";
import { type RepositorySearch, repositorySearch, toQuery } from "../../lib/search.ts";
import type { GateResult, Page, RepositoryRow, Severity } from "../../lib/types.ts";

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
/** Open findings per severity as small tinted counts (mockup .count). */
const COUNT_PILL = "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold";
const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

function Repositories() {
  const { t } = useTranslation();
  const search = Route.useSearch();
  const { me } = Route.useRouteContext();
  const navigate = useNavigate({ from: Route.fullPath });
  const canEdit = me.role !== "viewer";
  const canDelete = me.role === "owner" || me.role === "admin";

  const query = useQuery({
    queryKey: ["repositories", search],
    queryFn: () => api<Page<RepositoryRow>>(`/repositories${toQuery({ ...search, tz: timeZone }, ["add"])}`),
    placeholderData: keepPreviousData,
    // Follow running scans until they finish.
    refetchInterval: (q) =>
      q.state.data?.items.some((r) => r.lastScan && ["queued", "running"].includes(r.lastScan.state))
        ? 4000
        : false,
  });

  // The latest gate result of each repository's own branch (pull request checks excluded).
  const gates = useQuery({
    queryKey: ["gate-latest"],
    queryFn: () => api<{ repositoryId: string; result: GateResult }[]>("/gates/latest"),
  });
  const gateOf = new Map((gates.data ?? []).map((g) => [g.repositoryId, g.result]));

  const counts = useQuery({
    queryKey: ["repository-counts", search.q ?? ""],
    queryFn: () =>
      api<Record<(typeof STATUSES)[number], number>>(`/repositories/counts${toQuery({ q: search.q })}`),
    placeholderData: keepPreviousData,
  });

  const setSearch = (patch: Partial<RepositorySearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, cursor: undefined, ...patch }), replace });
  const sortProps = {
    current: search.sort,
    dir: search.dir,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      setSearch({ sort: sort as RepositorySearch["sort"], dir }),
  };

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
              <SortHeader
                column="name"
                label={t("repositories.columnName")}
                natural="asc"
                className="px-5"
                {...sortProps}
              />
              <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">
                {t("repositories.columnSource")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">
                {t("repositories.columnBranch")}
              </th>
              {SEVERITY_COLUMNS.map((severity) => (
                <SortHeader
                  key={severity}
                  column={severity}
                  label={t(`severity.${severity}`)}
                  natural="desc"
                  align="right"
                  className="px-3"
                  {...sortProps}
                />
              ))}
              <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">
                {t("repositories.columnScanners")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @xwide:table-cell">
                {t("repositories.columnTrend")}
              </th>
              <th className="hidden px-3 py-2.5 font-medium @5xl:table-cell">{t("gates.columnGate")}</th>
              <SortHeader
                column="lastScan"
                label={t("repositories.columnLastScan")}
                natural="desc"
                className="px-3"
                {...sortProps}
              />
              <th className="w-14 px-5 py-2.5 text-right font-medium">
                <span className="sr-only">{t("repositories.columnActions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {query.data?.items.map((repo) => (
              <RepositoryRowView
                key={repo.id}
                repo={repo}
                gate={gateOf.get(repo.id) ?? null}
                canEdit={canEdit}
                canDelete={canDelete}
              />
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
  gate,
  canEdit,
  canDelete,
}: {
  repo: RepositoryRow;
  gate: GateResult | null;
  canEdit: boolean;
  canDelete: boolean;
}) {
  const { t } = useTranslation();
  const scanErrorText = useScanErrorText();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
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
  const ssh = repo.authKind === "ssh-deploy-key";
  const SourceIcon = ssh ? Terminal : GitFork;

  const actions: MenuAction[] = [];
  if (canEdit) {
    actions.push({
      label: busy ? t(`scanState.${state}`) : t("repositories.scanNow"),
      icon: RefreshCw,
      disabled: busy || scan.isPending,
      onSelect: () => scan.mutate(),
    });
  }
  if (repo.deployPublicKey) {
    actions.push({ label: t("repositories.deployKey"), icon: KeyRound, onSelect: () => setShowKey(true) });
  }
  if (canDelete) {
    actions.push({
      label: t("repositories.delete"),
      icon: Trash2,
      destructive: true,
      disabled: remove.isPending,
      onSelect: () => {
        remove.reset();
        setConfirmRemove(true);
      },
    });
  }

  return (
    <tr
      className="row-link border-b align-top last:border-0"
      onClick={rowClick(() => void navigate({ to: "/repositories/$id", params: { id: repo.id } }))}
    >
      {/* The name column takes what the others leave and truncates, so a long address never pushes the table past its card. */}
      <td className="w-full max-w-0 px-5 py-3 @wide:w-auto @wide:max-w-none">
        <div className="flex min-w-0 items-start gap-2.5">
          <FolderGit2 aria-hidden="true" className="mt-1 size-4 flex-none text-muted-foreground" />
          <div className="min-w-0">
            <RepositoryLink id={repo.id} name={repo.name} className="font-medium" />
            <div
              className="max-w-[32ch] truncate font-mono text-sm text-muted-foreground @xwide:max-w-[52ch]"
              title={repo.url}
            >
              {repo.url}
            </div>
          </div>
        </div>
      </td>
      <td className="hidden px-3 py-3 @3xl:table-cell">
        <div className="flex items-start gap-2.5">
          <SourceIcon aria-hidden="true" className="mt-1 size-4 flex-none text-muted-foreground" />
          <div>
            <div>{forgeOf(repo.url)}</div>
            <div className="text-sm text-muted-foreground">{t(SOURCE_ACCESS[repo.authKind])}</div>
          </div>
        </div>
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
                className={cn(COUNT_PILL, BADGE_TONE[severity], "hover:underline")}
              >
                {formatNumber(n)}
              </Link>
            ) : (
              <span className={cn(COUNT_PILL, "font-normal text-muted-foreground")}>0</span>
            )}
          </td>
        );
      })}
      <td className="hidden px-3 py-3 @5xl:table-cell">
        {gate ? <GateBadge result={gate} /> : <span className="text-muted-foreground">–</span>}
      </td>
      <td className="hidden px-3 py-3 @xwide:table-cell">
        <div className="flex flex-wrap gap-1">
          {repo.scanners.map((scanner) => (
            <Badge key={scanner} tone="neutral">
              {scanner}
            </Badge>
          ))}
        </div>
      </td>
      <td className="hidden px-3 py-3 @xwide:table-cell">
        <Sparkline
          values={repo.trend}
          label={t("repositories.trendLabel", {
            first: formatNumber(repo.trend[0] ?? 0),
            last: formatNumber(repo.trend[repo.trend.length - 1] ?? 0),
          })}
        />
      </td>
      <td className="px-3 py-3">
        <div className="flex flex-wrap gap-1">
          <ScanStateBadge state={state} />
          {/* Narrow screens have no gate column; the result moves here instead of disappearing. */}
          {gate ? (
            <span className="@5xl:hidden">
              <GateBadge result={gate} />
            </span>
          ) : null}
        </div>
        {when && !busy ? (
          <time
            dateTime={when}
            title={formatDateTime(when)}
            className="dash-time mt-1 block w-fit text-sm text-muted-foreground"
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
      <td className="px-5 py-2 text-right">
        <ActionMenu label={t("repositories.moreActions", { name: repo.name })} actions={actions} />
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

type BulkResult = {
  created: { id: string; name: string; url: string; scanId: string }[];
  skipped: { url: string; reason: "duplicate" }[];
};

function AddRepositoryDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  /** Several https:// repositories at once, all with the same access. */
  const [many, setMany] = useState(false);
  const [urlList, setUrlList] = useState("");
  const [access, setAccess] = useState<RepositoryRow["authKind"]>("none");
  /** Set after an SSH repository was added: the key the user now adds to the forge. */
  const [created, setCreated] = useState<{ id: string; deployPublicKey: string } | null>(null);
  /** Set after several repositories were added and some were already connected. */
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const urls = parseUrlList(urlList);

  function fail(e: unknown, sent: string[] = []) {
    if (!(e instanceof ApiError)) return setError(t("errors.network"));
    if (e.code === "duplicate") return setError(t("repositories.errorDuplicate"));
    if (e.code === "auth-mismatch") {
      const ssh = (e.problem as { urls?: string[] } | undefined)?.urls;
      return setError(
        ssh?.length
          ? t("repositories.errorSshMany", { urls: ssh.join(", ") })
          : t("repositories.errorAuthMismatch"),
      );
    }
    if (e.status === 422) {
      const errors: Record<string, string> = {};
      for (const x of e.problem?.errors ?? []) {
        const [field, index] = x.path.split(".");
        if (!field || errors[field]) continue;
        const url = field === "urls" && index !== undefined ? sent[Number(index)] : undefined;
        errors[field] = url ? t("repositories.errorUrlInvalid", { url }) : x.message;
      }
      setFieldErrors(errors);
      return setError(t("repositories.errorInvalid"));
    }
    setError(t("errors.generic"));
  }

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
    onError: (e) => fail(e),
  });

  const createMany = useMutation({
    mutationFn: (body: { urls: string[] } & Record<string, unknown>) =>
      api<BulkResult>("/repositories/bulk", { method: "POST", body }),
    onSuccess: async (result) => {
      await queryClient.invalidateQueries();
      if (result.skipped.length > 0) setBulkResult(result);
      else onClose();
    },
    onError: (e, body) => fail(e, body.urls),
  });

  useEffect(() => {
    if (!open) {
      setError(null);
      setFieldErrors({});
      setAccess("none");
      setMany(false);
      setUrlList("");
      setCreated(null);
      setBulkResult(null);
    }
  }, [open]);

  const firstScan = useMutation({
    mutationFn: (id: string) => api(`/repositories/${id}/scans`, { method: "POST" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
      onClose();
    },
    onError: () => setError(t("errors.generic")),
  });

  function switchMode(next: boolean) {
    setMany(next);
    setError(null);
    setFieldErrors({});
    // Deploy keys are created per repository, so the list offers public access and tokens only.
    if (next && access === "ssh-deploy-key") setAccess("none");
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const optional = (key: string) => String(form.get(key) ?? "").trim() || undefined;
    const auth =
      access === "https-token" ? { kind: "https-token", token: String(form.get("token")) } : { kind: access };
    setError(null);
    setFieldErrors({});
    if (!many) {
      create.mutate({
        url: String(form.get("url")).trim(),
        name: optional("name"),
        branch: optional("branch"),
        auth,
      });
      return;
    }
    if (urls.length === 0) return setFieldErrors({ urls: t("repositories.errorUrlsEmpty") });
    if (urls.length > BULK_LIMIT) {
      return setFieldErrors({ urls: t("repositories.errorUrlsTooMany", { max: BULK_LIMIT }) });
    }
    createMany.mutate({ urls, branch: optional("branch"), auth });
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
          {error ? <Alert tone="error">{error}</Alert> : null}
          <DeployKeyInstructions publicKey={created.deployPublicKey} />
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("repositories.later")}
            </Button>
            <Button disabled={firstScan.isPending} onClick={() => firstScan.mutate(created.id)}>
              {firstScan.isPending ? t("common.loading") : t("repositories.startFirstScan")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
    );
  }

  if (bulkResult) {
    return (
      <Dialog open={open} onClose={onClose} title={t("repositories.bulkResultTitle")}>
        <div className="grid gap-4">
          <p>{t("repositories.bulkAdded", { count: bulkResult.created.length })}</p>
          <div className="grid gap-1.5">
            <p className="text-sm font-medium">{t("repositories.bulkSkipped")}</p>
            <ul className="grid gap-1 font-mono text-sm break-all text-muted-foreground">
              {bulkResult.skipped.map((s) => (
                <li key={s.url}>{s.url}</li>
              ))}
            </ul>
          </div>
          <DialogFooter>
            <Button onClick={onClose}>{t("common.close")}</Button>
          </DialogFooter>
        </div>
      </Dialog>
    );
  }

  const pending = create.isPending || createMany.isPending;
  const kinds = many
    ? (["none", "https-token"] as const)
    : (["none", "https-token", "ssh-deploy-key"] as const);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("repositories.addTitle")}
      description={t("repositories.addDescription")}
    >
      <form className="grid gap-4" onSubmit={submit} noValidate={many}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        {many ? (
          <TextAreaField
            label={t("repositories.urls")}
            hint={t("repositories.urlsHint", { max: BULK_LIMIT })}
            error={fieldErrors.urls}
            name="urls"
            rows={6}
            value={urlList}
            onChange={(e) => setUrlList(e.currentTarget.value)}
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
        ) : (
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
        )}
        <div>
          <button
            type="button"
            className="text-sm font-medium text-primary underline-offset-4 hover:underline"
            onClick={() => switchMode(!many)}
          >
            {many ? t("repositories.addOne") : t("repositories.addSeveral")}
          </button>
        </div>
        {many ? null : (
          <Field
            label={t("repositories.name")}
            hint={t("repositories.nameHint")}
            error={fieldErrors.name}
            name="name"
            maxLength={120}
          />
        )}
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
          {kinds.map((kind) => (
            <label key={kind} className="flex items-center gap-2.5">
              <Radio name="access" value={kind} checked={access === kind} onChange={() => setAccess(kind)} />
              {t(ACCESS_LABELS[kind])}
            </label>
          ))}
        </fieldset>
        {access === "https-token" ? (
          <Field
            label={t("repositories.token")}
            hint={many ? t("repositories.tokenHintMany") : t("repositories.tokenHint")}
            error={fieldErrors.auth}
            name="token"
            type="password"
            required
            minLength={8}
            maxLength={500}
            autoComplete="off"
          />
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("repositories.cancel")}
          </Button>
          <Button type="submit" disabled={pending}>
            {pending
              ? t("common.loading")
              : many
                ? t("repositories.submitMany", { count: urls.length })
                : access === "ssh-deploy-key"
                  ? t("repositories.submitKey")
                  : t("repositories.submit")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
