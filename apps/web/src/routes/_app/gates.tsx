import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { ExternalLink, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Segmented } from "../../components/filters.tsx";
import { GateBadge } from "../../components/gate-badge.tsx";
import { isAdmin } from "../../components/nav.ts";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { Pagination } from "../../components/pagination.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { RepositoryLink } from "../../components/repository-link.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { Badge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { ConfirmDialog } from "../../components/ui/confirm-dialog.tsx";
import { CopyButton } from "../../components/ui/copy-button.tsx";
import { Field } from "../../components/ui/field.tsx";
import { Select } from "../../components/ui/select.tsx";
import { api } from "../../lib/api.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { type GateSearch, gateSearch, toQuery } from "../../lib/search.ts";
import type {
  GateMatches,
  GateMode,
  GateRuleState,
  GateRunRow,
  GateTokenRow,
  Page,
  RepositoryRow,
} from "../../lib/types.ts";

export const Route = createFileRoute("/_app/gates")({
  validateSearch: gateSearch,
  component: GatesPage,
});

const MODES: GateMode[] = ["off", "report", "block"];
const MODE_TONE = { off: "neutral", report: "medium", block: "critical" } as const;
const GATES_DOCS = "https://github.com/lcsfls/garnet-ops/blob/main/docs/quality-gates.md";

/** Quality gates (mockup): rules, recent runs, and how a pipeline asks for a result (ADR 0008). */
function GatesPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const setSearch = (patch: Partial<GateSearch>) => navigate({ search: (prev) => ({ ...prev, ...patch }) });
  return (
    <>
      <PageHeader icon={ShieldCheck} title={t("gates.title")} description={t("gates.description")} />
      <div
        className={cn(
          "grid items-start gap-4",
          "@wide:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)] @wide:[grid-template-areas:'rules_pipeline'_'runs_runs']",
          "@xwide:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)_minmax(0,0.9fr)] @xwide:[grid-template-areas:'rules_runs_pipeline']",
        )}
      >
        <div className="min-w-0 @wide:[grid-area:rules]">
          <Rules canEdit={isAdmin(me)} />
        </div>
        <div className="min-w-0 @wide:[grid-area:runs]">
          <Runs
            search={search}
            onCursor={(cursor) => setSearch({ cursor })}
            onPageSize={(pageSize) => setSearch({ pageSize, cursor: undefined })}
          />
        </div>
        <div className="min-w-0 @wide:[grid-area:pipeline]">
          <Pipeline
            admin={isAdmin(me)}
            repositoryId={search.repositoryId}
            onRepository={(repositoryId) => setSearch({ repositoryId })}
          />
        </div>
      </div>
    </>
  );
}

function Rules({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const rules = useQuery({ queryKey: ["gate-rules"], queryFn: () => api<GateRuleState[]>("/gates/rules") });
  const [saved, setSaved] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (input: { rule: string; mode: GateMode; deniedLicenses?: string[] }) =>
      api(`/gates/rules/${input.rule}`, {
        method: "PUT",
        body: { mode: input.mode, deniedLicenses: input.deniedLicenses },
      }),
    onSuccess: async (_, input) => {
      setSaved(input.rule);
      await queryClient.invalidateQueries({ queryKey: ["gate-rules"] });
    },
  });
  return (
    <Card>
      <CardHeader title={t("gates.rulesTitle")} description={t("gates.rulesDescription")} />
      <QueryStatus query={rules} />
      {save.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      <ul>
        {rules.data?.map((rule) => (
          <li key={rule.rule} className="grid gap-3 border-t px-5 py-3">
            <div className="flex flex-wrap items-start gap-3">
              <Badge tone={MODE_TONE[rule.mode]} className="mt-0.5">
                {t(`gates.mode.${rule.mode}`)}
              </Badge>
              <div className="min-w-0 flex-[1_1_14rem]">
                <div className="font-medium">{t(`gates.rule.${rule.rule}`)}</div>
                <div className="text-[13.5px] text-muted-foreground">{t(`gates.ruleHint.${rule.rule}`)}</div>
              </div>
              {canEdit ? (
                <Segmented
                  label={t("gates.modeLabel", { rule: t(`gates.rule.${rule.rule}`) })}
                  value={rule.mode}
                  options={MODES.map((mode) => ({ value: mode, label: t(`gates.mode.${mode}`) }))}
                  onChange={(mode) => save.mutate({ rule: rule.rule, mode })}
                />
              ) : null}
            </div>
            <p className="text-[13px] text-muted-foreground">{t(`gates.modeHint.${rule.mode}`)}</p>
            {rule.rule === "license-denied" && canEdit ? (
              <LicenseList
                value={rule.deniedLicenses ?? []}
                pending={save.isPending}
                onSave={(deniedLicenses) => save.mutate({ rule: rule.rule, mode: rule.mode, deniedLicenses })}
              />
            ) : null}
            {saved === rule.rule && save.isSuccess ? (
              <p role="status" className="text-[13px] text-muted-foreground">
                {t("gates.saved")}
              </p>
            ) : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function LicenseList({
  value,
  pending,
  onSave,
}: {
  value: string[];
  pending: boolean;
  onSave: (list: string[]) => void;
}) {
  const { t } = useTranslation();
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const raw = String(new FormData(event.currentTarget).get("licenses") ?? "");
    onSave([
      ...new Set(
        raw
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    ]);
  }
  return (
    <form className="grid gap-2" onSubmit={submit}>
      <Field
        label={t("gates.deniedLicenses")}
        hint={t("gates.deniedLicensesHint")}
        name="licenses"
        defaultValue={value.join(", ")}
        spellCheck={false}
        className="font-mono text-sm"
      />
      <div>
        <Button type="submit" variant="outline" disabled={pending}>
          {t("gates.saveLicenses")}
        </Button>
      </div>
    </form>
  );
}

/** "2 × Critical vulnerability with a fix (blocks)" for each matching rule. */
export function useGateReason() {
  const { t } = useTranslation();
  return (matches: GateMatches) => {
    const parts = Object.entries(matches).map(
      ([rule, m]) =>
        `${t("gates.reasonPart", { count: m.count, rule: t(`gates.rule.${rule as GateRuleState["rule"]}`) })}${m.mode === "block" ? ` (${t("gates.blocks")})` : ""}`,
    );
    return parts.length ? parts.join(", ") : t("gates.reasonNone");
  };
}

function Runs({
  search,
  onCursor,
  onPageSize,
}: {
  search: GateSearch;
  onCursor: (cursor: string | undefined) => void;
  onPageSize: (pageSize: GateSearch["pageSize"]) => void;
}) {
  const { t } = useTranslation();
  const reason = useGateReason();
  const runs = useQuery({
    queryKey: ["gate-runs", search.cursor, search.pageSize],
    queryFn: () =>
      api<Page<GateRunRow>>(`/gates/runs${toQuery({ cursor: search.cursor, pageSize: search.pageSize })}`),
    placeholderData: keepPreviousData,
  });
  const duration = (run: GateRunRow) => {
    if (!run.startedAt || !run.finishedAt) return "–";
    const s = Math.max(0, Math.round((Date.parse(run.finishedAt) - Date.parse(run.startedAt)) / 1000));
    return s < 60
      ? t("gates.seconds", { count: s })
      : t("gates.minutes", { minutes: Math.floor(s / 60), seconds: s % 60 });
  };
  return (
    <Card>
      <CardHeader title={t("gates.runsTitle")} description={t("gates.runsDescription")} />
      <QueryStatus query={runs} />
      {runs.data && runs.data.items.length === 0 ? (
        <p className="px-5 pb-6 text-muted-foreground">{t("gates.runsEmpty")}</p>
      ) : null}
      {runs.data && runs.data.items.length > 0 ? (
        <>
          <table className="w-full text-left">
            <thead className="text-sm text-muted-foreground">
              <tr className="border-b">
                <th className="px-5 py-2.5 font-medium">{t("findings.columnRepository")}</th>
                <th className="px-3 py-2.5 font-medium">{t("gates.columnTrigger")}</th>
                <th className="px-3 py-2.5 font-medium">{t("gates.columnResult")}</th>
                <th className="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("gates.columnReason")}</th>
                <th className="hidden px-3 py-2.5 text-right font-medium @wide:table-cell">
                  {t("gates.columnDuration")}
                </th>
                <th className="px-5 py-2.5 font-medium">{t("gates.columnTime")}</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id} className="border-b align-top last:border-0">
                  <td className="px-5 py-2.5">
                    <RepositoryLink id={run.repositoryId} name={run.repositoryName} className="font-medium" />
                  </td>
                  <td className="px-3 py-2.5 text-sm">
                    {t(`gates.trigger.${run.trigger}`)}
                    {run.ref || run.commitSha ? (
                      <div className="font-mono text-[13px] break-all text-muted-foreground">
                        {[run.ref ?? run.branch, run.commitSha?.slice(0, 7)].filter(Boolean).join(" · ")}
                      </div>
                    ) : null}
                  </td>
                  <td className="px-3 py-2.5">
                    <GateBadge result={run.result} />
                  </td>
                  <td className="hidden px-3 py-2.5 text-sm text-muted-foreground @3xl:table-cell">
                    {reason(run.matches)}
                  </td>
                  <td className="hidden px-3 py-2.5 text-right text-sm tabular-nums @wide:table-cell">
                    {duration(run)}
                  </td>
                  <td className="px-5 py-2.5 text-sm whitespace-nowrap">
                    <time
                      dateTime={run.createdAt}
                      title={formatDateTime(run.createdAt)}
                      className="dash-time"
                    >
                      {formatRelative(run.createdAt)}
                    </time>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={runs.data} onCursor={onCursor} onPageSize={onPageSize} />
        </>
      ) : null}
    </Card>
  );
}

/** The pipeline step to copy, with the server's own address. */
function pipelineStep(origin: string) {
  return `- name: GarnetOps quality gate
  env:
    GARNETOPS_URL: ${origin}
    GARNETOPS_TOKEN: \${{ secrets.GARNETOPS_TOKEN }}
    REF: refs/pull/\${{ github.event.number }}/head
    SHA: \${{ github.event.pull_request.head.sha }}
  run: |
    auth="Authorization: Bearer $GARNETOPS_TOKEN"
    id=$(curl -fsS -X POST "$GARNETOPS_URL/api/v1/gate/checks" -H "$auth" \\
      -H "Content-Type: application/json" -d "{\\"ref\\":\\"$REF\\",\\"sha\\":\\"$SHA\\"}" | jq -r .id)
    while :; do
      r=$(curl -fsS "$GARNETOPS_URL/api/v1/gate/checks/$id" -H "$auth")
      case $(echo "$r" | jq -r .state) in queued|running) sleep 10 ;; *) break ;; esac
    done
    echo "$r" | jq .
    [ "$(echo "$r" | jq -r .state)" = succeeded ] && [ "$(echo "$r" | jq -r .result)" != blocked ]`;
}

function Pipeline({
  admin,
  repositoryId,
  onRepository,
}: {
  admin: boolean;
  repositoryId: string | undefined;
  onRepository: (id: string | undefined) => void;
}) {
  const { t } = useTranslation();
  const repositories = useQuery({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  });
  const step = pipelineStep(window.location.origin);
  return (
    <Card>
      <CardHeader title={t("gates.pipelineTitle")} description={t("gates.pipelineDescription")} />
      <div className="grid gap-4 px-5 pb-5">
        <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed">
          <code>{step}</code>
        </pre>
        <div className="flex flex-wrap items-center gap-3">
          <CopyButton text={step} />
          <a
            href={GATES_DOCS}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm text-primary-text underline-offset-4 hover:underline"
          >
            {t("gates.pipelineDocs")}
            <ExternalLink aria-hidden="true" className="size-3.5" />
          </a>
        </div>
        <p className="text-sm text-muted-foreground">{t("gates.pipelineHint")}</p>

        <section aria-labelledby="gate-tokens" className="grid gap-3 border-t pt-4">
          <h3 id="gate-tokens" className="flex items-center gap-2 font-medium">
            <KeyRound aria-hidden="true" className="size-4" />
            {t("gates.tokensTitle")}
          </h3>
          {admin ? (
            <>
              <Select
                aria-label={t("gates.repository")}
                value={repositoryId ?? ""}
                onChange={(e) => onRepository(e.target.value || undefined)}
              >
                <option value="">{t("gates.chooseRepository")}</option>
                {repositories.data?.items.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </Select>
              {repositoryId ? <Tokens key={repositoryId} repositoryId={repositoryId} /> : null}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">{t("gates.adminOnly")}</p>
          )}
        </section>
      </div>
    </Card>
  );
}

function Tokens({ repositoryId }: { repositoryId: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const key = ["gate-tokens", repositoryId];
  const tokens = useQuery({
    queryKey: key,
    queryFn: () => api<GateTokenRow[]>(`/gates/repositories/${repositoryId}/tokens`),
  });
  const [created, setCreated] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<GateTokenRow | null>(null);
  const create = useMutation({
    mutationFn: (label: string) =>
      api<{ token: string }>(`/gates/repositories/${repositoryId}/tokens`, {
        method: "POST",
        body: { label },
      }),
    onSuccess: async (result) => {
      setCreated(result.token);
      await queryClient.invalidateQueries({ queryKey: key });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/gates/repositories/${repositoryId}/tokens/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setRevoking(null);
      await queryClient.invalidateQueries({ queryKey: key });
    },
  });
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const label = String(new FormData(form).get("label") ?? "").trim();
    if (label) create.mutate(label, { onSuccess: () => form.reset() });
  }
  return (
    <div className="grid gap-3">
      <p className="text-sm text-muted-foreground">{t("gates.tokensHint")}</p>
      {created ? (
        <div className="grid gap-2">
          <Alert tone="info">{t("gates.tokenCreated")}</Alert>
          <code className="rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">{created}</code>
          <div>
            <CopyButton text={created} />
          </div>
        </div>
      ) : null}
      <QueryStatus query={tokens} />
      {tokens.data && tokens.data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("gates.tokensEmpty")}</p>
      ) : null}
      <ul className="grid gap-2">
        {tokens.data?.map((token) => (
          <li key={token.id} className="flex flex-wrap items-center gap-3 rounded-md border px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="font-medium">{token.label}</div>
              <div className="text-[13px] text-muted-foreground">
                <span className="font-mono">{token.prefix}…</span> ·{" "}
                {token.lastUsedAt
                  ? t("gates.lastUsed", { when: formatRelative(token.lastUsedAt) })
                  : t("gates.neverUsed")}
              </div>
            </div>
            <Button
              variant="ghost"
              onClick={() => setRevoking(token)}
              aria-label={`${t("gates.revoke")}: ${token.label}`}
            >
              <Trash2 aria-hidden="true" className="size-4" />
              {t("gates.revoke")}
            </Button>
          </li>
        ))}
      </ul>
      <form className="grid gap-2" onSubmit={submit}>
        <Field
          label={t("gates.tokenLabel")}
          hint={t("gates.tokenLabelHint")}
          name="label"
          required
          maxLength={80}
        />
        <div>
          <Button type="submit" variant="outline" disabled={create.isPending}>
            {t("gates.createToken")}
          </Button>
        </div>
        {create.isError ? <Alert tone="error">{t("errors.actionFailed")}</Alert> : null}
      </form>
      <ConfirmDialog
        open={revoking !== null}
        title={t("gates.revokeTitle", { label: revoking?.label ?? "" })}
        description={t("gates.revokeDescription")}
        confirmLabel={t("gates.revoke")}
        pending={revoke.isPending}
        error={revoke.isError ? t("errors.actionFailed") : null}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
        onClose={() => setRevoking(null)}
      />
    </div>
  );
}
