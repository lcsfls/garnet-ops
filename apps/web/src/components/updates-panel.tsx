import {
  type AdminMessages,
  adminMessagesFor,
  describeCode,
  formatLeadTime,
  formatMessage,
  interpolate,
  type Messages,
  messagesFor,
} from "@restow-backup/cicd-updater/messages";
import type { ReleasesView, StateView } from "@restow-backup/cicd-updater/protocol";
import { formatCountdown, useCountdown } from "@restow-backup/cicd-updater/react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, RefreshCw } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import type { Me } from "../lib/session.ts";
import { notifyMaintenanceChanged, updatesApi } from "../lib/updates.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { StepUpDialog } from "./step-up-dialog.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { FormField, FormRow } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";

/** Manual update steps and the recovery runbook (docs/updating.md). */
export const UPDATING_DOCS = "https://github.com/lcsfls/garnet-ops/blob/main/docs/updating.md";
const RUNBOOK_DOCS = `${UPDATING_DOCS}#an-update-needs-attention`;

/** One sentence for an error answer; sidecar codes go through the cicd-updater catalogs. */
function explain(error: unknown, messages: Messages, texts: AdminMessages): string {
  if (!(error instanceof ApiError)) return texts.offline;
  const problem = (error.problem ?? {}) as {
    blockers?: { code: string }[];
    reasons?: string[];
    feedError?: string;
  };
  switch (error.code) {
    case "forbidden":
    case "unauthenticated":
      return texts.forbidden;
    case "step-up-required":
      return texts.stepUp;
    case "updater_unavailable":
      return texts.noSidecar;
    case "blocked":
      return [
        describeCode(messages, "problems", "blocked"),
        ...(problem.blockers ?? []).map((b) => describeCode(messages, "blockers", b.code)),
      ].join(" ");
    case "release_refused":
      return [
        describeCode(messages, "problems", "release_refused"),
        ...(problem.reasons ?? []).map((r) => describeCode(messages, "refusals", r)),
      ].join(" ");
    case "feed_unavailable":
      return [
        describeCode(messages, "problems", "feed_unavailable"),
        problem.feedError ? describeCode(messages, "feedErrors", problem.feedError) : "",
      ].join(" ");
    default:
      return error.code ? describeCode(messages, "problems", error.code) : texts.offline;
  }
}

/**
 * The Updates section of the settings (owners and admins). Shows the running version,
 * what blocks updates, the next release with its notes, a schedule form, the live state
 * of a run with cancel, and the result with acknowledge. Without the optional sidecar
 * it shows how to update by hand.
 */
export function UpdatesPanel({ me }: { me: Me }) {
  const { t, i18n } = useTranslation();
  const messages = messagesFor(i18n.language);
  const texts = adminMessagesFor(i18n.language);
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<(() => void) | null>(null);

  const status = useQuery({
    queryKey: ["updates"],
    queryFn: updatesApi.status,
    // Follow a scheduled or running update closely; otherwise check now and then.
    refetchInterval: (q) => {
      const phase = q.state.data?.state?.phase;
      return phase === "scheduled" || phase === "running" || q.state.status === "error" ? 3_000 : 30_000;
    },
    retry: false,
  });
  const state = status.data?.state ?? null;
  const releases = useQuery({
    queryKey: ["updates", "releases", state?.running.version ?? null],
    queryFn: () => updatesApi.releases(false),
    enabled: state !== null,
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 5 * 60_000,
  });

  const refresh = async (next: StateView | null) => {
    if (next) queryClient.setQueryData(["updates"], { ...status.data, state: next });
    await queryClient.invalidateQueries({ queryKey: ["updates"] });
  };

  const action = useMutation({
    mutationFn: (run: () => Promise<StateView>) => run(),
    onMutate: () => {
      setActionError(null);
      setNotice("");
    },
  });
  const act = (run: () => Promise<StateView>, done: string): void =>
    action.mutate(run, {
      onSuccess: async (next) => {
        setNotice(done);
        notifyMaintenanceChanged();
        await refresh(next);
      },
      onError: (error) => {
        if (error instanceof ApiError && error.code === "step-up-required") {
          // Confirm the sign-in, then try the same action again.
          setStepUp(() => () => act(run, done));
          return;
        }
        setActionError(explain(error, messages, texts));
      },
    });

  return (
    <>
      <Card>
        <CardHeader title={texts.title} description={t("settings.updatesDescription")} />
        <div className="grid gap-4 px-5 py-5">
          <output aria-live="polite" className={notice ? "text-sm text-muted-foreground" : "sr-only"}>
            {notice}
          </output>
          {actionError ? <Alert tone="error">{actionError}</Alert> : null}
          {status.isError && !status.data ? (
            <Alert tone="error">{explain(status.error, messages, texts)}</Alert>
          ) : !status.data ? (
            <p role="status" className="text-muted-foreground">
              {texts.loading}
            </p>
          ) : !state ? (
            <NoSidecar texts={texts} />
          ) : (
            <Overview state={state} messages={messages} texts={texts} offline={status.isError} />
          )}
        </div>
      </Card>

      {state?.run && state.phase !== "idle" ? (
        <RunPanel
          state={state}
          messages={messages}
          texts={texts}
          busy={action.isPending}
          onCancel={(runId) => act(() => updatesApi.cancel(runId), texts.cancelled)}
          onAcknowledge={(runId) => act(() => updatesApi.acknowledge(runId), texts.acknowledged)}
        />
      ) : null}

      {state ? (
        <ReleasePanel
          releases={releases.data ?? null}
          error={releases.isError ? explain(releases.error, messages, texts) : null}
          checking={releases.isFetching}
          leadTimes={status.data?.leadTimes ?? []}
          blockedReason={
            state.phase === "scheduled" || state.phase === "running"
              ? texts.busyRun
              : state.capabilities.ready
                ? null
                : describeCode(messages, "problems", "blocked")
          }
          messages={messages}
          texts={texts}
          busy={action.isPending}
          onRefresh={() =>
            queryClient.fetchQuery({
              queryKey: ["updates", "releases", state.running.version],
              queryFn: () => updatesApi.releases(true),
            })
          }
          onSchedule={(input) =>
            act(() => updatesApi.schedule(input), interpolate(texts.scheduled, { version: input.version }))
          }
        />
      ) : null}

      <StepUpDialog
        open={stepUp !== null}
        email={me.user.email}
        onClose={() => setStepUp(null)}
        onConfirmed={() => {
          const retry = stepUp;
          setStepUp(null);
          retry?.();
        }}
      />
    </>
  );
}

/** Until the first release there are no signed images; installations build them from the repository. */
const SOURCE_UPDATE = [
  "git pull",
  "docker build --target app -t garnetops:local --build-arg VERSION=0.0.3 .",
  "docker build --target web -t garnetops-web:local --build-arg VERSION=0.0.3 .",
  "docker compose up -d",
].join("\n");

function NoSidecar({ texts }: { texts: AdminMessages }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-3">
      <Alert tone="info">{texts.noSidecar}</Alert>
      <p className="text-muted-foreground">{t("settings.updatesManual")}</p>
      <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm">
        <code>{SOURCE_UPDATE}</code>
      </pre>
      <a
        href={UPDATING_DOCS}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1.5 text-primary-text underline-offset-4 hover:underline"
      >
        {texts.manualSteps}
        <ExternalLink aria-hidden="true" className="size-3.5" />
      </a>
    </div>
  );
}

function Overview({
  state,
  messages,
  texts,
  offline,
}: {
  state: StateView;
  messages: Messages;
  texts: AdminMessages;
  offline: boolean;
}) {
  const { t } = useTranslation();
  // Unsigned mode has its own, stronger notice above; the same warning is not listed twice.
  const warnings = state.capabilities.warnings.filter((w) => w.code !== "trust_mode_none");
  return (
    <>
      {offline ? <Alert tone="info">{texts.offline}</Alert> : null}
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2">
        <dt className="text-muted-foreground">{texts.runningVersion}</dt>
        <dd className="font-mono">{state.running.version ?? texts.unknownVersion}</dd>
        <dt className="text-muted-foreground">{t("settings.updatesTrust")}</dt>
        <dd>{t(`settings.updatesTrustMode.${state.trust.mode}`)}</dd>
        <dt className="text-muted-foreground">{t("settings.updatesUpdater")}</dt>
        <dd className="font-mono">{state.updater.version}</dd>
      </dl>
      {state.trust.mode === "none" ? <Alert tone="error">{messages.ui.trustModeNone}</Alert> : null}
      {state.capabilities.blockers.length > 0 ? (
        <Alert tone="error">
          <p>{texts.blocked}</p>
          <ul className="mt-1 list-disc pl-5">
            {state.capabilities.blockers.map((b) => (
              <li key={b.code}>{describeCode(messages, "blockers", b.code)}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      {warnings.length > 0 ? (
        <Alert tone="info">
          <p>{texts.warnings}</p>
          <ul className="mt-1 list-disc pl-5">
            {warnings.map((w) => (
              <li key={w.code}>{describeCode(messages, "warnings", w.code)}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
    </>
  );
}

function RunPanel({
  state,
  messages,
  texts,
  busy,
  onCancel,
  onAcknowledge,
}: {
  state: StateView;
  messages: Messages;
  texts: AdminMessages;
  busy: boolean;
  onCancel: (runId: string) => void;
  onAcknowledge: (runId: string) => void;
}) {
  const run = state.run;
  const offsetMs = Date.parse(state.serverTime) - Date.now();
  const countdown = useCountdown(state.phase === "scheduled" ? (run?.startsAt ?? null) : null, offsetMs);
  if (!run) return null;
  const finished = state.phase === "succeeded" || state.phase === "failed";
  const detail = run.outcome
    ? messages.outcomes[run.outcome]
    : state.phase === "scheduled"
      ? ""
      : formatMessage(messages, run.message);

  return (
    <Card>
      <CardHeader title={texts.currentRun} />
      <div className="grid gap-3 px-5 py-5">
        <p aria-live="polite">
          <span className="font-semibold">{messages.phases[state.phase]}</span>{" "}
          <span className="text-muted-foreground">{detail}</span>
        </p>
        {state.phase === "scheduled" ? (
          <p className="font-mono tabular-nums">
            {countdown && countdown > 0
              ? interpolate(messages.ui.startsIn, { time: formatCountdown(countdown) })
              : messages.ui.startingNow}
          </p>
        ) : null}
        <p className="text-sm text-muted-foreground">
          {interpolate(texts.versions, {
            from: run.fromVersion ?? texts.unknownVersion,
            to: run.targetVersion,
          })}
          . {interpolate(texts.requestedBy, { label: run.requestedBy.label })}.
        </p>
        {state.phase === "running" ? (
          <>
            <progress
              max={100}
              value={run.progress}
              aria-label={texts.progressLabel}
              className="h-2 w-full overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info"
            />
            <ol className="flex flex-wrap gap-1.5">
              {run.steps
                .filter((step) => step.status !== "skipped")
                .map((step) => (
                  <li key={step.id}>
                    <Badge
                      className={cn(
                        step.status === "done" && "bg-muted text-foreground",
                        step.status === "running" && "bg-info/15 text-info-text",
                        step.status === "failed" && "bg-destructive/15 text-destructive-text",
                        step.status === "pending" && "bg-muted text-muted-foreground",
                      )}
                    >
                      {messages.steps[step.id]}
                    </Badge>
                  </li>
                ))}
            </ol>
          </>
        ) : null}
        {run.abortRequestedAt ? <p>{texts.abortRequested}</p> : null}
        {run.failure ? (
          <Alert tone="error">{describeCode(messages, "failures", run.failure.code)}</Alert>
        ) : null}
        {run.outcome === "needs_attention" ? <AttentionGuide run={run} texts={texts} /> : null}
        <div className="flex gap-2">
          {(state.phase === "scheduled" || state.phase === "running") && !run.abortRequestedAt ? (
            <Button variant="destructive" disabled={busy} onClick={() => onCancel(run.id)}>
              {texts.cancel}
            </Button>
          ) : null}
          {finished ? (
            <Button variant="outline" disabled={busy} onClick={() => onAcknowledge(run.id)}>
              {texts.acknowledge}
            </Button>
          ) : null}
        </div>
      </div>
    </Card>
  );
}

/** What an admin needs when an update ended in needs_attention. */
function AttentionGuide({ run, texts }: { run: NonNullable<StateView["run"]>; texts: AdminMessages }) {
  const schemaChanged = run.failure?.schemaChanged ?? null;
  return (
    <div className="grid gap-2 rounded-md border border-destructive/40 px-4 py-3">
      <h3 className="font-semibold">{texts.attentionTitle}</h3>
      <p>{texts.attentionBody}</p>
      <p>
        {schemaChanged === true
          ? texts.attentionSchemaChanged
          : schemaChanged === false
            ? texts.attentionSchemaUnchanged
            : texts.attentionSchemaUnknown}
      </p>
      {run.recovery?.backup ? (
        <p className="break-all">{interpolate(texts.attentionBackup, { file: run.recovery.backup.file })}</p>
      ) : null}
      <p>{texts.attentionCommand}</p>
      <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm">
        <code>docker compose exec updater cicd-updater recover show</code>
      </pre>
      {run.recovery && run.recovery.commands.length > 0 ? (
        <details>
          <summary className="cursor-pointer">{texts.attentionCommands}</summary>
          <pre className="mt-2 overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm">
            <code>{run.recovery.commands.join("\n")}</code>
          </pre>
        </details>
      ) : null}
      <p>
        <a
          href={RUNBOOK_DOCS}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary-text underline-offset-4 hover:underline"
        >
          {texts.attentionRunbook}
        </a>
        . {texts.attentionAcknowledge}
      </p>
    </div>
  );
}

function ReleasePanel({
  releases,
  error,
  checking,
  leadTimes,
  blockedReason,
  messages,
  texts,
  busy,
  onRefresh,
  onSchedule,
}: {
  releases: ReleasesView | null;
  error: string | null;
  checking: boolean;
  leadTimes: readonly number[];
  blockedReason: string | null;
  messages: Messages;
  texts: AdminMessages;
  busy: boolean;
  onRefresh: () => void;
  onSchedule: (input: { version: string; leadSeconds: number; releaseSha256: string }) => void;
}) {
  const installable = (releases?.releases ?? []).filter(
    (r) => r.refusals.length === 0 && r.releaseSha256 !== null,
  );
  const refused = (releases?.releases ?? []).filter(
    (r) => r.refusals.length > 0 && !r.refusals.includes("not_newer"),
  );
  const [version, setVersion] = useState("");
  const [leadSeconds, setLeadSeconds] = useState(leadTimes.includes(900) ? 900 : (leadTimes[0] ?? 0));
  const chosen =
    installable.find((r) => r.version === version) ??
    installable.find((r) => r.version === releases?.nextInstallable) ??
    installable[0];

  function submit(event: FormEvent) {
    event.preventDefault();
    if (chosen?.releaseSha256) {
      onSchedule({ version: chosen.version, leadSeconds, releaseSha256: chosen.releaseSha256 });
    }
  }

  return (
    <Card>
      <CardHeader
        title={texts.available}
        actions={
          <Button variant="outline" className="h-9" disabled={busy || checking} onClick={onRefresh}>
            <RefreshCw aria-hidden="true" className={cn("size-4", checking && "motion-safe:animate-spin")} />
            {texts.checkAgain}
          </Button>
        }
      />
      <div className="grid gap-4 px-5 py-5">
        {error ? (
          <Alert tone="error">{error}</Alert>
        ) : !releases ? (
          <p role="status" className="text-muted-foreground">
            {texts.checking}
          </p>
        ) : !chosen ? (
          <p>{refused.length === 0 ? texts.newest : texts.nothingInstallable}</p>
        ) : (
          <form className="grid gap-4" onSubmit={submit}>
            <FormRow columns={2} from="md">
              <FormField id="update-version" label={texts.version}>
                {(control) => (
                  <Select {...control} value={chosen.version} onChange={(e) => setVersion(e.target.value)}>
                    {installable.map((r) => (
                      <option key={r.version} value={r.version}>
                        {r.version}
                      </option>
                    ))}
                  </Select>
                )}
              </FormField>
              <FormField id="update-start" label={texts.start}>
                {(control) => (
                  <Select
                    {...control}
                    value={leadSeconds}
                    onChange={(e) => setLeadSeconds(Number(e.target.value))}
                  >
                    {leadTimes.map((seconds) => (
                      <option key={seconds} value={seconds}>
                        {formatLeadTime(texts, seconds)}
                      </option>
                    ))}
                  </Select>
                )}
              </FormField>
            </FormRow>
            <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
              {chosen.notesUrl ? (
                <a
                  href={chosen.notesUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-primary-text underline-offset-4 hover:underline"
                >
                  {texts.notes}
                  <ExternalLink aria-hidden="true" className="size-3.5" />
                </a>
              ) : null}
              {chosen.releaseSha256 ? (
                <span className="font-mono">
                  {interpolate(texts.releaseDigest, { sha: chosen.releaseSha256.slice(0, 16) })}
                </span>
              ) : null}
            </p>
            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" disabled={busy || blockedReason !== null}>
                {texts.schedule}
              </Button>
              {blockedReason ? <span className="text-sm text-muted-foreground">{blockedReason}</span> : null}
            </div>
          </form>
        )}
        {refused.length > 0 ? (
          <ul className="grid gap-1 text-sm text-muted-foreground">
            {refused.map((r) => (
              <li key={r.version}>
                <span className="font-mono text-foreground">{r.version}</span>:{" "}
                {r.refusals.map((code) => describeCode(messages, "refusals", code)).join(" ")}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}
