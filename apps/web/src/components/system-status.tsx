import type { StatusLevel } from "@garnetops/core/system-status";
import type {
  InstanceStatus,
  IntegrationPartStatus,
  IntegrationStatus,
  Reason,
  SystemStatus,
} from "@garnetops/core/system-status-view";
import { Link } from "@tanstack/react-router";
import { CircleCheck, CircleDashed, ExternalLink, OctagonX, RefreshCw, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import { formatBytes, formatDateTime, formatDuration, formatNumber, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import {
  camelState,
  canOpenSection,
  INTEGRATION_SECTION,
  LEVEL_TONE,
  queueKey,
  SOURCE_KEY,
} from "../lib/system-status.ts";
import { displayVersion } from "../lib/version.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

const SOURCE_REPOSITORY = "https://github.com/lcsfls/garnet-ops";
export const ROADMAP_URL = `${SOURCE_REPOSITORY}/blob/main/ROADMAP.md`;
export const SYSTEM_STATUS_DOCS = `${SOURCE_REPOSITORY}/blob/main/docs/system-status.md`;

const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

/* -------------------------------------------------------------------------- */
/* Building blocks                                                             */
/* -------------------------------------------------------------------------- */

const LEVEL_ICON = {
  ok: CircleCheck,
  attention: TriangleAlert,
  failed: OctagonX,
  inactive: CircleDashed,
} as const;

/** A level with its icon and a word. Colour only supports it (AGENTS.md rule 6). */
export function StatusBadge({ level, children }: { level: StatusLevel; children: ReactNode }) {
  const Icon = LEVEL_ICON[level];
  return (
    <Badge tone={LEVEL_TONE[level]}>
      <Icon aria-hidden="true" />
      {children}
    </Badge>
  );
}

/** An instant as a relative time with the exact one on hover; `never` text if there is none. */
export function When({ value }: { value: string | null }) {
  const { t } = useTranslation();
  if (!value) return <>{t("systemStatus.never")}</>;
  return (
    <time dateTime={value} title={formatDateTime(value)}>
      {formatRelative(value)}
    </time>
  );
}

/** A row of a card: the title, its status badge and a few lines of detail. */
function Row({
  title,
  badge,
  testId,
  children,
}: {
  title: ReactNode;
  badge: ReactNode;
  testId?: string;
  children?: ReactNode;
}) {
  return (
    <li data-testid={testId} className="border-t px-5 py-3 first:border-t-0">
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1.5">
        <div className="min-w-0 flex-[1_1_10rem] font-medium [overflow-wrap:anywhere]">{title}</div>
        {badge}
      </div>
      {children ? (
        <div className="mt-1 grid gap-1 text-sm [overflow-wrap:anywhere] text-muted-foreground [&>*]:min-w-0">
          {children}
        </div>
      ) : null}
    </li>
  );
}

function Facts({ children }: { children: ReactNode }) {
  return (
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 px-5 pt-1 pb-4 text-sm">
      {children}
    </dl>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

const ExternalLinkIcon = () => <ExternalLink aria-hidden="true" className="ml-1 inline size-3.5" />;

/** One text for every reason family the page shows. Unknown values appear as they are. */
function useReasonText(): (reason: Reason | null) => string | null {
  const { t, i18n } = useTranslation();
  return (reason) => {
    if (!reason) return null;
    const { family, value } = reason;
    switch (family) {
      case "ai": {
        const key = `ai.error.${camel(value)}`;
        return i18n.exists(key) ? t(key as MessageKey) : value;
      }
      case "vulndb-update": {
        const key = `systemStatus.vulnDb.updateReason.${camel(value)}`;
        return i18n.exists(key) ? t(key as MessageKey) : value;
      }
      case "status": {
        const key = `systemStatus.reason.${value}`;
        return i18n.exists(key) ? t(key as MessageKey) : value;
      }
      default:
        return value;
    }
  };
}

/* -------------------------------------------------------------------------- */
/* The summary                                                                 */
/* -------------------------------------------------------------------------- */

export function SummaryCard({
  status,
  fetching,
  onRefresh,
}: {
  status: SystemStatus;
  fetching: boolean;
  onRefresh: () => void;
}) {
  const { t } = useTranslation();
  const { level, attention, failed } = status.overall;
  const text =
    level === "ok"
      ? t("systemStatus.summary.ok")
      : failed > 0 && attention > 0
        ? t("systemStatus.summary.both", { failed, attention })
        : failed > 0
          ? t("systemStatus.summary.failed", { count: failed })
          : t("systemStatus.summary.attention", { count: attention });
  return (
    <Card className="mb-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4" data-testid="system-summary">
        <StatusBadge level={level}>{t(`systemStatus.level.${level}`)}</StatusBadge>
        <div className="min-w-0 flex-[1_1_16rem]">
          <p className="font-medium" data-testid="system-summary-text">
            {text}
          </p>
          <p className="text-sm text-muted-foreground">
            {t("systemStatus.summary.checked", { when: formatRelative(status.generatedAt) })}{" "}
            <span>{t("systemStatus.legend")}</span>
          </p>
        </div>
        <Button variant="outline" className="h-9 px-3" disabled={fetching} onClick={onRefresh}>
          <RefreshCw aria-hidden="true" className={cn("size-4", fetching && "motion-safe:animate-spin")} />
          {fetching ? t("systemStatus.summary.refreshing") : t("systemStatus.summary.refresh")}
        </Button>
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Scanners                                                                    */
/* -------------------------------------------------------------------------- */

export function ScannersCard({ scanners }: { scanners: SystemStatus["scanners"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("systemStatus.scanners.title")}
        description={t("systemStatus.scanners.description")}
      />
      <ul>
        {scanners.items.map((s) => {
          const word = s.problem
            ? t(`systemStatus.scanners.problem.${camelState(s.problem)}`)
            : t(`systemStatus.scanners.match.${s.match}`);
          return (
            <Row
              key={s.name}
              testId={`scanner-${s.name}`}
              title={<span className="font-mono">{s.name}</span>}
              badge={<StatusBadge level={s.level}>{word}</StatusBadge>}
            >
              <span>
                {s.version
                  ? t("systemStatus.scanners.version", { version: s.version })
                  : t("systemStatus.scanners.noVersion")}
                {" · "}
                {t("systemStatus.scanners.pinned", { pinned: s.pinned })}
                {s.reportedAt ? (
                  <>
                    {" · "}
                    {t("systemStatus.scanners.reported", { when: formatRelative(s.reportedAt) })}
                  </>
                ) : null}
              </span>
              {s.problem ? (
                <span>{t(`systemStatus.scanners.problemHint.${camelState(s.problem)}`)}</span>
              ) : s.match === "differs" ? (
                <span>{t("systemStatus.scanners.differsHint")}</span>
              ) : null}
            </Row>
          );
        })}
      </ul>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Vulnerability database                                                      */
/* -------------------------------------------------------------------------- */

export function VulnDbCard({ vulnDb }: { vulnDb: SystemStatus["vulnDb"] }) {
  const { t } = useTranslation();
  const reasonText = useReasonText();
  const stateKey = !vulnDb.reported ? "notReported" : vulnDb.valid === false ? "invalid" : vulnDb.freshness;
  const { update } = vulnDb;
  const reason = reasonText(update.reason);
  const dueNow = update.nextAt !== null && new Date(update.nextAt).getTime() <= Date.now();
  const showScanNote = vulnDb.valid !== false && vulnDb.freshness !== "current";
  const counted = vulnDb.providers.items.some((p) => p.records !== null);
  return (
    <Card>
      <CardHeader
        title={t("systemStatus.vulnDb.title")}
        description={t("systemStatus.vulnDb.description")}
        actions={
          <StatusBadge level={vulnDb.level}>
            <span data-testid="vulndb-state">{t(`systemStatus.vulnDb.state.${stateKey}`)}</span>
          </StatusBadge>
        }
      />
      <Facts>
        <Fact label={t("systemStatus.vulnDb.built")}>
          {vulnDb.builtAt ? (
            <>
              <time dateTime={vulnDb.builtAt} title={formatDateTime(vulnDb.builtAt)}>
                {formatRelative(vulnDb.builtAt)}
              </time>
              {vulnDb.ageDays !== null
                ? ` (${t("systemStatus.vulnDb.age", { days: vulnDb.ageDays })})`
                : null}
            </>
          ) : (
            t("systemStatus.never")
          )}
        </Fact>
        <Fact label={t("systemStatus.vulnDb.schema")}>
          <span className="font-mono">{vulnDb.schemaVersion ?? "–"}</span>
        </Fact>
        <Fact label={t("systemStatus.vulnDb.source")}>
          {vulnDb.source ? t(`systemStatus.vulnDb.sourceValue.${SOURCE_KEY[vulnDb.source]}`) : "–"}
        </Fact>
        <Fact label={t("systemStatus.vulnDb.checked")}>
          {vulnDb.checkedAt ? <When value={vulnDb.checkedAt} /> : "–"}
        </Fact>
        <Fact label={t("systemStatus.vulnDb.lastUpdate")}>
          {update.lastResult === "ok" && update.lastAttemptAt
            ? t("systemStatus.vulnDb.updateOk", { when: formatRelative(update.lastAttemptAt) })
            : update.lastResult === "failed" && update.lastAttemptAt
              ? t("systemStatus.vulnDb.updateFailed", {
                  when: formatRelative(update.lastAttemptAt),
                  reason: reason ?? "",
                })
              : update.mode === null
                ? t("systemStatus.vulnDb.unknownMode")
                : t("systemStatus.vulnDb.noUpdateYet")}
        </Fact>
        <Fact label={t("systemStatus.vulnDb.nextUpdate")}>
          {update.mode === "off" ? (
            t("systemStatus.vulnDb.nextOff")
          ) : update.nextAt ? (
            dueNow ? (
              t("systemStatus.vulnDb.nextDue")
            ) : (
              <When value={update.nextAt} />
            )
          ) : update.mode === null ? (
            t("systemStatus.vulnDb.unknownMode")
          ) : (
            t("systemStatus.vulnDb.nextNone")
          )}
        </Fact>
        <Fact label={t("systemStatus.vulnDb.thresholds")}>
          {t("systemStatus.vulnDb.thresholdsValue", {
            stale: vulnDb.thresholds.staleAfterDays,
            outdated: vulnDb.thresholds.outdatedAfterDays,
          })}
        </Fact>
      </Facts>
      {vulnDb.problem ? (
        <p className="px-5 pb-3 text-sm text-muted-foreground">
          {t(`systemStatus.vulnDb.problem.${vulnDb.problem}`)}
        </p>
      ) : null}
      {vulnDb.valid === false ? (
        <p className="px-5 pb-3 text-sm text-muted-foreground">{t("systemStatus.vulnDb.noDbNote")}</p>
      ) : null}
      {!vulnDb.reported ? (
        <p className="px-5 pb-3 text-sm text-muted-foreground">{t("systemStatus.vulnDb.notReportedNote")}</p>
      ) : null}
      {showScanNote ? (
        <p className="px-5 pb-3 text-sm text-muted-foreground" data-testid="vulndb-scan-note">
          {t("systemStatus.vulnDb.scanNote")}
        </p>
      ) : null}
      {vulnDb.reported ? (
        <div className="border-t px-5 py-3">
          <h3 className="mb-1.5 text-sm font-medium">{t("systemStatus.vulnDb.providers")}</h3>
          {vulnDb.providers.available && vulnDb.providers.items.length > 0 ? (
            <>
              <table className="w-full text-left text-sm">
                <thead className="text-muted-foreground">
                  <tr>
                    <th className="py-1 pr-3 font-medium">{t("systemStatus.vulnDb.provider")}</th>
                    <th className="py-1 pr-3 text-right font-medium">
                      {t("systemStatus.vulnDb.advisories")}
                    </th>
                    <th className="py-1 font-medium">{t("systemStatus.vulnDb.capturedAt")}</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnDb.providers.items.map((p) => (
                    <tr key={p.name} className="border-t">
                      <td className="py-1 pr-3 font-mono break-all">{p.name}</td>
                      <td className="py-1 pr-3 text-right tabular-nums">
                        {p.records === null ? "–" : formatNumber(p.records)}
                      </td>
                      <td className="py-1">{p.capturedAt ? <When value={p.capturedAt} /> : "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!counted ? (
                <p className="mt-1.5 text-sm text-muted-foreground">{t("systemStatus.vulnDb.noCounts")}</p>
              ) : null}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">{t("systemStatus.vulnDb.providersUnavailable")}</p>
          )}
        </div>
      ) : null}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Local build                                                                 */
/* -------------------------------------------------------------------------- */

export function LocalBuildCard({ build }: { build: SystemStatus["localBuild"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("systemStatus.localBuild.title")}
        description={t("systemStatus.localBuild.description")}
        actions={
          <StatusBadge level={build.level}>
            <span data-testid="local-build-state">
              {build.state === "set_up"
                ? t("systemStatus.localBuild.setUp")
                : t("systemStatus.localBuild.notSetUp")}
            </span>
          </StatusBadge>
        }
      />
      {build.state === "not_set_up" ? (
        <p className="px-5 pb-4 text-sm text-muted-foreground">
          {t("systemStatus.localBuild.plannedNote")}{" "}
          <a
            href={ROADMAP_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary-text underline-offset-4 hover:underline"
          >
            {t("systemStatus.localBuild.roadmap")}
            <ExternalLinkIcon />
          </a>
        </p>
      ) : (
        <div className="px-5 pb-4">
          {build.lastBuildAt ? (
            <p className="mb-2 text-sm text-muted-foreground">
              {t("systemStatus.localBuild.lastBuild", { when: formatRelative(build.lastBuildAt) })}
            </p>
          ) : null}
          {build.providers.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("systemStatus.localBuild.noProviders")}</p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-muted-foreground">
                <tr>
                  <th className="py-1 pr-3 font-medium">{t("systemStatus.localBuild.provider")}</th>
                  <th className="py-1 pr-3 font-medium">{t("systemStatus.localBuild.result")}</th>
                  <th className="py-1 pr-3 text-right font-medium">{t("systemStatus.localBuild.records")}</th>
                  <th className="hidden py-1 pr-3 font-medium @3xl:table-cell">
                    {t("systemStatus.localBuild.lastRun")}
                  </th>
                  <th className="hidden py-1 text-right font-medium @3xl:table-cell">
                    {t("systemStatus.localBuild.duration")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {build.providers.map((p) => (
                  <tr key={p.name} className="border-t">
                    <td className="py-1 pr-3 font-mono break-all">{p.name}</td>
                    <td className="py-1 pr-3">
                      <StatusBadge level={p.level}>
                        {t(`systemStatus.localBuild.resultValue.${p.result ?? "none"}`)}
                      </StatusBadge>
                    </td>
                    <td className="py-1 pr-3 text-right tabular-nums">
                      {p.records === null ? "–" : formatNumber(p.records)}
                    </td>
                    <td className="hidden py-1 pr-3 @3xl:table-cell">
                      {p.lastRunAt ? <When value={p.lastRunAt} /> : "–"}
                    </td>
                    <td className="hidden py-1 text-right tabular-nums @3xl:table-cell">
                      {p.durationMs === null ? "–" : formatDuration(p.durationMs / 1000)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Integrations                                                                */
/* -------------------------------------------------------------------------- */

function InstanceLine({ instance }: { instance: InstanceStatus }) {
  const { t } = useTranslation();
  const reasonText = useReasonText();
  const reason = reasonText(instance.reason);
  return (
    <li className="[overflow-wrap:anywhere]">
      <span className="font-medium text-foreground">{instance.name}</span>
      {": "}
      {t(`systemStatus.integrations.state.${camelState(instance.state)}`)}
      {instance.blocked ? ` – ${t(`systemStatus.integrations.blocked.${instance.blocked}`)}` : null}
      {reason ? ` – ${reason}` : null}
      {instance.lastSuccessAt
        ? ` (${t("systemStatus.integrations.instanceLast", { when: formatRelative(instance.lastSuccessAt) })})`
        : null}
    </li>
  );
}

function PartLine({ integration, part }: { integration: IntegrationStatus; part: IntegrationPartStatus }) {
  const { t } = useTranslation();
  const reasonText = useReasonText();
  const off = part.state === "not_configured";
  const reason = reasonText(part.reason);
  const detail = part.detail;
  const extra: string[] = [];
  if (integration.key === "ai" && typeof detail.scope === "string") {
    extra.push(
      t("systemStatus.integrations.scope", {
        scope: t(`systemStatus.integrations.scopeValue.${detail.scope as "private"}`),
      }),
    );
  }
  if (integration.key === "directory" && typeof detail.accountsChecked === "number") {
    extra.push(t("systemStatus.integrations.accounts", { count: detail.accountsChecked }));
  }
  if (integration.key === "notifications") {
    extra.push(
      t("systemStatus.integrations.channels", {
        enabled: Number(detail.enabled ?? 0),
        connections: Number(detail.connections ?? 0),
      }),
    );
  }
  const showFacts = !off;
  return (
    <li className="grid gap-0.5" data-testid={`part-${integration.key}-${part.key}`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium text-foreground">
          {t(`systemStatus.integrations.part.${part.key}` as MessageKey)}
        </span>
        <StatusBadge level={part.level}>
          {off
            ? t("systemStatus.integrations.partOff")
            : t(`systemStatus.integrations.state.${camelState(part.state)}`)}
        </StatusBadge>
      </div>
      {showFacts ? (
        <span>
          {part.lastSuccessAt
            ? t("systemStatus.integrations.lastSuccess", { when: formatRelative(part.lastSuccessAt) })
            : t("systemStatus.integrations.noSuccess")}
          {" · "}
          {part.lastAttemptAt && part.lastAttemptOk !== null
            ? t(
                part.lastAttemptOk
                  ? "systemStatus.integrations.attemptOk"
                  : "systemStatus.integrations.attemptFailed",
                {
                  when: formatRelative(part.lastAttemptAt),
                },
              )
            : t("systemStatus.integrations.noAttempt")}
        </span>
      ) : null}
      {extra.length > 0 && !off ? <span>{extra.join(" · ")}</span> : null}
      {part.blocked ? <span>{t(`systemStatus.integrations.blocked.${part.blocked}`)}</span> : null}
      {reason && part.state !== "blocked" ? <span>{reason}</span> : null}
      {part.instances.length > 0 ? (
        <ul className="ml-4 list-disc">
          {part.instances.map((i) => (
            <InstanceLine key={i.name} instance={i} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function IntegrationRow({ integration, role }: { integration: IntegrationStatus; role: string }) {
  const { t } = useTranslation();
  const section = INTEGRATION_SECTION[integration.key];
  const word = t(`systemStatus.integrations.state.${camelState(integration.state)}`);
  return (
    <Row
      testId={`integration-${integration.key}`}
      title={
        <>
          {t(`systemStatus.integrations.name.${integration.key}`)}
          {integration.configured ? (
            <span className="ml-2 text-sm font-normal text-muted-foreground">
              {t(`systemStatus.integrations.count.${integration.key}`, { count: integration.count })}
            </span>
          ) : null}
        </>
      }
      badge={<StatusBadge level={integration.level}>{word}</StatusBadge>}
    >
      {integration.parts.length > 0 ? (
        <ul className="grid gap-2">
          {integration.parts.map((p) => (
            <PartLine key={p.key} integration={integration} part={p} />
          ))}
        </ul>
      ) : null}
      {canOpenSection(section, role) ? (
        <span>
          <Link
            to="/settings"
            search={{ section }}
            data-testid={`settings-link-${integration.key}`}
            className="text-primary-text underline-offset-4 hover:underline"
          >
            {t("systemStatus.settingsLink")}
          </Link>
        </span>
      ) : (
        <span>{t("systemStatus.integrations.directoryOwnerOnly")}</span>
      )}
    </Row>
  );
}

export function IntegrationsCard({
  integrations,
  role,
}: {
  integrations: IntegrationStatus[];
  role: string;
}) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader
        title={t("systemStatus.integrations.title")}
        description={t("systemStatus.integrations.description")}
      />
      <ul>
        {integrations.map((i) => (
          <IntegrationRow key={i.key} integration={i} role={role} />
        ))}
      </ul>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Worker, queues, nightly scan and database                                    */
/* -------------------------------------------------------------------------- */

function QueueTable({ items }: { items: SystemStatus["worker"]["queues"]["items"] }) {
  const { t, i18n } = useTranslation();
  const label = (name: string) => {
    const key = `systemStatus.worker.queueName.${queueKey(name)}`;
    return i18n.exists(key) ? t(key as MessageKey) : name;
  };
  const oldest = (q: (typeof items)[number]) =>
    q.oldestQueuedSeconds === null ? (
      "–"
    ) : q.level === "attention" && q.failed24h === 0 ? (
      <StatusBadge level="attention">{formatDuration(q.oldestQueuedSeconds)}</StatusBadge>
    ) : (
      formatDuration(q.oldestQueuedSeconds)
    );
  const failed = (q: (typeof items)[number]) =>
    q.failed24h > 0 ? (
      <StatusBadge level="attention">{formatNumber(q.failed24h)}</StatusBadge>
    ) : (
      formatNumber(0)
    );
  return (
    <>
      {/* Narrow content area: one block per queue, the figures on a line of their own. */}
      <ul className="@3xl:hidden">
        {items.map((q) => (
          <li
            key={q.name}
            className="border-t py-1.5 text-sm [overflow-wrap:anywhere]"
            data-testid={`queue-item-${q.name}`}
          >
            <div className="font-medium" title={q.name}>
              {label(q.name)}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground tabular-nums">
              <span>
                {t("systemStatus.worker.queued")}: {formatNumber(q.queued)}
              </span>
              <span>
                {t("systemStatus.worker.active")}: {formatNumber(q.active)}
              </span>
              <span className="inline-flex items-center gap-1">
                {t("systemStatus.worker.failed24h")}: {failed(q)}
              </span>
              <span className="inline-flex items-center gap-1">
                {t("systemStatus.worker.oldest")}: {oldest(q)}
              </span>
            </div>
          </li>
        ))}
      </ul>
      <table className="hidden w-full text-left text-sm @3xl:table">
        <thead className="text-muted-foreground">
          <tr>
            <th className="py-1 pr-3 font-medium">{t("systemStatus.worker.queue")}</th>
            <th className="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.queued")}</th>
            <th className="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.active")}</th>
            <th className="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.failed24h")}</th>
            <th className="py-1 text-right font-medium">{t("systemStatus.worker.oldest")}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((q) => (
            <tr key={q.name} className="border-t align-top" data-testid={`queue-${q.name}`}>
              <td className="py-1 pr-3 [overflow-wrap:anywhere]" title={q.name}>
                {label(q.name)}
              </td>
              <td className="py-1 pr-3 text-right tabular-nums">{formatNumber(q.queued)}</td>
              <td className="py-1 pr-3 text-right tabular-nums">{formatNumber(q.active)}</td>
              <td className="py-1 pr-3 text-right tabular-nums">{failed(q)}</td>
              <td className="py-1 text-right tabular-nums">{oldest(q)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

/** Queues with something waiting, running or failing first; the idle ones sit behind a click (progressive disclosure). */
function QueuesBlock({ queues }: { queues: SystemStatus["worker"]["queues"] }) {
  const { t } = useTranslation();
  const busy = queues.items.filter((q) => q.queued > 0 || q.active > 0 || q.failed24h > 0);
  const idle = queues.items.filter((q) => !busy.includes(q));
  return (
    <div className="border-t px-5 py-3" data-testid="worker-queues">
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium">{t("systemStatus.worker.queues")}</h3>
        {!queues.available ? (
          <StatusBadge level="attention">{t("systemStatus.level.attention")}</StatusBadge>
        ) : null}
      </div>
      {!queues.available ? (
        <p className="text-sm text-muted-foreground">{t("systemStatus.worker.queuesUnavailable")}</p>
      ) : queues.items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("systemStatus.worker.noQueues")}</p>
      ) : (
        <>
          {busy.length > 0 ? (
            <QueueTable items={busy} />
          ) : (
            <p className="text-sm text-muted-foreground">{t("systemStatus.worker.queuesIdle")}</p>
          )}
          {idle.length > 0 ? (
            <details className="mt-2" data-testid="worker-idle-queues">
              <summary className="cursor-pointer text-sm text-primary-text underline-offset-4 hover:underline">
                {t("systemStatus.worker.showIdle", { count: idle.length })}
              </summary>
              <div className="mt-1.5">
                <QueueTable items={idle} />
              </div>
            </details>
          ) : null}
        </>
      )}
    </div>
  );
}

export function WorkerCard({ worker, role }: { worker: SystemStatus["worker"]; role: string }) {
  const { t, i18n } = useTranslation();
  const beat = worker.heartbeat;
  const { nightly, database, queues } = worker;
  const nextDue = nightly.nextAt !== null && new Date(nightly.nextAt).getTime() <= Date.now();
  const level = worker.liveness === "running" ? "ok" : "failed";
  return (
    <Card>
      <CardHeader title={t("systemStatus.worker.title")} description={t("systemStatus.worker.description")} />
      <ul>
        <Row
          testId="worker-heartbeat"
          title={t("systemStatus.worker.heartbeat")}
          badge={<StatusBadge level={level}>{t(`systemStatus.worker.state.${worker.liveness}`)}</StatusBadge>}
        >
          {beat && worker.liveness === "running" ? (
            <span>
              {t("systemStatus.worker.runningDetail", {
                version: beat.version,
                started: formatRelative(beat.startedAt),
                when: formatRelative(beat.beatAt),
              })}
            </span>
          ) : beat ? (
            <span>{t("systemStatus.worker.lateDetail", { when: formatRelative(beat.beatAt) })}</span>
          ) : (
            <span>{t("systemStatus.worker.missingDetail")}</span>
          )}
          {beat && beat.instances > 1 ? (
            <span>{t("systemStatus.worker.instances", { count: beat.instances })}</span>
          ) : null}
        </Row>
        <Row
          testId="worker-nightly"
          title={t("systemStatus.worker.nightly")}
          badge={
            <StatusBadge level={nightly.enabled ? "ok" : "inactive"}>
              {nightly.enabled
                ? t("systemStatus.integrations.state.current")
                : t("systemStatus.integrations.partOff")}
            </StatusBadge>
          }
        >
          {nightly.enabled ? (
            <>
              <span>
                {t("systemStatus.worker.nightlySchedule", {
                  time: new Intl.DateTimeFormat(i18n.language, {
                    hour: "numeric",
                    minute: "2-digit",
                    timeZone: "UTC",
                  }).format(new Date(`1970-01-01T${nightly.localTime}Z`)),
                  zone: nightly.timeZone,
                })}
              </span>
              <span>
                {nightly.lastRun
                  ? t("systemStatus.worker.lastRun", {
                      when: formatRelative(nightly.lastRun.at),
                      queued: nightly.lastRun.queued,
                      succeeded: nightly.lastRun.succeeded,
                      failed: nightly.lastRun.failed,
                      pending: nightly.lastRun.pending,
                    })
                  : t("systemStatus.worker.noRun")}
              </span>
              {nightly.nextAt ? (
                <span>
                  {nextDue ? (
                    t("systemStatus.worker.nextDue")
                  ) : (
                    <>
                      {t("systemStatus.worker.nextRun", { when: formatRelative(nightly.nextAt) })}{" "}
                      <span title={formatDateTime(nightly.nextAt)}>({formatDateTime(nightly.nextAt)})</span>
                    </>
                  )}
                </span>
              ) : null}
            </>
          ) : (
            <span>{t("systemStatus.worker.nightlyOff")}</span>
          )}
          {canOpenSection("scanning", role) ? (
            <span>
              <Link
                to="/settings"
                className="text-primary-text underline-offset-4 hover:underline"
                data-testid="settings-link-scanning"
              >
                {t("systemStatus.settingsLink")}
              </Link>
            </span>
          ) : null}
        </Row>
        <Row
          testId="worker-database"
          title={t("systemStatus.worker.database")}
          badge={
            <StatusBadge level={database.level}>
              {database.level === "ok" ? t("systemStatus.level.ok") : t("systemStatus.level.attention")}
            </StatusBadge>
          }
        >
          <span>
            {database.sizeBytes === null
              ? "–"
              : t("systemStatus.worker.size", { size: formatBytes(database.sizeBytes) })}
          </span>
          <span>
            {database.migrations.applied === database.migrations.expected
              ? t("systemStatus.worker.migrations", {
                  applied: database.migrations.applied,
                  expected: database.migrations.expected,
                  latest: database.migrations.latest ?? "–",
                })
              : t("systemStatus.worker.migrationsBehind", {
                  applied: database.migrations.applied,
                  expected: database.migrations.expected,
                })}
          </span>
        </Row>
      </ul>
      <QueuesBlock queues={queues} />
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Application                                                                 */
/* -------------------------------------------------------------------------- */

export function AppCard({ app, role }: { app: SystemStatus["app"]; role: string }) {
  const { t } = useTranslation();
  const { updater } = app;
  const word = !updater.configured
    ? t("systemStatus.integrations.state.notConfigured")
    : !updater.reachable
      ? t("systemStatus.app.updaterDown")
      : t(`systemStatus.app.phase.${updater.phase ?? "idle"}`);
  return (
    <Card>
      <CardHeader title={t("systemStatus.app.title")} description={t("systemStatus.app.description")} />
      <Facts>
        <Fact label={t("systemStatus.app.version")}>
          <span className="font-mono" data-testid="app-version">
            {displayVersion(app.version, t("shell.alpha"))}
          </span>
        </Fact>
        <Fact label={t("systemStatus.app.updates")}>
          <span className="inline-flex flex-wrap items-center gap-2">
            <StatusBadge level={updater.level}>
              {!updater.configured
                ? t("systemStatus.integrations.state.notConfigured")
                : !updater.reachable
                  ? t("systemStatus.level.attention")
                  : updater.level === "failed"
                    ? t("systemStatus.level.failed")
                    : t("systemStatus.level.ok")}
            </StatusBadge>
            <span data-testid="updater-text">
              {updater.configured ? word : t("systemStatus.app.updaterOff")}
            </span>
          </span>
          {updater.configured && updater.reachable ? (
            <span className="mt-1 block text-muted-foreground">
              {updater.latestAvailable
                ? t("systemStatus.app.latest", { version: updater.latestAvailable })
                : t("systemStatus.app.noLatest")}
            </span>
          ) : null}
        </Fact>
      </Facts>
      {canOpenSection("updates", role) ? (
        <p className="px-5 pb-4 text-sm">
          <Link
            to="/settings"
            search={{ section: "updates" }}
            className="text-primary-text underline-offset-4 hover:underline"
            data-testid="settings-link-updates"
          >
            {t("systemStatus.settingsLink")}
          </Link>
        </p>
      ) : null}
    </Card>
  );
}
