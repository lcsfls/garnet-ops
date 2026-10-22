import { Link } from "@tanstack/react-router";
import { ArrowRight, ExternalLink, GitPullRequest, TriangleAlert, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { camelCode, PR_TONE, safeHttpsUrl } from "../lib/fixes.ts";
import { formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { FixProposalRow } from "../lib/types.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { Badge, SeverityBadge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

/** The full story of one proposal: the change, what it fixes, why it is by hand, the AI suggestion, the pull request. */
export function FixDetail({
  proposal: p,
  canCreate,
  onCreate,
  onClose,
}: {
  proposal: FixProposalRow;
  canCreate: boolean;
  onCreate: () => void;
  onClose?: () => void;
}) {
  const { t } = useTranslation();
  const prUrl = safeHttpsUrl(p.pr?.url ?? null);
  return (
    <Card className="self-start">
      <CardHeader
        title={p.packageName}
        description={`${p.repositoryName} · ${p.packageType}`}
        actions={
          onClose ? (
            <button
              type="button"
              onClick={onClose}
              aria-label={t("fixes.detailClose")}
              className="grid size-8 place-items-center rounded-md hover:bg-accent"
            >
              <X aria-hidden="true" className="size-4" />
            </button>
          ) : null
        }
      />
      <div className="grid gap-4 px-5 pb-5">
        <section aria-label={t("fixes.detailChange")} className="grid gap-1.5">
          <h3 className="text-sm font-medium text-muted-foreground">{t("fixes.detailChange")}</h3>
          <div className="flex flex-wrap items-center gap-2 font-mono">
            {p.installedVersion}
            <ArrowRight aria-hidden="true" className="size-4 text-muted-foreground" />
            {p.targetVersion ?? (
              <span className="font-sans text-muted-foreground">{t("fixes.noVersion")}</span>
            )}
            {p.majorUpgrade ? (
              <Badge tone="outline" className="font-sans">
                <TriangleAlert aria-hidden="true" />
                {t("fixes.majorUpgrade")}
              </Badge>
            ) : null}
          </div>
          {p.majorUpgrade ? <p className="text-sm text-muted-foreground">{t("fixes.majorHint")}</p> : null}
          {p.manifestPath ? (
            <dl className="mt-1 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted-foreground">{t("fixes.detailFile")}</dt>
              <dd className="font-mono break-all">{p.manifestPath}</dd>
              {p.currentSpec ? (
                <>
                  <dt className="text-muted-foreground">{t("fixes.detailRequirement")}</dt>
                  <dd className="font-mono break-all">
                    {p.currentSpec}
                    {p.newSpec ? ` → ${p.newSpec}` : ""}
                  </dd>
                </>
              ) : null}
              <dt className="text-muted-foreground">{t("fixes.detailDependency")}</dt>
              <dd>
                {p.dependency === "direct"
                  ? t("fixes.direct")
                  : p.dependency === "transitive"
                    ? t("fixes.transitive")
                    : t("fixes.unknownDependency")}
                {p.dev ? ` · ${t("fixes.dev")}` : ""}
              </dd>
            </dl>
          ) : null}
        </section>

        <section aria-label={t("fixes.detailVulnerabilities")} className="grid gap-1.5">
          <h3 className="text-sm font-medium text-muted-foreground">{t("fixes.detailVulnerabilities")}</h3>
          <div>
            <SeverityBadge severity={p.severity} />
          </div>
          <ul className="flex flex-wrap gap-x-3 gap-y-1">
            {p.vulnerabilityIds.map((id) => (
              <li key={id}>
                <Link
                  to="/findings"
                  search={{ repositoryId: p.repositoryId, q: id }}
                  className="font-mono text-sm break-all hover:underline"
                >
                  {id}
                </Link>
              </li>
            ))}
          </ul>
          {p.unresolvedIds.length > 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("fixes.detailUnresolved")} <span className="font-mono">{p.unresolvedIds.join(", ")}</span>
            </p>
          ) : null}
          <Link
            to="/findings"
            search={{ repositoryId: p.repositoryId, q: p.packageName }}
            className="text-sm font-medium text-primary-text hover:underline"
          >
            {t("fixes.showFindings")}
          </Link>
        </section>

        {p.action === "manual" && p.reason ? (
          <section aria-label={t("fixes.detailManual")} className="grid gap-1">
            <h3 className="text-sm font-medium text-muted-foreground">{t("fixes.detailManual")}</h3>
            <p>{t(`fixes.reason.${camelCode(p.reason)}` as MessageKey)}</p>
          </section>
        ) : null}

        {p.aiSuggestion ? (
          <section aria-label={t("fixes.aiLabel")} className="grid gap-1.5 rounded-md border bg-muted/40 p-3">
            <h3 className="flex flex-wrap items-center gap-2 text-sm font-medium">
              <Badge tone="outline">{t("fixes.aiLabel")}</Badge>
              <span className="font-normal text-muted-foreground">
                {t("fixes.aiConfidence", { confidence: t(`fixes.confidence.${p.aiSuggestion.confidence}`) })}
              </span>
            </h3>
            {/* Plain text only: it is written by a model and never rendered as markup. */}
            <p className="whitespace-pre-wrap">{p.aiSuggestion.summary}</p>
            {p.aiSuggestion.recommendation ? (
              <p className="whitespace-pre-wrap">{p.aiSuggestion.recommendation}</p>
            ) : null}
            {p.aiSuggestion.upgradeTo && p.aiSuggestion.upgradeTo !== p.targetVersion ? (
              <p className="text-sm text-muted-foreground">
                {t("fixes.aiDifferentVersion", {
                  version: p.aiSuggestion.upgradeTo,
                  target: p.targetVersion ?? "–",
                })}
              </p>
            ) : null}
            <p className="text-sm text-muted-foreground">{t("fixes.aiReadOnly")}</p>
          </section>
        ) : null}

        {p.pr ? (
          <section aria-label={t("fixes.detailPr")} className="grid gap-1.5">
            <h3 className="text-sm font-medium text-muted-foreground">{t("fixes.detailPr")}</h3>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={PR_TONE[p.pr.state]}>{t(`fixes.prState.${p.pr.state}`)}</Badge>
              {prUrl && p.pr.number !== null ? (
                <a
                  href={prUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-medium text-primary-text hover:underline"
                >
                  {t("fixes.prNumber", { number: p.pr.number })}
                  <ExternalLink aria-hidden="true" className="size-3.5" />
                  <span className="sr-only">{t("fixes.openOnForge")}</span>
                </a>
              ) : null}
            </div>
            {p.pr.state === "failed" && p.pr.reason ? (
              <p className="text-sm text-destructive-text">
                {t(`fixes.failure.${camelCode(p.pr.reason)}` as MessageKey)}
              </p>
            ) : null}
            <p className="text-sm text-muted-foreground">
              {p.pr.requestedBy ? `${p.pr.requestedBy} · ` : ""}
              {p.pr.lastCheckedAt
                ? t("fixes.prChecked", { when: formatRelative(p.pr.lastCheckedAt) })
                : t("fixes.prNotChecked")}
            </p>
          </section>
        ) : null}

        {p.creatable && canCreate && p.pr?.state !== "merged" ? (
          <div>
            <Button onClick={onCreate}>
              <GitPullRequest aria-hidden="true" className="size-4" />
              {t("fixes.createPr")}
            </Button>
          </div>
        ) : null}
      </div>
    </Card>
  );
}
