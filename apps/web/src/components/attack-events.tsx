import { HIGH_ABUSE_SCORE } from "@garnetops/core/attack-live";
import { Link } from "@tanstack/react-router";
import { CircleOff, Clock, PauseCircle, Radio } from "lucide-react";
import { useTranslation } from "react-i18next";
import { type Freshness, formatAge, freshnessOf, useNow } from "../lib/attack-feed.ts";
import { countryName } from "../lib/attacks.ts";
import { cn } from "../lib/cn.ts";
import { formatDateTime } from "../lib/format.ts";
import type { AttackEvent, AttackLiveInfo } from "../lib/types.ts";
import { useWazuhCodeText } from "../lib/xdr.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Badge } from "./ui/badge.tsx";

/**
 * One honest line about the feed: "Live — last event 12 s ago", "Waiting for Wazuh", "Paused: connection blocked" or
 * "The live feed is switched off". Neutral colours: a feed that is merely running is not proof of anything, so it is
 * never green. The totals of the page keep their own "updated" time (the 15-minute sync).
 */
export function LiveStatusLine({
  live,
  canEdit,
  hideActions = false,
  className,
}: {
  live: AttackLiveInfo | null;
  canEdit: boolean;
  /** Leave out the hint and the link to Settings (the settings page itself shows the line). */
  hideActions?: boolean;
  className?: string;
}) {
  const { t, i18n } = useTranslation();
  const now = useNow(5_000);
  const errorText = useWazuhCodeText();
  const freshness: Freshness = freshnessOf(live);
  let Icon = Radio;
  let text: string;
  let hint: string | null = null;
  switch (freshness.kind) {
    case "live":
      text = freshness.lastEventAt
        ? t("attacks.live.statusLive", { when: formatAge(freshness.lastEventAt, now, i18n.language) })
        : t("attacks.live.statusLiveNone");
      break;
    case "paused":
      Icon = PauseCircle;
      text = t("attacks.live.statusPaused");
      hint = hideActions
        ? null
        : t(
            freshness.reason === "certificate"
              ? "attacks.live.pausedCertificate"
              : freshness.reason === "privileges"
                ? "attacks.live.pausedPrivileges"
                : "attacks.live.pausedDisabled",
          );
      break;
    case "off":
      Icon = CircleOff;
      text = t("attacks.live.statusOff");
      hint = canEdit || hideActions ? null : t("attacks.live.offHint");
      break;
    default:
      Icon = Clock;
      text = freshness.error
        ? t("attacks.live.statusWaitingReason", { reason: errorText(freshness.error) })
        : t("attacks.live.statusWaiting");
  }
  return (
    <p
      className={cn("flex flex-wrap items-center gap-x-2 gap-y-0.5 text-sm text-muted-foreground", className)}
      data-testid="live-status"
      data-state={freshness.kind}
    >
      <Icon aria-hidden="true" className="size-3.5 flex-none" />
      <span className="font-medium text-foreground">{text}</span>
      {hint ? <span>{hint}</span> : null}
      {!hideActions && (freshness.kind === "paused" || freshness.kind === "off") ? (
        canEdit ? (
          <Link
            to="/settings"
            search={{ section: freshness.kind === "off" ? "attacks" : "xdr" }}
            className="text-primary-text hover:underline"
          >
            {t("attacks.manage")}
          </Link>
        ) : null
      ) : null}
    </p>
  );
}

/** The abuse score of an event, only while OSINT is on and a cached score exists. */
function Score({ score }: { score: number }) {
  const { t } = useTranslation();
  return (
    <div className="text-right text-sm leading-tight whitespace-nowrap" data-testid="attack-event-score">
      <b className="text-base tabular-nums">{score}</b>
      <span className="sr-only">{t("attacks.live.scoreLabel", { score })}</span>
      <span aria-hidden="true" className="block text-muted-foreground">
        {score > HIGH_ABUSE_SCORE ? t("attacks.osint.high") : t("attacks.columns.score")}
      </span>
    </div>
  );
}

/**
 * One event of the live feed. Everything from the alert (the rule description, the agent name) is attacker-influenced
 * text: React renders it as text, it is cut here for the layout, the full text is in the tooltip, and it is not a link.
 */
export function AttackEventRow({
  event,
  osintEnabled,
  now,
}: {
  event: AttackEvent;
  osintEnabled: boolean;
  now: number;
}) {
  const { t, i18n } = useTranslation();
  const country =
    event.scope === "internal"
      ? t("attacks.live.internal")
      : event.country && event.country !== "ZZ"
        ? countryName(event.country, i18n.language)
        : t("attacks.live.unknownCountry");
  const code =
    event.scope === "internal" ? "LAN" : event.country && event.country !== "ZZ" ? event.country : "–";
  const description = event.description || t("attacks.live.noRule");
  return (
    <li
      className="flex items-start gap-3 border-b px-5 py-2.5 last:border-0"
      data-testid="attack-event"
      data-seq={event.seq}
    >
      <Badge tone="neutral" className="mt-0.5 min-w-9 justify-center font-mono">
        <span data-testid="attack-event-country">{code}</span>
      </Badge>
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium" title={description} data-testid="attack-event-description">
          {description}
        </div>
        <div className="flex flex-wrap items-baseline gap-x-1.5 text-sm text-muted-foreground">
          <span className="font-mono text-foreground" data-testid="attack-event-ip">
            {event.ip}
          </span>
          <span aria-hidden="true">·</span>
          <span>{country}</span>
          <span aria-hidden="true">·</span>
          <span>{t("attacks.live.observed")}</span>
        </div>
        <div className="truncate text-sm text-muted-foreground" title={event.agentName}>
          {event.agentName ? t("attacks.live.onAgent", { agent: event.agentName }) : null}
          {event.agentName ? " · " : null}
          {t("attacks.live.level", { level: event.level })}
        </div>
      </div>
      <div className="flex flex-none flex-col items-end gap-1">
        <time
          dateTime={event.at}
          title={formatDateTime(event.at)}
          className="text-sm whitespace-nowrap text-muted-foreground"
        >
          {formatAge(event.at, now, i18n.language)}
        </time>
        {osintEnabled && event.score !== null ? <Score score={event.score} /> : null}
      </div>
    </li>
  );
}

/** The "Latest events" card of the Attacks page: newest first, at most 50, with the status of the feed. */
export function AttackEventsCard({
  events,
  live,
  connected,
  query,
  osintEnabled,
  canEdit,
  className,
  scrollClassName,
}: {
  events: AttackEvent[] | undefined;
  live: AttackLiveInfo | null;
  connected: boolean;
  query: Parameters<typeof QueryStatus>[0]["query"];
  osintEnabled: boolean;
  canEdit: boolean;
  className?: string;
  scrollClassName?: string;
}) {
  const { t } = useTranslation();
  const now = useNow(5_000);
  return (
    <Card className={className}>
      <CardHeader title={t("attacks.live.title")} description={t("attacks.live.description")} />
      <LiveStatusLine live={live} canEdit={canEdit} className="px-5 pb-2" />
      {events === undefined ? (
        <QueryStatus query={query} />
      ) : events.length === 0 ? (
        <p className="border-t px-5 py-4 text-muted-foreground">{t("attacks.live.empty")}</p>
      ) : (
        <ol
          aria-label={t("attacks.live.listLabel")}
          className={cn("max-h-[28rem] overflow-y-auto border-t", scrollClassName)}
          data-testid="attack-events"
        >
          {events.map((event) => (
            <AttackEventRow key={event.seq} event={event} osintEnabled={osintEnabled} now={now} />
          ))}
        </ol>
      )}
      {!connected && events !== undefined ? (
        <p className="border-t px-5 py-2.5 text-sm text-muted-foreground" data-testid="live-polling">
          {t("attacks.live.polling")}
        </p>
      ) : null}
    </Card>
  );
}
