import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { formatAge, useAttackFeed, useNow } from "../lib/attack-feed.ts";
import { formatDateTime } from "../lib/format.ts";
import { LiveStatusLine } from "./attack-events.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";

/** How many alerts the compact card shows. */
const SHOWN = 8;

/**
 * "Latest alerts" on the XDR page (ADR 0021): the same attack events as the Attacks page, kept current by the same
 * stream, as a compact table. Rule descriptions and agent names come from alerts and are shown as plain text.
 */
export function XdrLatestAlerts({ canEdit }: { canEdit: boolean }) {
  const { t, i18n } = useTranslation();
  const feed = useAttackFeed();
  const now = useNow(5_000);
  const rows = feed.events?.slice(0, SHOWN);
  return (
    <Card>
      <CardHeader
        title={t("xdr.latestTitle")}
        description={t("xdr.latestDescription")}
        actions={
          <Link to="/attacks" className="text-sm text-primary-text hover:underline">
            {t("xdr.latestMore")}
          </Link>
        }
      />
      <LiveStatusLine live={feed.live} canEdit={canEdit} className="px-5 pb-2" />
      {rows === undefined ? (
        <QueryStatus query={feed.query} />
      ) : rows.length === 0 ? (
        <p className="border-t px-5 py-4 text-muted-foreground">{t("xdr.latestEmpty")}</p>
      ) : (
        <table className="w-full text-left" data-testid="xdr-latest-alerts">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-y">
              <th className="px-5 py-2 font-medium">{t("attacks.live.title")}</th>
              <th className="hidden px-3 py-2 font-medium @xl:table-cell">{t("attacks.columns.address")}</th>
              <th className="hidden px-3 py-2 font-medium @3xl:table-cell">{t("xdr.columnAgent")}</th>
              <th className="px-5 py-2 text-right font-medium">{t("attacks.columns.lastSeen")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((event) => (
              <tr key={event.seq} className="border-b align-top last:border-0" data-testid="xdr-latest-alert">
                <td className="max-w-0 px-5 py-2.5">
                  <div className="truncate font-medium" title={event.description}>
                    {event.description || t("attacks.live.noRule")}
                  </div>
                  <div className="truncate text-sm text-muted-foreground @xl:hidden">
                    <span className="font-mono">{event.ip}</span>
                    {event.agentName ? ` · ${event.agentName}` : ""}
                  </div>
                </td>
                <td className="hidden px-3 py-2.5 font-mono text-sm @xl:table-cell">{event.ip}</td>
                <td
                  className="hidden max-w-[14rem] truncate px-3 py-2.5 @3xl:table-cell"
                  title={event.agentName}
                >
                  {event.agentName}
                </td>
                <td className="px-5 py-2.5 text-right text-sm whitespace-nowrap text-muted-foreground">
                  <time dateTime={event.at} title={formatDateTime(event.at)}>
                    {formatAge(event.at, now, i18n.language)}
                  </time>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
