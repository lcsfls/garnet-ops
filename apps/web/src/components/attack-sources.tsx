import { scoreBand } from "@garnetops/core/osint";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Check, Copy, ExternalLink, Server, X } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { countryName, isRuleGroup, RULE_GROUPS } from "../lib/attacks.ts";
import { cn } from "../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { type AttacksSearch, toQuery } from "../lib/search.ts";
import type { AttackAgent, AttackOverview, AttackSourceRow, Page } from "../lib/types.ts";
import { SearchInput } from "./filters.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { Pagination } from "./pagination.tsx";
import { QueryStatus } from "./query-state.tsx";
import { type SortDir, SortHeader } from "./sort-header.tsx";
import { Badge } from "./ui/badge.tsx";
import { Select } from "./ui/select.tsx";

const Dash = () => <span className="text-muted-foreground">–</span>;

/** Address, copy button. The address is plain text: never a link, never markup. */
function Address({ ip }: { ip: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="font-mono text-[15px] break-all" data-testid="attack-ip">
        {ip}
      </span>
      <button
        type="button"
        aria-label={t("attacks.copyAddress", { ip })}
        title={copied ? t("attacks.copied") : t("common.copy")}
        className="grid size-6 flex-none place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(ip);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          } catch {
            // The clipboard can be blocked; the address stays selectable as text.
          }
        }}
      >
        {copied ? (
          <Check aria-hidden="true" className="size-3.5" />
        ) : (
          <Copy aria-hidden="true" className="size-3.5" />
        )}
      </button>
      {copied ? (
        <span role="status" className="sr-only">
          {t("attacks.copied")}
        </span>
      ) : null}
    </span>
  );
}

function CountryCell({ row, onFilter }: { row: AttackSourceRow; onFilter: (country: string) => void }) {
  const { t, i18n } = useTranslation();
  if (row.scope === "internal") {
    return (
      <button type="button" title={t("attacks.internalHint")} onClick={() => onFilter("internal")}>
        <Badge tone="neutral">{t("attacks.internal")}</Badge>
      </button>
    );
  }
  if (!row.country || row.country === "ZZ") {
    return (
      <button
        type="button"
        className="text-muted-foreground hover:underline"
        onClick={() => onFilter("unknown")}
      >
        {t("attacks.unknown")}
      </button>
    );
  }
  return (
    <button
      type="button"
      className="text-left hover:underline"
      onClick={() => onFilter(row.country as string)}
    >
      {countryName(row.country, i18n.language)}{" "}
      <span className="font-mono text-sm text-muted-foreground">{row.country}</span>
    </button>
  );
}

function Network({ row, onFilter }: { row: AttackSourceRow; onFilter: (asn: number) => void }) {
  if (row.asn === null) return <Dash />;
  return (
    <button type="button" className="text-left hover:underline" onClick={() => onFilter(row.asn as number)}>
      <span className="font-mono text-sm">AS{row.asn}</span>
      {row.org ? <span className="ml-1.5 break-words">{row.org}</span> : null}
    </button>
  );
}

/** The machines an address attacked: a link to the server when one is confirmed, otherwise to the agent in XDR. */
export function AgentLinks({ agents, limit = 3 }: { agents: AttackAgent[]; limit?: number }) {
  const { t } = useTranslation();
  if (agents.length === 0) return <Dash />;
  return (
    <ul className="grid gap-0.5">
      {agents.slice(0, limit).map((a) => (
        <li key={a.agentId} className="flex items-center gap-1.5">
          {a.hostId ? (
            <Link
              to="/servers/$id"
              params={{ id: a.hostId }}
              title={t("attacks.openServer", { name: a.name })}
              className="inline-flex items-center gap-1 break-all hover:underline"
            >
              <Server aria-hidden="true" className="size-3.5 flex-none text-muted-foreground" />
              {a.name}
            </Link>
          ) : (
            <Link
              to="/xdr"
              search={{ q: a.name }}
              title={t("attacks.findInXdr", { name: a.name })}
              className="break-all hover:underline"
            >
              {a.name}
            </Link>
          )}
          <span className="text-sm text-muted-foreground tabular-nums">{formatNumber(a.count)}</span>
        </li>
      ))}
      {agents.length > limit ? (
        <li className="text-sm text-muted-foreground">+{agents.length - limit}</li>
      ) : null}
    </ul>
  );
}

function Score({ row, provider }: { row: AttackSourceRow; provider: string }) {
  const { t } = useTranslation();
  if (row.scope === "internal") return <Dash />;
  const o = row.osint;
  if (!o) return <span className="text-sm text-muted-foreground">{t("attacks.osint.notChecked")}</span>;
  const band = scoreBand(o.score);
  return (
    <div className="grid gap-0.5">
      <span className="inline-flex items-center gap-1.5">
        <Badge
          tone={band === "high" ? "outline" : "neutral"}
          className={band === "high" ? "font-semibold" : undefined}
        >
          {t(`attacks.osint.${band}`)} · {t("attacks.osint.scoreOf", { score: o.score })}
        </Badge>
      </span>
      <span className="text-sm text-muted-foreground">
        {t("attacks.osint.reports", { count: o.reports })}
        {o.lastReportedAt
          ? `, ${t("attacks.osint.lastReport", { when: formatRelative(o.lastReportedAt) })}`
          : ""}
      </span>
      {o.pageUrl ? (
        // Only while the provider is switched on, only the provider's page for this address.
        <a
          href={o.pageUrl}
          target="_blank"
          rel="noopener noreferrer nofollow"
          className="inline-flex items-center gap-1 text-sm text-primary-text hover:underline"
          aria-label={t("attacks.osint.openProvider", { provider, ip: row.ip })}
        >
          <ExternalLink aria-hidden="true" className="size-3" />
          {t("attacks.osint.providerLink", { provider })}
        </a>
      ) : null}
    </div>
  );
}

function Time({ value }: { value: string | null }) {
  const { t } = useTranslation();
  if (!value) return <span className="text-sm text-muted-foreground">{t("attacks.unknownTime")}</span>;
  return (
    <time dateTime={value} title={formatDateTime(value)} className="text-sm">
      {formatRelative(value)}
    </time>
  );
}

/**
 * The aggregated source addresses of the period (ADR 0016): sortable, filterable, with the
 * country and network from the local tables and, when switched on, the OSINT score. More
 * columns appear with the width of the content area; nothing disappears, it moves under the
 * address.
 */
export function AttackSources({
  state,
  onChange,
  overview,
}: {
  state: AttacksSearch;
  onChange: (patch: Partial<AttacksSearch>, replace?: boolean) => void;
  overview: AttackOverview;
}) {
  const { t, i18n } = useTranslation();
  const period = state.period ?? "24h";
  const osint = overview.osint.enabled ? overview.osint : null;
  const query = useQuery({
    queryKey: ["attacks-sources", state],
    queryFn: () =>
      api<Page<AttackSourceRow>>(
        `/attacks/sources${toQuery({ ...state, agentName: undefined, period, pageSize: state.pageSize })}`,
      ),
    placeholderData: keepPreviousData,
  });
  const filter = (patch: Partial<AttacksSearch>, replace = false) =>
    onChange({ cursor: undefined, ...patch }, replace);
  const sortProps = {
    current: state.sort,
    dir: state.dir as SortDir | undefined,
    onSort: (sort: string | undefined, dir: SortDir | undefined) =>
      onChange({ sort: sort as AttacksSearch["sort"], dir, cursor: undefined }),
  };
  const hasFilter = Boolean(state.q || state.country || state.asn || state.agent || state.group);
  const countries = overview.window?.countries ?? [];
  const chips: { key: string; label: string; clear: Partial<AttacksSearch> }[] = [];
  if (state.country) {
    chips.push({
      key: "country",
      label:
        state.country === "internal"
          ? t("attacks.internal")
          : state.country === "unknown"
            ? t("attacks.unknown")
            : countryName(state.country, i18n.language),
      clear: { country: undefined },
    });
  }
  if (state.asn)
    chips.push({ key: "asn", label: t("attacks.filterAsn", { asn: state.asn }), clear: { asn: undefined } });
  if (state.agent) {
    chips.push({
      key: "agent",
      label: t("attacks.filterAgent", { name: state.agentName ?? state.agent }),
      clear: { agent: undefined, agentName: undefined },
    });
  }
  const columns = 4 + (osint ? 1 : 0);

  return (
    <Card>
      <CardHeader title={t("attacks.tableTitle")} description={t("attacks.tableDescription")} />
      <div className="flex flex-wrap items-center gap-3 px-5 pb-4">
        <label className="inline-flex items-center gap-2 text-sm text-muted-foreground">
          {t("attacks.countryFilter")}
          <Select
            aria-label={t("attacks.countryFilter")}
            className="h-9 text-sm"
            value={state.country ?? "all"}
            onChange={(e) => {
              const v = e.currentTarget.value;
              filter({ country: v === "all" ? undefined : v });
            }}
          >
            <option value="all">{t("attacks.allCountries")}</option>
            {countries.map((c) => (
              <option key={c.country} value={c.country}>
                {countryName(c.country, i18n.language)}
              </option>
            ))}
            <option value="unknown">{t("attacks.unknown")}</option>
            <option value="internal">{t("attacks.internal")}</option>
          </Select>
        </label>
        <label className="inline-flex items-center gap-2 text-sm text-muted-foreground">
          {t("attacks.groupFilter")}
          <Select
            aria-label={t("attacks.groupFilter")}
            className="h-9 text-sm"
            value={state.group ?? "all"}
            onChange={(e) => {
              const v = e.currentTarget.value;
              filter({ group: v === "all" ? undefined : v });
            }}
          >
            <option value="all">{t("attacks.allGroups")}</option>
            {RULE_GROUPS.map((g) => (
              <option key={g} value={g}>
                {t(`attacks.group.${g}` as MessageKey)}
              </option>
            ))}
          </Select>
        </label>
        <SearchInput
          className="ml-auto"
          label={t("attacks.search")}
          value={state.q ?? ""}
          onChange={(q) => filter({ q: q || undefined }, true)}
        />
      </div>
      {chips.length > 0 ? (
        <ul aria-label={t("attacks.activeFilters")} className="flex flex-wrap items-center gap-2 px-5 pb-4">
          {chips.map((chip) => (
            <li key={chip.key}>
              <button
                type="button"
                aria-label={t("attacks.removeFilter", { name: chip.label })}
                onClick={() => filter(chip.clear)}
                className="inline-flex h-8 items-center gap-1.5 rounded-md border border-input bg-card px-2.5 text-sm hover:bg-accent"
              >
                {chip.label}
                <X aria-hidden="true" className="size-3.5" />
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <table className="w-full border-t text-left" data-testid="attack-table">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-b">
            <SortHeader
              column="ip"
              label={t("attacks.columns.address")}
              natural="asc"
              className="px-5"
              {...sortProps}
            />
            <SortHeader
              column="country"
              label={t("attacks.columns.country")}
              natural="asc"
              className="hidden px-3 @3xl:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="asn"
              label={t("attacks.columns.network")}
              natural="asc"
              className="hidden px-3 @3xl:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="count"
              label={t("attacks.columns.alerts")}
              natural="desc"
              align="right"
              className="px-3"
              {...sortProps}
            />
            <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("attacks.columns.groups")}</th>
            <th className="hidden px-3 py-2.5 font-medium @wide:table-cell">
              {t("attacks.columns.targets")}
            </th>
            <SortHeader
              column="firstSeen"
              label={t("attacks.columns.firstSeen")}
              natural="desc"
              className="hidden px-3 @xwide:table-cell"
              {...sortProps}
            />
            <SortHeader
              column="lastSeen"
              label={t("attacks.columns.lastSeen")}
              natural="desc"
              className="hidden px-3 @wide:table-cell"
              {...sortProps}
            />
            {osint ? (
              <SortHeader
                column="score"
                label={t("attacks.columns.score")}
                natural="desc"
                className="px-5"
                {...sortProps}
              />
            ) : null}
          </tr>
        </thead>
        <tbody>
          {query.data?.items.map((row) => (
            <tr
              key={row.ip}
              className="border-b align-top last:border-0"
              data-testid={`attack-row-${row.ip}`}
            >
              <td className="px-5 py-3">
                <Address ip={row.ip} />
                {/* Narrow content has no country and network columns; they move under the address. */}
                <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-sm @3xl:hidden">
                  <CountryCell row={row} onFilter={(country) => filter({ country })} />
                  <Network row={row} onFilter={(asn) => filter({ asn: String(asn) })} />
                </div>
              </td>
              <td className="hidden px-3 py-3 @3xl:table-cell">
                <CountryCell row={row} onFilter={(country) => filter({ country })} />
              </td>
              <td className="hidden px-3 py-3 @3xl:table-cell">
                <Network row={row} onFilter={(asn) => filter({ asn: String(asn) })} />
              </td>
              <td className="px-3 py-3 text-right tabular-nums">
                {formatNumber(row.count)}
                {row.blocked ? (
                  <div className="text-sm text-muted-foreground" data-testid="attack-row-blocked">
                    {t("attacks.blockedCount", { count: row.blocked })}
                  </div>
                ) : null}
              </td>
              <td className="hidden px-3 py-3 @wide:table-cell">
                {row.groups.length > 0 ? (
                  <ul className="flex flex-wrap gap-1">
                    {row.groups.map((g) => (
                      <li key={g}>
                        <Badge tone="neutral">
                          {isRuleGroup(g) ? t(`attacks.group.${g}` as MessageKey) : g}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Dash />
                )}
              </td>
              <td className="hidden px-3 py-3 @wide:table-cell">
                <AgentLinks agents={row.agents} />
              </td>
              <td className="hidden px-3 py-3 @xwide:table-cell">
                <Time value={row.firstSeen} />
              </td>
              <td className="hidden px-3 py-3 @wide:table-cell">
                <Time value={row.lastSeen} />
              </td>
              {osint ? (
                <td className="px-5 py-3">
                  <Score row={row} provider={osint.providerName} />
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
        {query.data && query.data.items.length === 0 ? (
          <tbody>
            <tr>
              <td colSpan={columns} className="px-5 py-6 text-muted-foreground">
                {hasFilter ? t("attacks.noMatch") : t("attacks.noSources")}
              </td>
            </tr>
          </tbody>
        ) : null}
      </table>
      <QueryStatus query={query} />
      {query.data ? (
        <Pagination
          page={query.data}
          onCursor={(cursor) => onChange({ cursor })}
          onPageSize={(pageSize) => onChange({ pageSize, cursor: undefined })}
        />
      ) : null}
      <p className={cn("border-t px-5 py-2.5 text-sm text-muted-foreground")}>{t("attacks.approximate")}</p>
    </Card>
  );
}
