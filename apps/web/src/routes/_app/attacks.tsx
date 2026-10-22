import { resolveHomePoint } from "@garnetops/core/home-location";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ArrowDown, ArrowUp, Globe, Minus, Server, Settings } from "lucide-react";
import { lazy, Suspense, useState } from "react";
import { useTranslation } from "react-i18next";
import { AttackEventsCard } from "../../components/attack-events.tsx";
import { AttackMap } from "../../components/attack-map.tsx";
import { AttackSources } from "../../components/attack-sources.tsx";
import { AttackSummaryCard } from "../../components/attack-summary.tsx";
import { Segmented } from "../../components/filters.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { Banner } from "../../components/ui/alert.tsx";
import { Badge } from "../../components/ui/badge.tsx";
import { Button } from "../../components/ui/button.tsx";
import { api } from "../../lib/api.ts";
import { useAttackFeed } from "../../lib/attack-feed.ts";
import { countryName } from "../../lib/attacks.ts";
import { cn } from "../../lib/cn.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import { type MapView, readMapView, writeMapView } from "../../lib/globe.ts";
import { type AttacksSearch, attacksSearch } from "../../lib/search.ts";
import type { AttackOverview } from "../../lib/types.ts";
import { changeOf, PERIOD_KEY } from "../../lib/xdr.ts";

export const Route = createFileRoute("/_app/attacks")({
  validateSearch: attacksSearch,
  component: AttacksPage,
});

const PERIODS = ["24h", "7d", "30d"] as const;
const SHOWN = 10;

/** The globe and d3-geo are a chunk of their own, loaded when the globe is shown (not for the flat map). */
const AttackGlobe = lazy(() => import("../../components/attack-globe.tsx"));

/** Infrastructure, Attacks (ADR 0016): where the attacks that Wazuh reports come from. Read-only. */
function AttacksPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const canEdit = me.role === "owner" || me.role === "admin";
  const period = search.period ?? "24h";

  const overview = useQuery({
    queryKey: ["attacks-overview", period],
    queryFn: () => api<AttackOverview>(`/attacks/overview?period=${period}`),
    refetchInterval: 60_000,
  });
  const setSearch = (patch: Partial<AttacksSearch>, replace = false) =>
    navigate({ search: (prev) => ({ ...prev, ...patch }), replace });
  // Globe or flat map: remembered in this browser only (try/catch inside; the globe if storage is unavailable).
  const [mapView, setMapView] = useState<MapView>(readMapView);
  const chooseView = (view: MapView) => {
    setMapView(view);
    writeMapView(view);
  };
  // The latest events (ADR 0021): a stream, with polling as the fallback.
  const feed = useAttackFeed({ enabled: overview.data?.connected === true });
  const header = (
    <PageHeader icon={Globe} title={t("attacks.title")} description={t("attacks.description")} />
  );

  const data = overview.data;
  if (!data) {
    return (
      <>
        {header}
        <Card>
          <QueryStatus query={overview} />
        </Card>
      </>
    );
  }
  if (!data.connected) {
    return (
      <>
        {header}
        <Card>
          <div className="grid justify-items-start gap-3 px-5 py-6">
            <p className="max-w-[60ch] text-muted-foreground">
              {canEdit ? t("attacks.emptyAdmin") : t("attacks.emptyMember")}
            </p>
            {canEdit ? (
              <Link
                to="/settings"
                search={{ section: "xdr" }}
                className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground hover:bg-primary/90"
              >
                {t("attacks.connect")}
              </Link>
            ) : null}
          </div>
        </Card>
      </>
    );
  }

  const staleDataset =
    data.geoip.datasets.find((d) => d.kind === "country" && d.active?.stale)?.active ?? null;
  const w = data.window;
  const home = resolveHomePoint(data.home);
  const periodChoice = (
    <Segmented
      label={t("xdr.periodLabel")}
      value={period}
      options={PERIODS.map((p) => ({ value: p, label: t(`xdr.period.${PERIOD_KEY[p]}`) }))}
      onChange={(p) => setSearch({ period: p === "24h" ? undefined : p, cursor: undefined })}
    />
  );
  const settingsLink = canEdit ? (
    <Link
      to="/settings"
      search={{ section: "attacks" }}
      className="inline-flex h-10 items-center gap-2 rounded-md border border-input bg-card px-4 font-medium shadow-xs hover:bg-accent"
    >
      <Settings aria-hidden="true" className="size-4" />
      {t("attacks.manage")}
    </Link>
  ) : null;

  return (
    <>
      <PageHeader
        icon={Globe}
        title={t("attacks.title")}
        description={t("attacks.description")}
        actions={
          <>
            {periodChoice}
            {settingsLink}
          </>
        }
      />

      {data.geoip.missing ? (
        <Banner
          title={t("attacks.geoMissingTitle")}
          action={
            canEdit ? (
              <Link
                to="/settings"
                search={{ section: "attacks" }}
                className="inline-flex h-9 items-center rounded-md border border-input bg-card px-3 font-medium shadow-xs hover:bg-accent"
              >
                {t("attacks.geoLoad")}
              </Link>
            ) : undefined
          }
        >
          {canEdit ? t("attacks.geoMissingAdmin") : t("attacks.geoMissingMember")}
        </Banner>
      ) : staleDataset ? (
        <Banner
          title={t("attacks.geoStaleTitle")}
          action={
            canEdit ? (
              <Link
                to="/settings"
                search={{ section: "attacks" }}
                className="inline-flex h-9 items-center rounded-md border border-input bg-card px-3 font-medium shadow-xs hover:bg-accent"
              >
                {t("attacks.geoLoad")}
              </Link>
            ) : undefined
          }
        >
          {t("attacks.geoStaleText", { month: staleDataset.month ?? "?" })}
        </Banner>
      ) : null}

      {!w ? (
        <Card>
          <p className="px-5 py-6 text-muted-foreground">
            {data.syncedAt ? t("attacks.noWindowData") : t("attacks.waitingForData")}
          </p>
        </Card>
      ) : (
        <div className="grid gap-4">
          <Figures data={data} />
          <div className="grid items-start gap-4 @wide:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] @xwide:grid-cols-[minmax(0,5fr)_minmax(0,3fr)_minmax(0,3fr)]">
            <Card className="@wide:col-start-1 @wide:row-span-2 @wide:row-start-1">
              <CardHeader
                title={t("attacks.mapTitle")}
                description={t("attacks.mapDescription", { count: w.listedSources })}
                actions={
                  <Segmented
                    label={t("attacks.globe.viewLabel")}
                    value={mapView}
                    options={[
                      { value: "globe", label: t("attacks.globe.viewGlobe") },
                      { value: "map", label: t("attacks.globe.viewMap") },
                    ]}
                    onChange={chooseView}
                  />
                }
              />
              {mapView === "globe" ? (
                <Suspense
                  fallback={
                    <p
                      role="status"
                      className="grid min-h-72 place-items-center px-5 pb-5 text-muted-foreground"
                    >
                      {t("attacks.globe.loading")}
                    </p>
                  }
                >
                  <AttackGlobe
                    countries={w.countries}
                    home={home}
                    osintEnabled={data.osint.enabled}
                    events={feed.events}
                    selected={search.country}
                  />
                </Suspense>
              ) : (
                <AttackMap countries={w.countries} selected={search.country} />
              )}
              {mapView === "globe" && !home ? (
                <div
                  className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t px-5 py-2.5 text-sm text-muted-foreground"
                  data-testid="attack-no-home"
                >
                  <span className="min-w-0 flex-[1_1_20rem]">
                    {canEdit ? t("attacks.globe.noHomeText") : t("attacks.globe.noHomeMember")}
                  </span>
                  {canEdit ? (
                    <Link
                      to="/settings"
                      search={{ section: "attacks" }}
                      className="inline-flex h-8 items-center rounded-md border border-input bg-card px-3 font-medium text-foreground shadow-xs hover:bg-accent"
                    >
                      {t("attacks.globe.noHomeLink")}
                    </Link>
                  ) : null}
                </div>
              ) : null}
              <p className="border-t px-5 py-2.5 text-sm text-muted-foreground">
                {t("attacks.coverage", {
                  listed: formatNumber(w.listedSources),
                  alerts: formatNumber(w.listedAlerts),
                  total: formatNumber(w.attackAlerts),
                })}
                {data.syncedAt ? (
                  <>
                    {" "}
                    <time dateTime={data.syncedAt} title={formatDateTime(data.syncedAt)}>
                      {t("attacks.syncedAt", { when: formatRelative(data.syncedAt) })}
                    </time>
                  </>
                ) : null}
              </p>
            </Card>
            <AttackEventsCard
              className="@wide:col-start-2 @wide:row-start-1 @xwide:row-span-2"
              scrollClassName="@wide:max-h-[26rem] @xwide:max-h-[min(64vh,46rem)]"
              events={feed.events}
              live={feed.live ?? data.live}
              connected={feed.connected}
              query={feed.query}
              osintEnabled={data.osint.enabled}
              canEdit={canEdit}
            />
            <CountriesCard
              className="@wide:col-start-2 @wide:row-start-2 @xwide:col-start-3 @xwide:row-start-1"
              data={data}
              selected={search.country}
              onSelect={(country) => setSearch({ country, cursor: undefined })}
            />
            <NetworksCard
              className="@wide:col-start-1 @wide:row-start-3 @xwide:col-start-3 @xwide:row-start-2"
              data={data}
              selected={search.asn}
              onSelect={(asn) => setSearch({ asn, cursor: undefined })}
            />
            <AgentsCard
              className="@wide:col-start-2 @wide:row-start-3 @xwide:col-span-3 @xwide:col-start-1"
              data={data}
              selected={search.agent}
              onSelect={(agent, name) => setSearch({ agent, agentName: name, cursor: undefined })}
            />
          </div>
          {data.ai.state === "ready" ? (
            <AttackSummaryCard canAsk={me.role !== "viewer"} model={data.ai.model} />
          ) : null}
          <AttackSources
            state={search}
            onChange={(patch, replace) => setSearch(patch, replace)}
            overview={data}
          />
        </div>
      )}

      <p
        className="mt-5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground"
        data-testid="attack-attribution"
      >
        <a
          href={data.attribution.url}
          target="_blank"
          rel="noopener noreferrer"
          className="underline underline-offset-2 hover:text-foreground"
        >
          {data.attribution.text}
        </a>
        <span>{t("attacks.attributionMap")}</span>
        {data.osint.enabled ? (
          <span>{t("attacks.osint.leavesNote", { provider: data.osint.providerName })}</span>
        ) : null}
      </p>
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Key figures                                                                 */
/* -------------------------------------------------------------------------- */

function ChangeLine({ now, before }: { now: number; before: number | null | undefined }) {
  const { t } = useTranslation();
  const change = changeOf(now, before);
  const Icon = change.kind === "up" ? ArrowUp : change.kind === "down" ? ArrowDown : Minus;
  const label =
    change.kind === "up"
      ? t("attacks.changeUp", { count: formatNumber(change.by) })
      : change.kind === "down"
        ? t("attacks.changeDown", { count: formatNumber(change.by) })
        : change.kind === "same"
          ? t("attacks.changeSame")
          : t("attacks.changeUnknown");
  return (
    <div className="flex flex-wrap items-center gap-x-1 text-sm text-muted-foreground">
      <Icon aria-hidden="true" className="size-3.5 flex-none" />
      <span>{label}</span>
      {before !== null && before !== undefined ? (
        <span className="hidden @xl:inline">
          · {t("attacks.previousCount", { count: formatNumber(before) })}
        </span>
      ) : null}
    </div>
  );
}

function Figures({ data }: { data: AttackOverview }) {
  const { t } = useTranslation();
  const w = data.window;
  if (!w) return null;
  const tile = "min-w-0 rounded-lg border bg-card px-3.5 py-3";
  return (
    <section aria-label={t("attacks.figuresLabel")}>
      <dl
        className="grid grid-cols-2 gap-3 @3xl:grid-cols-4 @wide:grid-cols-5 @xwide:grid-cols-6"
        data-testid="attack-figures"
      >
        <div className={tile} data-figure="alerts">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.alerts")}</dt>
          <dd className="text-2xl font-semibold tabular-nums">{formatNumber(w.attackAlerts)}</dd>
          <ChangeLine now={w.attackAlerts} before={w.previousAttackAlerts} />
        </div>
        <div className={tile} data-figure="sources">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.sources")}</dt>
          <dd className="text-2xl font-semibold tabular-nums">{formatNumber(w.distinctSources)}</dd>
          <ChangeLine now={w.distinctSources} before={w.previousDistinctSources} />
        </div>
        <div className={tile} data-figure="countries">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.countries")}</dt>
          <dd className="text-2xl font-semibold tabular-nums">{formatNumber(w.countryCount)}</dd>
          <ChangeLine now={w.countryCount} before={w.previousCountryCount} />
        </div>
        <div className={cn(tile, "col-span-2 @3xl:col-span-1")} data-figure="agents">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.agents")}</dt>
          <dd className="grid min-w-0 gap-0.5">
            {w.agents.length === 0 ? (
              <span className="text-lg font-semibold">{t("attacks.figures.none")}</span>
            ) : (
              w.agents.slice(0, 3).map((a) => (
                <span key={a.agentId} className="flex min-w-0 items-baseline justify-between gap-2">
                  <span className="min-w-0 truncate font-medium" title={a.name}>
                    {a.name}
                  </span>
                  <span className="text-sm text-muted-foreground tabular-nums">{formatNumber(a.count)}</span>
                </span>
              ))
            )}
          </dd>
        </div>
        <div className={cn(tile, "hidden @wide:block")} data-figure="internal">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.internal")}</dt>
          <dd className="text-2xl font-semibold tabular-nums">{formatNumber(w.internal.alerts)}</dd>
          <div className="text-sm text-muted-foreground">{t("attacks.figures.internalHint")}</div>
        </div>
        <div className={cn(tile, "hidden @xwide:block")} data-figure="unlocated">
          <dt className="text-sm text-muted-foreground">{t("attacks.figures.unlocated")}</dt>
          <dd className="text-2xl font-semibold tabular-nums">{formatNumber(w.unlocated.alerts)}</dd>
          <div className="text-sm text-muted-foreground">{t("attacks.figures.unlocatedHint")}</div>
        </div>
      </dl>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Lists: the table alternative to the map                                     */
/* -------------------------------------------------------------------------- */

/** A table whose count column carries a plain proportional bar. SVG, because the CSP allows no inline style. */
function Bar({ value, max }: { value: number; max: number }) {
  return (
    <svg aria-hidden="true" className="mt-1 block h-1.5 w-full" preserveAspectRatio="none">
      <rect width="100%" height="100%" rx="3" className="fill-muted" />
      <rect
        width={`${Math.max(2, Math.round((value / Math.max(1, max)) * 100))}%`}
        height="100%"
        rx="3"
        className="fill-map-4"
      />
    </svg>
  );
}

function Expand({
  total,
  shown,
  open,
  onToggle,
}: {
  total: number;
  shown: number;
  open: boolean;
  onToggle: () => void;
}) {
  const { t } = useTranslation();
  if (total <= shown) return null;
  return (
    <div className="border-t px-5 py-2.5">
      <Button variant="link" className="text-sm" aria-expanded={open} onClick={onToggle}>
        {open ? t("pagination.showFewer") : t("pagination.showAll", { count: total })}
      </Button>
    </div>
  );
}

function CountriesCard({
  data,
  selected,
  onSelect,
  className,
}: {
  className?: string;
  data: AttackOverview;
  selected: string | undefined;
  onSelect: (country: string | undefined) => void;
}) {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const w = data.window;
  if (!w) return null;
  const max = Math.max(1, ...w.countries.map((c) => c.alerts), w.internal.alerts, w.unlocated.alerts);
  const rows = open ? w.countries : w.countries.slice(0, SHOWN);
  const pick = (code: string) => onSelect(selected === code ? undefined : code);
  const button = "text-left hover:underline aria-pressed:font-semibold";
  return (
    <Card className={className}>
      <CardHeader title={t("attacks.countriesTitle")} description={t("attacks.countriesDescription")} />
      <table className="w-full text-left" data-testid="attack-countries">
        <thead className="text-sm text-muted-foreground">
          <tr className="border-y">
            <th className="px-5 py-2 font-medium">{t("attacks.columnCountry")}</th>
            <th className="px-3 py-2 text-right font-medium">{t("attacks.columnAlerts")}</th>
            <th className="px-5 py-2 text-right font-medium">{t("attacks.columnAddresses")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr
              key={c.country}
              className="border-b align-top last:border-0"
              data-testid={`country-${c.country}`}
            >
              <td className="px-5 py-2.5">
                <button
                  type="button"
                  aria-pressed={selected === c.country}
                  className={button}
                  onClick={() => pick(c.country)}
                >
                  {countryName(c.country, i18n.language)}{" "}
                  <span className="font-mono text-sm text-muted-foreground">{c.country}</span>
                </button>
                <Bar value={c.alerts} max={max} />
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums">{formatNumber(c.alerts)}</td>
              <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(c.sources)}</td>
            </tr>
          ))}
          {open || w.countries.length <= SHOWN ? (
            <>
              {w.unlocated.sources > 0 ? (
                <tr className="border-b align-top last:border-0" data-testid="country-unknown">
                  <td className="px-5 py-2.5">
                    <button
                      type="button"
                      aria-pressed={selected === "unknown"}
                      className={button}
                      title={t("attacks.unknownHint")}
                      onClick={() => pick("unknown")}
                    >
                      {t("attacks.unknown")}
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums">{formatNumber(w.unlocated.alerts)}</td>
                  <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(w.unlocated.sources)}</td>
                </tr>
              ) : null}
              {w.internal.sources > 0 ? (
                <tr className="border-b align-top last:border-0" data-testid="country-internal">
                  <td className="px-5 py-2.5">
                    <button
                      type="button"
                      aria-pressed={selected === "internal"}
                      className={button}
                      title={t("attacks.internalHint")}
                      onClick={() => pick("internal")}
                    >
                      <Badge tone="neutral">{t("attacks.internal")}</Badge>
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums">{formatNumber(w.internal.alerts)}</td>
                  <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(w.internal.sources)}</td>
                </tr>
              ) : null}
            </>
          ) : null}
          {w.countries.length === 0 && w.unlocated.sources === 0 && w.internal.sources === 0 ? (
            <tr>
              <td colSpan={3} className="px-5 py-4 text-muted-foreground">
                {t("attacks.noSources")}
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
      <Expand total={w.countries.length} shown={SHOWN} open={open} onToggle={() => setOpen(!open)} />
    </Card>
  );
}

function NetworksCard({
  data,
  selected,
  onSelect,
  className,
}: {
  className?: string;
  data: AttackOverview;
  selected: string | undefined;
  onSelect: (asn: string | undefined) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const w = data.window;
  if (!w) return null;
  const rows = open ? w.asns : w.asns.slice(0, SHOWN);
  const max = Math.max(1, ...w.asns.map((a) => a.alerts));
  return (
    <Card className={className}>
      <CardHeader title={t("attacks.networksTitle")} description={t("attacks.networksDescription")} />
      {w.asns.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">
          {data.geoip.asnMissing ? t("attacks.geoMissingMember") : t("attacks.noSources")}
        </p>
      ) : (
        <table className="w-full text-left" data-testid="attack-networks">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-y">
              <th className="px-5 py-2 font-medium">{t("attacks.columnNetwork")}</th>
              <th className="px-3 py-2 text-right font-medium">{t("attacks.columnAlerts")}</th>
              <th className="px-5 py-2 text-right font-medium">{t("attacks.columnAddresses")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.asn} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5">
                  <button
                    type="button"
                    aria-pressed={selected === String(a.asn)}
                    className="text-left hover:underline aria-pressed:font-semibold"
                    onClick={() => onSelect(selected === String(a.asn) ? undefined : String(a.asn))}
                  >
                    <span className="font-mono text-sm">AS{a.asn}</span>
                    {a.org ? <span className="ml-1.5 break-words">{a.org}</span> : null}
                  </button>
                  <Bar value={a.alerts} max={max} />
                </td>
                <td className="px-3 py-2.5 text-right tabular-nums">{formatNumber(a.alerts)}</td>
                <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(a.sources)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Expand total={w.asns.length} shown={SHOWN} open={open} onToggle={() => setOpen(!open)} />
    </Card>
  );
}

function AgentsCard({
  data,
  selected,
  onSelect,
  className,
}: {
  className?: string;
  data: AttackOverview;
  selected: string | undefined;
  onSelect: (agent: string | undefined, name: string | undefined) => void;
}) {
  const { t } = useTranslation();
  const w = data.window;
  if (!w) return null;
  const max = Math.max(1, ...w.agents.map((a) => a.count));
  return (
    <Card className={className}>
      <CardHeader title={t("attacks.agentsTitle")} description={t("attacks.agentsDescription")} />
      {w.agents.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("attacks.figures.none")}</p>
      ) : (
        <table className="w-full text-left" data-testid="attack-agents">
          <thead className="text-sm text-muted-foreground">
            <tr className="border-y">
              <th className="px-5 py-2 font-medium">{t("attacks.columnAgent")}</th>
              <th className="px-5 py-2 text-right font-medium">{t("attacks.columnAlerts")}</th>
            </tr>
          </thead>
          <tbody>
            {w.agents.map((a) => (
              <tr key={a.agentId} className="border-b align-top last:border-0">
                <td className="px-5 py-2.5">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <button
                      type="button"
                      aria-pressed={selected === a.agentId}
                      className="text-left break-all hover:underline aria-pressed:font-semibold"
                      onClick={() =>
                        onSelect(
                          selected === a.agentId ? undefined : a.agentId,
                          selected === a.agentId ? undefined : a.name,
                        )
                      }
                    >
                      {a.name}
                    </button>
                    {a.hostId ? (
                      <Link
                        to="/servers/$id"
                        params={{ id: a.hostId }}
                        className="inline-flex items-center gap-1 text-sm text-primary-text hover:underline"
                        title={t("attacks.openServer", { name: a.name })}
                      >
                        <Server aria-hidden="true" className="size-3.5" />
                        {t("attacks.openServer", { name: a.name })}
                      </Link>
                    ) : (
                      <Link
                        to="/xdr"
                        search={{ q: a.name }}
                        className="text-sm text-primary-text hover:underline"
                      >
                        {t("attacks.findInXdr", { name: a.name })}
                      </Link>
                    )}
                  </div>
                  <Bar value={a.count} max={max} />
                </td>
                <td className="px-5 py-2.5 text-right tabular-nums">{formatNumber(a.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
