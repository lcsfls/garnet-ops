import { EXPOSURE_PORTS, HSTS_WEAK_BELOW_SECONDS, parseHsts } from "@garnetops/core/exposure";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { cn } from "../lib/cn.ts";
import type {
  ExposureDetail,
  ExposureFindingRow,
  ExposureHistoryRow,
  ExposurePortRow,
  ExposureSeverity,
} from "../lib/exposure.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import { CertificateExpiry, countryName, useExposureError } from "./exposure-parts.tsx";
import { Segmented } from "./filters.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { Badge, SeverityBadge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

export const dash = <span className="text-muted-foreground">–</span>;

/** A two-column list of facts: a muted label and the value as text. */
export function Facts({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-5 gap-y-2 px-5 pb-5 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/* -------------------------------------------------------------------------- */
/* Findings                                                                    */
/* -------------------------------------------------------------------------- */

/** The title and the sentence of a finding in the user's language. A rule this version does not know shows as its id. */
export function useRuleText() {
  const { t, i18n } = useTranslation();
  return (f: Pick<ExposureFindingRow, "rule" | "params">) => {
    const titleKey = `exposure.rules.${f.rule}.title`;
    const textKey = `exposure.rules.${f.rule}.text`;
    if (!i18n.exists(titleKey)) return { title: f.rule, text: "" };
    const service = typeof f.params.service === "string" ? f.params.service : "";
    const category = typeof f.params.category === "string" ? f.params.category : "";
    const values = {
      ...f.params,
      service: i18n.exists(`exposure.service.${service}`)
        ? t(`exposure.service.${service}` as MessageKey)
        : service,
      category: i18n.exists(`exposure.category.${category}`)
        ? t(`exposure.category.${category}` as MessageKey)
        : category,
    };
    return {
      title: t(titleKey as MessageKey, values as Record<string, string | number>) as string,
      text: t(textKey as MessageKey, values as Record<string, string | number>) as string,
    };
  };
}

export function FindingsCard({
  detail,
  state,
  onState,
  className,
}: {
  detail: ExposureDetail;
  state: "open" | "resolved" | "all";
  onState: (state: "open" | "resolved" | "all") => void;
  className?: string;
}) {
  const { t } = useTranslation();
  const ruleText = useRuleText();
  const shown = detail.findings.filter((f) => state === "all" || f.state === state);
  const counts = {
    open: detail.findings.filter((f) => f.state === "open").length,
    resolved: detail.findings.filter((f) => f.state === "resolved").length,
  };
  return (
    <Card className={className}>
      <CardHeader title={t("exposure.findingsTitle")} description={t("exposure.findingsDescription")} />
      <div className="px-5 pb-3">
        <Segmented
          label={t("exposure.findingsFilter")}
          value={state}
          options={[
            { value: "open", label: t("exposure.findingState.open"), count: counts.open },
            { value: "resolved", label: t("exposure.findingState.resolved"), count: counts.resolved },
            { value: "all", label: t("exposure.findingState.all"), count: counts.open + counts.resolved },
          ]}
          onChange={onState}
        />
      </div>
      {shown.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">
          {state === "resolved"
            ? t("exposure.findingsNoneResolved")
            : detail.stage1.lastAt
              ? t("exposure.findingsNone")
              : t("exposure.findingsNotYet")}
        </p>
      ) : (
        <ul data-testid="exposure-findings">
          {shown.map((f) => {
            const { title, text } = ruleText(f);
            return (
              <li key={f.id} className="border-t px-5 py-3 first:border-t-0">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <b className="font-medium">{title}</b>
                  {f.state === "resolved" ? (
                    <Badge tone="neutral">{t("exposure.findingState.resolvedBadge")}</Badge>
                  ) : null}
                  <span className="text-sm text-muted-foreground">{t(`exposure.stageName.${f.stage}`)}</span>
                </div>
                {text ? <p className="mt-1 text-sm text-muted-foreground break-words">{text}</p> : null}
                <p className="mt-1 text-xs text-muted-foreground">
                  {f.state === "resolved" && f.resolvedAt
                    ? t("exposure.findingResolvedOn", { when: formatDateTime(f.resolvedAt) })
                    : t("exposure.findingFirstSeen", { when: formatRelative(f.firstSeenAt) })}
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* DNS                                                                         */
/* -------------------------------------------------------------------------- */

export function DnsCard({
  detail,
  canEdit,
  className,
}: {
  detail: ExposureDetail;
  canEdit: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const p = detail.passive;
  const dns = p?.dns ?? null;
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["exposure"] });
  const addName = useMutation({
    mutationFn: (id: string) => api(`/exposure/discoveries/${id}/add`, { method: "POST" }),
    onSuccess: refresh,
  });
  const dismiss = useMutation({
    mutationFn: (id: string) => api(`/exposure/discoveries/${id}/dismiss`, { method: "POST" }),
    onSuccess: refresh,
  });
  const list = (items: string[]) =>
    items.length === 0 ? (
      dash
    ) : (
      <ul className="grid gap-0.5">
        {items.map((x) => (
          <li key={x} className="font-mono break-all">
            {x}
          </li>
        ))}
      </ul>
    );

  return (
    <Card className={className}>
      <CardHeader title={t("exposure.dnsTitle")} description={t("exposure.dnsDescription")} />
      {!p ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("exposure.notYet")}</p>
      ) : (
        <Facts
          rows={[
            [t("exposure.dnsAddresses"), list(p.addresses)],
            ...(p.nonPublic.length > 0
              ? ([[t("exposure.dnsNonPublic"), list(p.nonPublic)]] as [string, React.ReactNode][])
              : []),
            ...(dns
              ? ([
                  [t("exposure.dnsCname"), list(dns.cname)],
                  [
                    t("exposure.dnsMx"),
                    dns.mx.length === 0 ? (
                      dash
                    ) : (
                      <ul key="mx" className="grid gap-0.5">
                        {dns.mx.map((m) => (
                          <li key={`${m.priority}-${m.exchange}`} className="font-mono break-all">
                            {m.priority} {m.exchange}
                          </li>
                        ))}
                      </ul>
                    ),
                  ],
                  [t("exposure.dnsNs"), list(dns.ns)],
                  [
                    t("exposure.dnsCaa"),
                    dns.caa.length === 0 ? (
                      dns.failed.includes("caa") ? (
                        t("exposure.lookupFailed")
                      ) : (
                        t("exposure.dnsNone")
                      )
                    ) : (
                      <ul key="caa" className="grid gap-0.5">
                        {dns.caa.map((c) => (
                          <li key={`${c.tag}-${c.value}`} className="font-mono break-all">
                            {c.tag} {c.value}
                          </li>
                        ))}
                      </ul>
                    ),
                  ],
                  [
                    t("exposure.dnsSpf"),
                    dns.failed.includes("txt") ? (
                      t("exposure.lookupFailed")
                    ) : dns.spf.record ? (
                      <>
                        <span className="font-mono break-all">{dns.spf.record}</span>
                        <span className="block text-muted-foreground">
                          {t(`exposure.spfPolicy.${dns.spf.policy}`)}
                        </span>
                      </>
                    ) : (
                      t("exposure.dnsNone")
                    ),
                  ],
                  [
                    t("exposure.dnsDmarc"),
                    dns.failed.includes("dmarc") ? (
                      t("exposure.lookupFailed")
                    ) : dns.dmarc.record ? (
                      <>
                        <span className="font-mono break-all">{dns.dmarc.record}</span>
                        {dns.dmarc.policy ? (
                          <span className="block text-muted-foreground">
                            {t(`exposure.dmarcPolicy.${dns.dmarc.policy}`)}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      t("exposure.dnsNone")
                    ),
                  ],
                  [t("exposure.dnsDnssec"), t("exposure.dnssecUnknown")],
                ] as [string, React.ReactNode][])
              : ([[t("exposure.dnsPtr"), list(p.ptr ?? [])]] as [string, React.ReactNode][])),
          ]}
        />
      )}
      {detail.suggestions.length > 0 ? (
        <section aria-labelledby="exposure-suggestions" className="border-t px-5 py-4">
          <h3 id="exposure-suggestions" className="font-medium">
            {t("exposure.suggestionsTitle")}
          </h3>
          <p className="mb-2 text-sm text-muted-foreground">{t("exposure.suggestionsText")}</p>
          <ul className="grid gap-1.5" data-testid="exposure-suggestions">
            {detail.suggestions.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm break-all">{s.name}</span>
                <span className="text-xs text-muted-foreground">
                  {t(`exposure.suggestionSource.${s.source}`)}
                </span>
                {canEdit ? (
                  <span className="ml-auto flex gap-1.5">
                    <Button
                      variant="outline"
                      className="h-8 px-3 text-sm"
                      disabled={addName.isPending}
                      onClick={() => addName.mutate(s.id)}
                      aria-label={t("exposure.suggestionAddNamed", { name: s.name })}
                    >
                      {t("exposure.suggestionAdd")}
                    </Button>
                    <Button
                      variant="ghost"
                      className="h-8 px-3 text-sm"
                      disabled={dismiss.isPending}
                      onClick={() => dismiss.mutate(s.id)}
                      aria-label={t("exposure.suggestionDismissNamed", { name: s.name })}
                    >
                      {t("exposure.suggestionDismiss")}
                    </Button>
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* TLS                                                                         */
/* -------------------------------------------------------------------------- */

function TlsFacts({ tls }: { tls: NonNullable<ExposureDetail["passive"]>["tls"][number] }) {
  const { t } = useTranslation();
  const rows: [string, React.ReactNode][] = [];
  if (!tls.ok) {
    rows.push([t("exposure.tlsHandshake"), t(`exposure.tlsError.${tls.error ?? "handshake"}`)]);
    return <Facts rows={rows} />;
  }
  rows.push([t("exposure.tlsProtocol"), `${tls.protocol ?? ""} ${tls.cipher ? `· ${tls.cipher}` : ""}`]);
  if (tls.trusted !== null) {
    rows.push([
      t("exposure.tlsTrust"),
      tls.trusted ? t("exposure.tlsTrusted") : t("exposure.tlsNotTrusted", { reason: tls.trustError ?? "" }),
    ]);
  }
  rows.push([
    t("exposure.tlsName"),
    tls.nameMatches === null
      ? t("exposure.tlsNameNotChecked")
      : tls.nameMatches
        ? t("exposure.tlsNameMatches")
        : t("exposure.tlsNameDiffers"),
  ]);
  if (tls.cert) {
    rows.push(
      [
        t("exposure.tlsSubject"),
        <span key="s" className="break-all">
          {tls.cert.subject}
        </span>,
      ],
      [
        t("exposure.tlsIssuer"),
        <span key="i" className="break-all">
          {tls.cert.issuer}
        </span>,
      ],
      [
        t("exposure.tlsNames"),
        tls.cert.sans.length ? (
          <span key="n" className="font-mono break-all">
            {tls.cert.sans.join(", ")}
          </span>
        ) : (
          dash
        ),
      ],
      [
        t("exposure.tlsValid"),
        <span key="v">
          {formatDateTime(tls.cert.validFrom)} – {formatDateTime(tls.cert.validTo)} (
          <CertificateExpiry expires={tls.cert.validTo} />)
        </span>,
      ],
      [
        t("exposure.tlsKey"),
        `${(tls.cert.keyType ?? "").toUpperCase()}${tls.cert.keyBits ? ` ${tls.cert.keyBits}` : ""}${tls.cert.selfSigned ? ` · ${t("exposure.tlsSelfSigned")}` : ""}`,
      ],
      [
        t("exposure.tlsFingerprint"),
        <span key="f" className="font-mono text-xs break-all">
          {tls.cert.fingerprint}
        </span>,
      ],
    );
  }
  rows.push([t("exposure.tlsChain"), formatNumber(tls.chainLength)]);
  if (tls.legacy) {
    const word = (v: boolean | null) => (v === null ? dash : v ? t("exposure.yes") : t("exposure.no"));
    rows.push(
      [t("exposure.tlsLegacy10"), word(tls.legacy.tls10)],
      [t("exposure.tlsLegacy11"), word(tls.legacy.tls11)],
    );
  }
  return <Facts rows={rows} />;
}

export function TlsCard({ detail, className }: { detail: ExposureDetail; className?: string }) {
  const { t, i18n } = useTranslation();
  const p = detail.passive;
  return (
    <Card className={className}>
      <CardHeader title={t("exposure.tlsTitle")} description={t("exposure.tlsDescription")} />
      {!p ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("exposure.notYet")}</p>
      ) : p.tls.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">
          {p.addresses.length === 0 ? t("exposure.noAddress") : t("exposure.tlsNone")}
        </p>
      ) : (
        p.tls.map((tls) => {
          const geo = p.geo.find((g) => g.address === tls.address);
          return (
            <section key={tls.address} className="border-t first:border-t-0" aria-label={tls.address}>
              <h3 className="px-5 pt-4 pb-2 font-mono text-sm font-medium">
                {tls.address}:{tls.port}
                {geo?.country ? (
                  <span className="ml-2 font-sans font-normal text-muted-foreground">
                    {countryName(geo.country, i18n.language)}
                    {geo.asn ? ` · AS${geo.asn}${geo.org ? ` ${geo.org}` : ""}` : ""}
                  </span>
                ) : null}
              </h3>
              <TlsFacts tls={tls} />
            </section>
          );
        })
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* HTTP                                                                        */
/* -------------------------------------------------------------------------- */

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
] as const;

export function HttpCard({ detail, className }: { detail: ExposureDetail; className?: string }) {
  const { t } = useTranslation();
  const p = detail.passive;
  const http = p?.http ?? null;
  return (
    <Card className={className}>
      <CardHeader title={t("exposure.httpTitle")} description={t("exposure.httpDescription")} />
      {!p ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("exposure.notYet")}</p>
      ) : (
        <>
          <Facts
            rows={[
              [
                t("exposure.httpPlain"),
                p.plain
                  ? p.plain.status === null
                    ? t(`exposure.httpError.${p.plain.error ?? "refused"}`)
                    : p.plain.redirectsToHttps
                      ? t("exposure.httpPlainRedirects", { status: p.plain.status })
                      : t("exposure.httpPlainAnswers", { status: p.plain.status })
                  : dash,
              ],
              [
                t("exposure.httpHttps"),
                http
                  ? http.status === null
                    ? t(`exposure.httpError.${http.error ?? "refused"}`)
                    : t("exposure.httpStatus", { status: http.status })
                  : t("exposure.httpNotOpen"),
              ],
              ...(http?.finalUrl
                ? ([
                    [
                      t("exposure.httpFinal"),
                      <span key="u" className="font-mono break-all">
                        {http.finalUrl}
                      </span>,
                    ],
                  ] as [string, React.ReactNode][])
                : []),
              ...(http && http.redirects.length > 0
                ? ([
                    [
                      t("exposure.httpRedirects"),
                      <ul key="r" className="grid gap-0.5">
                        {http.redirects.map((r) => (
                          <li key={`${r.status}-${r.to}`} className="break-all">
                            <span className="font-mono">{r.to}</span> ({r.status},{" "}
                            {r.followed ? t("exposure.httpFollowed") : t("exposure.httpNotFollowed")})
                          </li>
                        ))}
                      </ul>,
                    ],
                  ] as [string, React.ReactNode][])
                : []),
            ]}
          />
          {http && http.status !== null ? (
            <div className="border-t px-5 py-4">
              <h3 className="mb-2 font-medium">{t("exposure.headersTitle")}</h3>
              <table className="w-full text-left text-sm" data-testid="exposure-headers">
                <tbody>
                  {SECURITY_HEADERS.map((name) => {
                    const value = http.headers[name];
                    const hsts = name === "strict-transport-security" ? parseHsts(value) : null;
                    return (
                      <tr key={name} className="border-b last:border-0 align-top">
                        <th
                          scope="row"
                          className="py-1.5 pr-4 font-mono text-xs font-normal text-muted-foreground"
                        >
                          {name}
                        </th>
                        <td className="py-1.5 break-all">
                          {value ? (
                            <>
                              <span className="font-mono">{value}</span>
                              {hsts && hsts.maxAge < HSTS_WEAK_BELOW_SECONDS ? (
                                <span className="block text-muted-foreground">{t("exposure.hstsShort")}</span>
                              ) : null}
                            </>
                          ) : (
                            <span className="text-muted-foreground">{t("exposure.headerMissing")}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <h3 className="mt-4 mb-1 font-medium">{t("exposure.bannersTitle")}</h3>
              <table className="w-full text-left text-sm" data-testid="exposure-banners">
                <tbody>
                  {(["server", "x-powered-by"] as const).map((name) => (
                    <tr key={name} className="border-b last:border-0 align-top">
                      <th
                        scope="row"
                        className="py-1.5 pr-4 font-mono text-xs font-normal text-muted-foreground"
                      >
                        {name}
                      </th>
                      <td className="py-1.5 font-mono break-all">
                        {http.headers[name] ?? (
                          <span className="font-sans text-muted-foreground">
                            {t("exposure.headerMissing")}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-2 text-sm text-muted-foreground">{t("exposure.bannerNote")}</p>
            </div>
          ) : null}
        </>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Ports                                                                       */
/* -------------------------------------------------------------------------- */

function PortRisk({ port }: { port: number }) {
  const { t } = useTranslation();
  const spec = EXPOSURE_PORTS.find((x) => x.port === port);
  if (!spec?.severity) return <span className="text-muted-foreground">{t("exposure.portUsual")}</span>;
  return <SeverityBadge severity={spec.severity as ExposureSeverity} />;
}

export function PortsCard({
  detail,
  canEdit,
  onStage2,
  className,
}: {
  detail: ExposureDetail;
  canEdit: boolean;
  onStage2: () => void;
  className?: string;
}) {
  const { t } = useTranslation();
  const a = detail.active;
  const rows: ExposurePortRow[] = detail.ports;
  return (
    <Card className={className}>
      <CardHeader
        title={t("exposure.portsTitle")}
        description={t("exposure.portsDescription", { count: EXPOSURE_PORTS.length })}
        actions={
          canEdit ? (
            <Button variant="outline" className="h-9 px-3 text-sm" onClick={onStage2}>
              {t("exposure.stage2Manage")}
            </Button>
          ) : undefined
        }
      />
      {!a ? (
        <p className="px-5 pb-5 text-muted-foreground" data-testid="ports-empty">
          {detail.stage2.enabled ? t("exposure.portsWaiting") : t("exposure.portsOff")}
        </p>
      ) : (
        <>
          <p className="px-5 pb-3 text-sm text-muted-foreground">
            {t("exposure.portsSummary", {
              checked: a.checked,
              open: rows.length,
              closed: a.closed,
              silent: a.noAnswer,
              when: formatDateTime(a.takenAt),
            })}
          </p>
          {rows.length === 0 ? (
            <p className="px-5 pb-5">{t("exposure.portsNoneOpen")}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm" data-testid="exposure-ports">
                <thead className="text-muted-foreground">
                  <tr className="border-y">
                    <th className="px-5 py-2 font-medium">{t("exposure.portColumn")}</th>
                    <th className="px-3 py-2 font-medium">{t("exposure.portService")}</th>
                    <th className="px-3 py-2 font-medium">{t("exposure.portRisk")}</th>
                    <th className="px-3 py-2 font-medium">{t("exposure.portBanner")}</th>
                    <th className="hidden px-3 py-2 font-medium @xwide:table-cell">
                      {t("exposure.portFirstSeen")}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={`${r.address}-${r.port}`} className="border-b align-top last:border-0">
                      <td className="px-5 py-2.5">
                        <span className="font-mono font-medium">{r.port}</span>
                        <div className="font-mono text-xs break-all text-muted-foreground">{r.address}</div>
                      </td>
                      <td className="px-3 py-2.5">
                        {t(`exposure.service.${r.service}` as MessageKey, { defaultValue: r.service })}
                      </td>
                      <td className="px-3 py-2.5">
                        <PortRisk port={r.port} />
                      </td>
                      <td className="px-3 py-2.5">
                        {r.banner ? (
                          <pre className="max-w-[48ch] font-mono text-xs whitespace-pre-wrap break-all">
                            {r.banner}
                          </pre>
                        ) : r.tls?.ok ? (
                          <span className="text-muted-foreground">
                            {r.tls.protocol} ·{" "}
                            {r.tls.cert ? <CertificateExpiry expires={r.tls.cert.validTo} /> : null}
                          </span>
                        ) : (
                          dash
                        )}
                      </td>
                      <td className="hidden px-3 py-2.5 @xwide:table-cell">
                        <time dateTime={r.firstSeenAt}>{formatRelative(r.firstSeenAt)}</time>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* History                                                                     */
/* -------------------------------------------------------------------------- */

function RunResult({ run }: { run: ExposureHistoryRow }) {
  const { t } = useTranslation();
  const errorText = useExposureError();
  if (run.state === "queued" || run.state === "running")
    return <span>{t(`exposure.runState.${run.state}`)}</span>;
  if (run.state === "failed") return <span className="text-destructive-text">{errorText(run.error)}</span>;
  const c = run.findingCounts ?? {};
  const total = (c.critical ?? 0) + (c.high ?? 0) + (c.medium ?? 0) + (c.low ?? 0);
  return (
    <span>
      {t("exposure.runFindings", { count: total })}
      {run.stage === "active" && run.openPorts !== null
        ? ` · ${t("exposure.runOpenPorts", { count: run.openPorts })}`
        : ""}
    </span>
  );
}

export function HistoryCard({ detail, className }: { detail: ExposureDetail; className?: string }) {
  const { t } = useTranslation();
  return (
    <Card className={className}>
      <CardHeader title={t("exposure.historyTitle")} description={t("exposure.historyDescription")} />
      {detail.runs.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("exposure.historyNone")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm" data-testid="exposure-history">
            <thead className="text-muted-foreground">
              <tr className="border-y">
                <th className="px-5 py-2 font-medium">{t("exposure.historyWhen")}</th>
                <th className="px-3 py-2 font-medium">{t("exposure.historyStage")}</th>
                <th className="hidden px-3 py-2 font-medium @3xl:table-cell">
                  {t("exposure.historyTrigger")}
                </th>
                <th className="px-3 py-2 font-medium">{t("exposure.historyResult")}</th>
              </tr>
            </thead>
            <tbody>
              {detail.runs.map((run) => (
                <tr key={run.id} className={cn("border-b align-top last:border-0")}>
                  <td className="px-5 py-2.5 whitespace-nowrap">
                    <time dateTime={run.createdAt} title={formatDateTime(run.createdAt)}>
                      {formatRelative(run.createdAt)}
                    </time>
                  </td>
                  <td className="px-3 py-2.5">{t(`exposure.stageName.${run.stage}`)}</td>
                  <td className="hidden px-3 py-2.5 @3xl:table-cell">
                    {t(`exposure.trigger.${run.trigger}`)}
                  </td>
                  <td className="px-3 py-2.5">
                    <RunResult run={run} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
