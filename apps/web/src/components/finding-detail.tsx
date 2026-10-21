import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, ShieldAlert, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { addLocalDays, endOfLocalDay, localDateInput } from "../lib/dates.ts";
import { formatDate, formatDateTime, formatPercent } from "../lib/format.ts";
import type { FindingDetail as Detail } from "../lib/types.ts";
import { Card } from "./page-header.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge, SeverityBadge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Field } from "./ui/field.tsx";

/**
 * Details of one finding. All text comes from scanned data (CVE descriptions,
 * paths) and is treated as untrusted: rendered as plain text only, and links
 * only for http(s) URLs, opened without a referrer or window access.
 */
export function FindingDetail({
  id,
  canEdit,
  onClose,
}: {
  id: string;
  canEdit: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { data, isError } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api<Detail>(`/findings/${id}`),
  });

  // Bring the pane into view when a finding is picked from further down the list.
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.scrollIntoView({ block: "nearest" });
  }, []);

  return (
    // Below the wide step the pane sits above the list; from wide on it sits beside it and stays in view.
    <div
      ref={ref}
      className="order-first scroll-mt-6 self-start @wide:sticky @wide:top-0 @wide:order-none @wide:max-h-[calc(100dvh-8.5rem)] @wide:overflow-y-auto @wide:rounded-lg"
    >
      <Card>
        <div className="flex items-start gap-3 border-b px-5 py-4">
          <div className="min-w-0 flex-1">
            {data ? (
              <>
                <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
                  <SeverityBadge severity={data.severity} />
                  {data.vulnerability.knownExploited ? (
                    <Badge className="bg-destructive/15 text-destructive-text">
                      <ShieldAlert aria-hidden="true" className="size-3.5" />
                      {t("findings.kev")}
                    </Badge>
                  ) : null}
                  <Badge className="bg-muted text-muted-foreground">{t(`findingState.${data.state}`)}</Badge>
                </div>
                <h2 className="text-lg font-semibold break-all">{data.vulnerability.id}</h2>
                <p className="font-mono text-sm break-all text-muted-foreground">
                  {data.packageName} {data.packageVersion} · {data.repository.name}
                </p>
              </>
            ) : (
              <p className="text-muted-foreground">{isError ? t("errors.generic") : t("common.loading")}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t("findings.close")}
            className="grid size-8 flex-none place-items-center rounded-md hover:bg-accent"
          >
            <X aria-hidden="true" className="size-4" />
          </button>
        </div>
        {data ? <DetailBody data={data} canEdit={canEdit} /> : null}
      </Card>
    </div>
  );
}

function DetailBody({ data, canEdit }: { data: Detail; canEdit: boolean }) {
  const { t } = useTranslation();
  const v = data.vulnerability;
  return (
    <div className="grid gap-5 px-5 py-4">
      {v.description ? <p className="whitespace-pre-line">{v.description}</p> : null}

      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
        <dt className="text-muted-foreground">{t("findings.columnFixedIn")}</dt>
        <dd className="font-mono break-all">
          {data.fixedIn?.length ? (
            data.fixedIn.join(", ")
          ) : (
            <span className="font-sans">{t("findings.noFix")}</span>
          )}
        </dd>
        {v.cvssScore !== null ? (
          <>
            <dt className="text-muted-foreground">{t("findings.cvss")}</dt>
            <dd>
              {v.cvssScore.toFixed(1)}
              {v.cvssVector ? (
                <span className="ml-2 font-mono break-all text-muted-foreground">{v.cvssVector}</span>
              ) : null}
            </dd>
          </>
        ) : null}
        {v.epss !== null ? (
          <>
            <dt className="text-muted-foreground">{t("findings.epss")}</dt>
            <dd>
              {formatPercent(v.epss)} <span className="text-muted-foreground">{t("findings.epssHint")}</span>
            </dd>
          </>
        ) : null}
        {v.publishedAt ? (
          <>
            <dt className="text-muted-foreground">{t("findings.columnPublished")}</dt>
            <dd>{formatDateTime(v.publishedAt)}</dd>
          </>
        ) : null}
        {v.modifiedAt ? (
          <>
            <dt className="text-muted-foreground">{t("findings.modified")}</dt>
            <dd>{formatDateTime(v.modifiedAt)}</dd>
          </>
        ) : null}
        {v.aliases?.length ? (
          <>
            <dt className="text-muted-foreground">{t("findings.aliases")}</dt>
            <dd className="font-mono break-all">{v.aliases.join(", ")}</dd>
          </>
        ) : null}
        <dt className="text-muted-foreground">{t("findings.columnFirstSeen")}</dt>
        <dd>{formatDateTime(data.firstSeenAt)}</dd>
      </dl>

      {v.knownExploited ? <Alert tone="error">{t("findings.kevHint")}</Alert> : null}

      {data.locations?.length ? (
        <div>
          <h3 className="mb-1 text-sm font-medium">{t("findings.locations")}</h3>
          <ul className="grid gap-0.5 font-mono text-sm break-all text-muted-foreground">
            {data.locations.map((path) => (
              <li key={path}>{path}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {v.urls?.length ? (
        <div>
          <h3 className="mb-1 text-sm font-medium">{t("findings.references")}</h3>
          <ul className="grid gap-1 text-sm">
            {v.urls.filter(isHttpUrl).map((url) => (
              <li key={url}>
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 break-all text-primary-text hover:underline"
                  aria-label={t("findings.externalLink", { host: new URL(url).host })}
                >
                  {url}
                  <ExternalLink aria-hidden="true" className="size-3.5 flex-none" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {canEdit ? <StateActions data={data} /> : null}
    </div>
  );
}

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

function StateActions({ data }: { data: Detail }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["findings"] }),
      queryClient.invalidateQueries({ queryKey: ["finding", data.id] }),
      queryClient.invalidateQueries({ queryKey: ["overview"] }),
      queryClient.invalidateQueries({ queryKey: ["finding-counts"] }),
    ]);

  const accept = useMutation({
    mutationFn: (body: { reason: string; until: string }) =>
      api(`/findings/${data.id}/accept`, { method: "POST", body }),
    onSuccess: refresh,
    onError: (e) => {
      if (e instanceof ApiError && e.status === 422) {
        setErrors(Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path, x.message])));
      }
    },
  });
  const reopen = useMutation({
    mutationFn: () => api(`/findings/${data.id}/reopen`, { method: "POST" }),
    onSuccess: refresh,
  });

  if (data.state === "accepted") {
    return (
      <div className="grid gap-3 border-t pt-4">
        <p className="text-sm">
          <span className="font-medium">
            {t("findings.acceptedBy", {
              // The stored instant is the first moment after the chosen day; show the day itself.
              date: data.acceptedUntil
                ? formatDate(new Date(new Date(data.acceptedUntil).getTime() - 1))
                : "",
            })}
          </span>
          {data.acceptedReason ? (
            <span className="mt-1 block whitespace-pre-line">{data.acceptedReason}</span>
          ) : null}
        </p>
        <Button
          variant="outline"
          className="justify-self-start"
          disabled={reopen.isPending}
          onClick={() => reopen.mutate()}
        >
          {t("findings.reopen")}
        </Button>
      </div>
    );
  }
  if (data.state !== "open") return null;

  // Calendar days in the browser's zone; never UTC dates (which are a day off around midnight).
  const today = new Date();
  const defaultUntil = localDateInput(addLocalDays(today, 90));
  const minUntil = localDateInput(addLocalDays(today, 1));
  const maxUntil = localDateInput(addLocalDays(today, 365));

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setErrors({});
    // "Until 19 January" means through the whole of that local day, sent as an exact instant.
    accept.mutate({
      reason: String(form.get("reason")).trim(),
      until: endOfLocalDay(String(form.get("until"))).toISOString(),
    });
  }

  return (
    <form className="grid gap-3 border-t pt-4" onSubmit={submit}>
      <div className="grid gap-1.5">
        <label htmlFor="accept-reason" className="text-sm font-medium">
          {t("findings.acceptReason")}
        </label>
        <textarea
          id="accept-reason"
          name="reason"
          required
          minLength={10}
          maxLength={1000}
          rows={3}
          aria-describedby="accept-reason-hint"
          className="rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs"
        />
        <p id="accept-reason-hint" className="text-sm text-muted-foreground">
          {errors.reason ?? t("findings.acceptReasonHint")}
        </p>
      </div>
      <Field
        label={t("findings.acceptUntil")}
        hint={t("findings.acceptUntilHint")}
        error={errors.until}
        name="until"
        type="date"
        required
        defaultValue={defaultUntil}
        min={minUntil}
        max={maxUntil}
      />
      <Button type="submit" variant="outline" className="justify-self-start" disabled={accept.isPending}>
        {t("findings.accept")}
      </Button>
    </form>
  );
}
