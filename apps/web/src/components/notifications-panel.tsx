import { LANGUAGE_NAMES, LANGUAGES, type Language } from "@garnetops/i18n";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Plus, Send, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { formatRelative } from "../lib/format.ts";
import type { Me } from "../lib/session.ts";
import { toast } from "../lib/toast.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox, Radio } from "./ui/checkbox.tsx";
import { ConfirmDialog } from "./ui/confirm-dialog.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field, FormRow } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { useStepUp } from "./use-step-up.tsx";

const EVENTS = ["finding.new_critical", "gate.blocked", "scan.failed"] as const;
const KINDS = ["webhook", "smtp", "graph"] as const;
const FORMATS = ["discord", "slack", "generic"] as const;
type Kind = (typeof KINDS)[number];
type Event = (typeof EVENTS)[number];

interface Channel {
  id: string;
  name: string;
  kind: Kind;
  format: (typeof FORMATS)[number] | null;
  language: Language;
  events: Event[];
  enabled: boolean;
  config: Record<string, unknown>;
  lastDelivery: { status: "sent" | "failed"; error: string | null; event: string; createdAt: string } | null;
}

/** Message keys cannot contain dots (i18next reads them as nesting). */
const eventKey = (event: Event) =>
  event.replace(".", "_") as "finding_new_critical" | "gate_blocked" | "scan_failed";

/** Where a channel sends to, without anything secret (ADR 0010). */
function target(channel: Channel): string {
  const c = channel.config;
  if (channel.kind === "webhook") return String(c.host ?? "");
  const to = Array.isArray(c.to) ? c.to.join(", ") : "";
  return channel.kind === "smtp" ? `${c.host}:${c.port} → ${to}` : `${c.from} → ${to}`;
}

/** Settings → Notifications (owners and admins). */
export function NotificationsPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const channels = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () => api<Channel[]>("/notifications/channels"),
    // A test result arrives a moment after it was queued.
    refetchInterval: 5000,
  });
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<Channel | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
  const patch = useMutation({
    mutationFn: (input: { id: string; body: Partial<Pick<Channel, "enabled" | "events">> }) =>
      api(`/notifications/channels/${input.id}`, { method: "PATCH", body: input.body }),
    // The switch moves at once; a failure puts it back when the list reloads.
    onMutate: (input) =>
      queryClient.setQueryData<Channel[]>(["notification-channels"], (list) =>
        list?.map((x) => (x.id === input.id ? { ...x, ...input.body } : x)),
      ),
    onSettled: refresh,
  });
  const test = useMutation({
    mutationFn: (id: string) => api(`/notifications/channels/${id}/test`, { method: "POST" }),
    onSuccess: () => toast.success(t("settings.testQueued")),
    onError: () => toast.error(t("errors.actionFailed")),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/notifications/channels/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setDeleting(null);
      await refresh();
    },
  });

  return (
    <Card>
      <CardHeader
        title={t("settings.notificationsTitle")}
        description={t("settings.notificationsDescription")}
        actions={
          <Button variant="outline" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" className="size-4" />
            {t("settings.addChannel")}
          </Button>
        }
      />
      <p className="px-5 pb-3 text-sm text-muted-foreground">
        {t("settings.notificationsRelation")}{" "}
        <Link
          to="/account"
          search={{ section: "notifications" }}
          className="font-medium text-primary-text underline underline-offset-4"
        >
          {t("settings.notificationsPersonalLink")}
        </Link>
      </p>
      <QueryStatus query={channels} />
      {patch.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      {channels.data && channels.data.length === 0 ? (
        <p className="px-5 pb-5 text-muted-foreground">{t("settings.notificationsEmpty")}</p>
      ) : null}
      <ul>
        {channels.data?.map((channel) => (
          <li key={channel.id} className="grid gap-2 border-t px-5 py-3">
            <div className="flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-[1_1_16rem]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{channel.name}</span>
                  <Badge tone="neutral">
                    {channel.kind === "webhook" && channel.format
                      ? t(`settings.format.${channel.format}`)
                      : t(`settings.kind.${channel.kind}`)}
                  </Badge>
                </div>
                <div className="text-sm break-all text-muted-foreground">{target(channel)}</div>
                <div className="text-[13px] text-muted-foreground">
                  {channel.events.map((e) => t(`settings.event.${eventKey(e)}`)).join(" · ")}
                </div>
                <div className="mt-1 text-[13px]">
                  {channel.lastDelivery ? (
                    channel.lastDelivery.status === "sent" ? (
                      <span className="text-muted-foreground">
                        {t("settings.lastSent", { when: formatRelative(channel.lastDelivery.createdAt) })}
                      </span>
                    ) : (
                      <span className="text-destructive-text">
                        {t("settings.lastFailed", {
                          when: formatRelative(channel.lastDelivery.createdAt),
                          reason: channel.lastDelivery.error ?? "",
                        })}
                      </span>
                    )
                  ) : (
                    <span className="text-muted-foreground">{t("settings.neverSent")}</span>
                  )}
                </div>
              </div>
              <EnabledSwitch
                key={`${channel.id}-${channel.enabled}`}
                label={`${t("settings.channelEnabled")}: ${channel.name}`}
                text={t("settings.channelEnabled")}
                enabled={channel.enabled}
                onChange={(enabled) => patch.mutate({ id: channel.id, body: { enabled } })}
              />
              <Button
                variant="outline"
                className="h-9"
                disabled={test.isPending}
                onClick={() => test.mutate(channel.id)}
              >
                <Send aria-hidden="true" className="size-4" />
                {t("settings.sendTest")}
              </Button>
              <Button
                variant="ghost"
                className="h-9 px-2.5"
                aria-label={`${t("settings.deleteChannel")}: ${channel.name}`}
                onClick={() => setDeleting(channel)}
              >
                <Trash2 aria-hidden="true" className="size-4" />
              </Button>
            </div>
          </li>
        ))}
      </ul>
      <AddChannelDialog me={me} open={adding} onClose={() => setAdding(false)} />
      <ConfirmDialog
        open={deleting !== null}
        title={t("settings.deleteChannelTitle", { name: deleting?.name ?? "" })}
        description={t("settings.deleteChannelDescription")}
        confirmLabel={t("settings.deleteChannel")}
        pending={remove.isPending}
        error={remove.isError ? t("errors.actionFailed") : null}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      />
    </Card>
  );
}

/** On/off for a channel: moves at once, the list reload confirms it. */
function EnabledSwitch({
  label,
  text,
  enabled,
  onChange,
}: {
  label: string;
  text: string;
  enabled: boolean;
  onChange: (enabled: boolean) => void;
}) {
  const [on, setOn] = useState(enabled);
  return (
    <label className="flex items-center gap-2 text-sm">
      <Checkbox
        checked={on}
        onChange={(e) => {
          setOn(e.target.checked);
          onChange(e.target.checked);
        }}
        aria-label={label}
      />
      {text}
    </label>
  );
}

function AddChannelDialog({ me, open, onClose }: { me: Me; open: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [kind, setKind] = useState<Kind>("webhook");
  const [events, setEvents] = useState<Event[]>(["finding.new_critical", "gate.blocked"]);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/notifications/channels", { method: "POST", body }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      close();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => create.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        setFieldErrors(
          Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message])),
        );
        return setError(t("repositories.errorInvalid"));
      }
      setError(t("errors.actionFailed"));
    },
  });
  function close() {
    setKind("webhook");
    setError(null);
    setFieldErrors({});
    onClose();
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    const s = (k: string) => String(f.get(k) ?? "").trim();
    const list = (k: string) =>
      s(k)
        .split(/[\s,;]+/)
        .filter(Boolean);
    const base = { name: s("name"), events, language: s("language") || "en", kind };
    const body =
      kind === "webhook"
        ? { ...base, format: s("format"), url: s("url") }
        : kind === "smtp"
          ? {
              ...base,
              host: s("host"),
              port: Number(s("port")),
              security: s("security"),
              username: s("username") || undefined,
              password: String(f.get("password") ?? "") || undefined,
              from: s("from"),
              to: list("to"),
            }
          : {
              ...base,
              tenantId: s("tenantId"),
              clientId: s("clientId"),
              clientSecret: String(f.get("clientSecret") ?? ""),
              from: s("from"),
              to: list("to"),
            };
    create.mutate(body);
  }
  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        title={t("settings.addChannelTitle")}
        description={t("settings.addChannelDescription")}
      >
        <form className="grid gap-4" onSubmit={submit}>
          {error ? <Alert tone="error">{error}</Alert> : null}
          <Field
            label={t("settings.channelName")}
            name="name"
            required
            maxLength={80}
            error={fieldErrors.name}
          />
          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-sm font-medium">{t("settings.channelKind")}</legend>
            {KINDS.map((k) => (
              <label key={k} className="flex items-center gap-2.5">
                <Radio name="kind" value={k} checked={kind === k} onChange={() => setKind(k)} />
                {t(`settings.kind.${k}`)}
              </label>
            ))}
          </fieldset>
          {kind === "webhook" ? (
            <>
              <label className="grid gap-1.5">
                <span className="text-sm font-medium">{t("settings.webhookFormat")}</span>
                <Select name="format" defaultValue="discord">
                  {FORMATS.map((format) => (
                    <option key={format} value={format}>
                      {t(`settings.format.${format}`)}
                    </option>
                  ))}
                </Select>
              </label>
              <Field
                label={t("settings.webhookUrl")}
                hint={t("settings.webhookUrlHint")}
                name="url"
                type="url"
                required
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-sm"
                error={fieldErrors.url}
              />
            </>
          ) : null}
          {kind === "smtp" ? (
            <>
              <FormRow columns={["1fr", "8rem"]} from="md">
                <Field
                  label={t("settings.smtpHost")}
                  name="host"
                  required
                  spellCheck={false}
                  error={fieldErrors.host}
                />
                <Field
                  label={t("settings.smtpPort")}
                  name="port"
                  type="number"
                  required
                  defaultValue={587}
                  min={1}
                  max={65535}
                />
              </FormRow>
              <label className="grid gap-1.5">
                <span className="text-sm font-medium">{t("settings.smtpSecurity")}</span>
                <Select name="security" defaultValue="starttls">
                  <option value="starttls">{t("settings.smtpSecurityStartTls")}</option>
                  <option value="tls">{t("settings.smtpSecurityTls")}</option>
                </Select>
              </label>
              <Field label={t("settings.smtpUser")} name="username" autoComplete="off" />
              <Field
                label={t("settings.smtpPassword")}
                name="password"
                type="password"
                autoComplete="new-password"
                error={fieldErrors.password}
              />
            </>
          ) : null}
          {kind === "graph" ? (
            <>
              <Alert tone="info">{t("settings.graphHint")}</Alert>
              <Field
                label={t("settings.graphTenant")}
                name="tenantId"
                required
                spellCheck={false}
                error={fieldErrors.tenantId}
              />
              <Field
                label={t("settings.graphClient")}
                name="clientId"
                required
                spellCheck={false}
                error={fieldErrors.clientId}
              />
              <Field
                label={t("settings.graphSecret")}
                name="clientSecret"
                type="password"
                required
                autoComplete="new-password"
              />
            </>
          ) : null}
          {kind !== "webhook" ? (
            <>
              <Field
                label={t("settings.mailFrom")}
                name="from"
                type="email"
                required
                error={fieldErrors.from}
              />
              <Field
                label={t("settings.mailTo")}
                hint={t("settings.mailToHint")}
                name="to"
                required
                error={fieldErrors.to}
              />
            </>
          ) : null}
          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-sm font-medium">{t("settings.channelEvents")}</legend>
            {EVENTS.map((e) => (
              <label key={e} className="flex items-center gap-2.5">
                <Checkbox
                  checked={events.includes(e)}
                  onChange={(x) =>
                    setEvents((list) => (x.target.checked ? [...list, e] : list.filter((v) => v !== e)))
                  }
                />
                {t(`settings.event.${eventKey(e)}`)}
              </label>
            ))}
          </fieldset>
          <label className="grid gap-1.5">
            <span className="text-sm font-medium">{t("settings.channelLanguage")}</span>
            <Select name="language" defaultValue={LANGUAGES.find((l) => l === i18n.language) ?? "en"}>
              {LANGUAGES.map((l) => (
                <option key={l} value={l}>
                  {LANGUAGE_NAMES[l]}
                </option>
              ))}
            </Select>
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={close}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={create.isPending || events.length === 0}>
              {create.isPending ? t("common.loading") : t("settings.channelSave")}
            </Button>
          </DialogFooter>
        </form>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
