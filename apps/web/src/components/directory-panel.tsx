import {
  DIRECTORY_LIMITS,
  DIRECTORY_PRESET_VALUES,
  DIRECTORY_ROLES,
  type DirectoryPreset,
  type DirectoryRole,
  GROUP_MODES,
  type GroupRole,
} from "@garnetops/core/directory";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import {
  type DirectoryServerView,
  type DirectorySettings,
  type DirectoryView,
  directoryQuery,
  type TestView,
} from "../lib/directory.ts";
import { formatDate, formatDateTime, formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { Me } from "../lib/session.ts";
import { toast } from "../lib/toast.ts";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox, Radio } from "./ui/checkbox.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { Field, FormField, FormRow, TextAreaField } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";
import { useStepUp } from "./use-step-up.tsx";

const PRESET_LABELS = {
  "active-directory": "directory.presets.active-directory",
  openldap: "directory.presets.openldap",
  custom: "directory.presets.custom",
} as const satisfies Record<DirectoryPreset, MessageKey>;
const MODE_LABELS = {
  "member-of": "directory.groupModes.member-of",
  nested: "directory.groupModes.nested",
  search: "directory.groupModes.search",
} as const satisfies Record<(typeof GROUP_MODES)[number], MessageKey>;
const MODE_HINTS = {
  "member-of": "directory.groupModeHints.member-of",
  nested: "directory.groupModeHints.nested",
  search: "directory.groupModeHints.search",
} as const satisfies Record<(typeof GROUP_MODES)[number], MessageKey>;

interface FormState {
  enabled: boolean;
  preset: DirectoryPreset;
  /** One URL per line. */
  servers: string;
  tlsTrust: DirectorySettings["tlsTrust"];
  caCertificate: string;
  bindDn: string;
  bindPassword: string;
  userBaseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  uniqueIdAttribute: string;
  groupMode: DirectorySettings["groupMode"];
  groupFilter: string;
  groupRoles: GroupRole[];
  emailVerified: boolean;
  connectTimeoutSeconds: string;
  operationTimeoutSeconds: string;
  sizeLimit: string;
}

const initialState = (settings: DirectorySettings | null): FormState => {
  if (!settings) {
    return {
      enabled: false,
      preset: "active-directory",
      servers: "",
      tlsTrust: "system",
      caCertificate: "",
      bindDn: "",
      bindPassword: "",
      userBaseDn: "",
      ...DIRECTORY_PRESET_VALUES["active-directory"],
      groupRoles: [{ dn: "", role: "member" }],
      emailVerified: false,
      connectTimeoutSeconds: String(DIRECTORY_LIMITS.connectTimeoutSeconds.default),
      operationTimeoutSeconds: String(DIRECTORY_LIMITS.operationTimeoutSeconds.default),
      sizeLimit: String(DIRECTORY_LIMITS.sizeLimit.default),
    };
  }
  return {
    enabled: settings.enabled,
    preset: settings.preset,
    servers: settings.servers.join("\n"),
    tlsTrust: settings.tlsTrust,
    caCertificate: settings.caCertificate,
    bindDn: settings.bindDn,
    bindPassword: "",
    userBaseDn: settings.userBaseDn,
    userFilter: settings.userFilter,
    emailAttribute: settings.emailAttribute,
    nameAttribute: settings.nameAttribute,
    uniqueIdAttribute: settings.uniqueIdAttribute,
    groupMode: settings.groupMode,
    groupFilter: settings.groupFilter,
    groupRoles: settings.groupRoles.length > 0 ? settings.groupRoles : [{ dn: "", role: "member" }],
    emailVerified: settings.emailVerified,
    connectTimeoutSeconds: String(settings.connectTimeoutSeconds),
    operationTimeoutSeconds: String(settings.operationTimeoutSeconds),
    sizeLimit: String(settings.sizeLimit),
  };
};

/** The request body for a form state. The password is sent only when something was typed. */
function bodyOf(form: FormState): Record<string, unknown> {
  return {
    enabled: form.enabled,
    preset: form.preset,
    servers: form.servers
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    tlsTrust: form.tlsTrust,
    caCertificate: form.caCertificate,
    bindDn: form.bindDn,
    ...(form.bindPassword ? { bindPassword: form.bindPassword } : {}),
    userBaseDn: form.userBaseDn,
    userFilter: form.userFilter,
    emailAttribute: form.emailAttribute,
    nameAttribute: form.nameAttribute,
    uniqueIdAttribute: form.uniqueIdAttribute,
    groupMode: form.groupMode,
    groupFilter: form.groupFilter,
    groupRoles: form.groupRoles.filter((g) => g.dn.trim() !== ""),
    emailVerified: form.emailVerified,
    connectTimeoutSeconds: Number(form.connectTimeoutSeconds),
    operationTimeoutSeconds: Number(form.operationTimeoutSeconds),
    sizeLimit: Number(form.sizeLimit),
  };
}

/**
 * Settings → Sign-in (owners): signing in with LDAP or Active Directory (ADR 0020). The service
 * account's password is write-only; the connection test shows what the directory says about a
 * person and never a password.
 */
export function DirectoryPanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const query = useQuery({
    ...directoryQuery,
    // The worker reads certificates a moment after they are asked for.
    refetchInterval: (q) =>
      q.state.data?.servers.some((s) => s.certificate?.status === "pending" && !s.certificate.candidate)
        ? 2500
        : false,
  });
  const [version, setVersion] = useState(0);
  const view = query.data;

  if (me.role !== "owner") {
    return (
      <Card>
        <CardHeader title={t("directory.panelTitle")} description={t("directory.panelDescription")} />
        <div className="px-5 pb-5">
          <Alert tone="info">{t("directory.ownersOnly")}</Alert>
        </div>
      </Card>
    );
  }
  if (!view) {
    return (
      <Card>
        <CardHeader title={t("directory.panelTitle")} description={t("directory.panelDescription")} />
        <QueryStatus query={query} />
      </Card>
    );
  }
  return (
    <>
      <SettingsCard
        key={`${version}:${view.configured}`}
        me={me}
        view={view}
        onSaved={() => setVersion((v) => v + 1)}
      />
      {view.configured && view.settings?.tlsTrust === "pin" ? <CertificatesCard me={me} view={view} /> : null}
      {view.configured ? <TestCard view={view} /> : null}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Settings                                                                    */
/* -------------------------------------------------------------------------- */

function SettingsCard({ me, view, onSaved }: { me: Me; view: DirectoryView; onSaved: () => void }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [form, setForm] = useState<FormState>(() => initialState(view.settings));
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const settings = view.settings;
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => api<DirectoryView>("/directory", { method: "PUT", body }),
    onMutate: () => {
      setError(null);
      setFieldErrors({});
    },
    onSuccess: async (result) => {
      toast.success(t("directory.saved"));
      if (result.switchedOff) toast.info(t("directory.switchedOff"));
      // A pinned server's certificate is read as soon as it is known, so there is something to confirm.
      if (result.settings?.tlsTrust === "pin" && result.servers.some((s) => !s.certificate?.pin)) {
        await api("/directory/certificates/scan", { method: "POST", body: {} }).catch(() => {});
      }
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      onSaved();
    },
    onError: (e, body) => {
      if (stepUp.handled(e, () => save.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        const errors: Record<string, string> = {};
        for (const item of e.problem?.errors ?? []) errors[item.path] = item.message;
        setFieldErrors(errors);
        return setError(t("directory.errorInvalid"));
      }
      if (e instanceof ApiError && e.code === "not-tested") return setError(t("directory.errorNotTested"));
      if (e instanceof ApiError && e.status === 429) return setError(t("errors.tooManyAttempts"));
      setError(t("errors.actionFailed"));
    },
  });

  const errorOf = (...paths: string[]) => {
    const found = paths.map((p) => fieldErrors[p]).find(Boolean);
    if (!found) return null;
    const key = `directory.fieldError.${found}`;
    return i18n.exists(key) ? t(key as never) : t("directory.errorInvalid");
  };
  const serverError = () => {
    const path = Object.keys(fieldErrors).find((p) => p === "servers" || p.startsWith("servers."));
    return path ? errorOf(path) : null;
  };
  const groupError = () => {
    const path = Object.keys(fieldErrors).find((p) => p === "groupRoles" || p.startsWith("groupRoles."));
    return path ? errorOf(path) : null;
  };

  function applyPreset(preset: DirectoryPreset) {
    const values = DIRECTORY_PRESET_VALUES[preset];
    setForm((f) => ({
      ...f,
      preset,
      // "Other" keeps what is typed; the two known types fill in their usual settings.
      ...(preset === "custom" ? {} : values),
    }));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    save.mutate(bodyOf(form));
  }

  const tested = view.testedAt !== null;

  return (
    <Card>
      <CardHeader
        title={t("directory.panelTitle")}
        description={t("directory.panelDescription")}
        actions={
          view.configured ? (
            <Badge tone={settings?.enabled ? "info" : "neutral"}>
              {settings?.enabled ? t("directory.statusOn") : t("directory.statusOff")}
            </Badge>
          ) : null
        }
      />
      <form className="grid gap-5 px-5 pt-1 pb-5" onSubmit={submit} noValidate data-testid="directory-form">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {view.bindBlockedUntil ? <Alert tone="error">{t("directory.blocked")}</Alert> : null}
        {view.configured && view.accounts > 0 ? (
          <p className="text-sm text-muted-foreground">{t("directory.accounts", { count: view.accounts })}</p>
        ) : null}

        <FormField id="directory-preset" label={t("directory.preset")} hint={t("directory.presetHint")}>
          {(control) => (
            <Select
              {...control}
              value={form.preset}
              onChange={(e) => applyPreset(e.target.value as DirectoryPreset)}
              className="max-w-80"
            >
              {(Object.keys(PRESET_LABELS) as DirectoryPreset[]).map((p) => (
                <option key={p} value={p}>
                  {t(PRESET_LABELS[p])}
                </option>
              ))}
            </Select>
          )}
        </FormField>

        <fieldset className="grid gap-4 border-t pt-4">
          <legend className="mb-1 font-medium">{t("directory.connectionTitle")}</legend>
          <TextAreaField
            id="directory-servers"
            label={t("directory.servers")}
            hint={t("directory.serversHint")}
            value={form.servers}
            rows={3}
            onChange={(e) => set("servers", e.target.value)}
            placeholder={"ldaps://dc1.example.lan\nldaps://dc2.example.lan"}
            error={serverError()}
            autoCapitalize="off"
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">{t("directory.trust")}</legend>
            {(["system", "ca", "pin"] as const).map((trust) => (
              <div key={trust} className="flex items-start gap-2.5">
                <Radio
                  id={`directory-trust-${trust}`}
                  name="tlsTrust"
                  value={trust}
                  checked={form.tlsTrust === trust}
                  onChange={() => set("tlsTrust", trust)}
                  aria-describedby={`directory-trust-${trust}-hint`}
                  className="mt-1"
                />
                <div>
                  <label htmlFor={`directory-trust-${trust}`}>{t(`directory.trusts.${trust}`)}</label>
                  <span id={`directory-trust-${trust}-hint`} className="block text-sm text-muted-foreground">
                    {t(`directory.trustHints.${trust}`)}
                  </span>
                </div>
              </div>
            ))}
          </fieldset>
          {form.tlsTrust === "ca" ? (
            <TextAreaField
              id="directory-ca"
              label={t("directory.caCertificate")}
              hint={t("directory.caCertificateHint")}
              value={form.caCertificate}
              rows={5}
              onChange={(e) => set("caCertificate", e.target.value)}
              placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
              error={errorOf("caCertificate")}
              spellCheck={false}
              className="font-mono text-[13px]"
            />
          ) : null}
          {form.tlsTrust === "pin" ? (
            <p className="text-sm text-muted-foreground">{t("directory.pinNote")}</p>
          ) : null}
        </fieldset>

        <fieldset className="grid gap-4 border-t pt-4">
          <legend className="mb-1 font-medium">{t("directory.serviceTitle")}</legend>
          <p className="-mt-2 text-sm text-muted-foreground">{t("directory.serviceHint")}</p>
          <Field
            id="directory-bind-dn"
            label={t("directory.bindDn")}
            value={form.bindDn}
            onChange={(e) => set("bindDn", e.target.value)}
            placeholder="CN=svc-garnetops,OU=Service,DC=example,DC=lan"
            error={errorOf("bindDn")}
            autoCapitalize="off"
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            id="directory-bind-password"
            label={t("directory.bindPassword")}
            hint={
              settings?.bindPasswordSet ? t("directory.bindPasswordKeep") : t("directory.bindPasswordHint")
            }
            type="password"
            value={form.bindPassword}
            onChange={(e) => set("bindPassword", e.target.value)}
            error={errorOf("bindPassword")}
            autoComplete="new-password"
            maxLength={DIRECTORY_LIMITS.bindPasswordMax}
          />
        </fieldset>

        <fieldset className="grid gap-4 border-t pt-4">
          <legend className="mb-1 font-medium">{t("directory.usersTitle")}</legend>
          <Field
            id="directory-base"
            label={t("directory.userBaseDn")}
            hint={t("directory.userBaseDnHint")}
            value={form.userBaseDn}
            onChange={(e) => set("userBaseDn", e.target.value)}
            placeholder="OU=Users,DC=example,DC=lan"
            error={errorOf("userBaseDn")}
            autoCapitalize="off"
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <Field
            id="directory-filter"
            label={t("directory.userFilter")}
            hint={t("directory.userFilterHint")}
            value={form.userFilter}
            onChange={(e) => set("userFilter", e.target.value)}
            error={errorOf("userFilter")}
            autoCapitalize="off"
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-sm"
          />
          <FormRow columns={3} from="lg">
            <Field
              id="directory-attr-email"
              label={t("directory.emailAttribute")}
              value={form.emailAttribute}
              onChange={(e) => set("emailAttribute", e.target.value)}
              error={errorOf("emailAttribute")}
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono text-sm"
            />
            <Field
              id="directory-attr-name"
              label={t("directory.nameAttribute")}
              value={form.nameAttribute}
              onChange={(e) => set("nameAttribute", e.target.value)}
              error={errorOf("nameAttribute")}
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono text-sm"
            />
            <Field
              id="directory-attr-id"
              label={t("directory.uniqueIdAttribute")}
              hint={t("directory.uniqueIdAttributeHint")}
              value={form.uniqueIdAttribute}
              onChange={(e) => set("uniqueIdAttribute", e.target.value)}
              error={errorOf("uniqueIdAttribute")}
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono text-sm"
            />
          </FormRow>
        </fieldset>

        <fieldset className="grid gap-4 border-t pt-4">
          <legend className="mb-1 font-medium">{t("directory.groupsTitle")}</legend>
          <p className="-mt-2 text-sm text-muted-foreground">{t("directory.groupsHint")}</p>
          <FormField
            id="directory-group-mode"
            label={t("directory.groupMode")}
            hint={t(MODE_HINTS[form.groupMode])}
          >
            {(control) => (
              <Select
                {...control}
                value={form.groupMode}
                onChange={(e) => set("groupMode", e.target.value as FormState["groupMode"])}
                className="max-w-96"
              >
                {GROUP_MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {t(MODE_LABELS[mode])}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
          {form.groupMode === "search" ? (
            <Field
              id="directory-group-filter"
              label={t("directory.groupFilter")}
              hint={t("directory.groupFilterHint")}
              value={form.groupFilter}
              onChange={(e) => set("groupFilter", e.target.value)}
              error={errorOf("groupFilter")}
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono text-sm"
            />
          ) : null}
          <GroupRoles
            rows={form.groupRoles}
            onChange={(rows) => set("groupRoles", rows)}
            error={groupError()}
            invalid={Object.keys(fieldErrors)
              .filter((p) => p.startsWith("groupRoles."))
              .map((p) => Number(p.split(".")[1]))}
          />
        </fieldset>

        <fieldset className="grid gap-4 border-t pt-4">
          <legend className="mb-1 font-medium">{t("directory.optionsTitle")}</legend>
          <label className="flex items-start gap-2.5">
            <Checkbox
              className="mt-1"
              checked={form.emailVerified}
              onChange={(e) => set("emailVerified", e.target.checked)}
            />
            <span>
              {t("directory.emailVerified")}
              <span className="block text-sm text-muted-foreground">{t("directory.emailVerifiedHint")}</span>
            </span>
          </label>
          <details className="rounded-md border px-3 py-2">
            <summary className="cursor-pointer text-sm font-medium">{t("directory.advanced")}</summary>
            <div className="mt-3">
              <FormRow columns={3} from="lg">
                <Field
                  label={t("directory.connectTimeout")}
                  type="number"
                  min={DIRECTORY_LIMITS.connectTimeoutSeconds.min}
                  max={DIRECTORY_LIMITS.connectTimeoutSeconds.max}
                  value={form.connectTimeoutSeconds}
                  onChange={(e) => set("connectTimeoutSeconds", e.target.value)}
                  error={errorOf("connectTimeoutSeconds")}
                />
                <Field
                  label={t("directory.operationTimeout")}
                  type="number"
                  min={DIRECTORY_LIMITS.operationTimeoutSeconds.min}
                  max={DIRECTORY_LIMITS.operationTimeoutSeconds.max}
                  value={form.operationTimeoutSeconds}
                  onChange={(e) => set("operationTimeoutSeconds", e.target.value)}
                  error={errorOf("operationTimeoutSeconds")}
                />
                <Field
                  label={t("directory.sizeLimit")}
                  hint={t("directory.sizeLimitHint")}
                  type="number"
                  min={DIRECTORY_LIMITS.sizeLimit.min}
                  max={DIRECTORY_LIMITS.sizeLimit.max}
                  value={form.sizeLimit}
                  onChange={(e) => set("sizeLimit", e.target.value)}
                  error={errorOf("sizeLimit")}
                />
              </FormRow>
            </div>
          </details>
        </fieldset>

        <div className="grid gap-3 border-t pt-4">
          <label className="flex items-start gap-2.5">
            <Checkbox
              className="mt-1"
              checked={form.enabled}
              disabled={!tested && !form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
              data-testid="directory-enabled"
            />
            <span>
              {t("directory.enable")}
              <span className="block text-sm text-muted-foreground">
                {tested && view.testedAt
                  ? t("directory.enableTested", { when: formatRelative(view.testedAt) })
                  : t("directory.enableUntested")}
              </span>
            </span>
          </label>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? t("common.loading") : t("directory.save")}
            </Button>
            {view.testedAt ? (
              <span className="text-sm text-muted-foreground">
                {t("directory.lastTest", { when: formatDateTime(view.testedAt) })}
              </span>
            ) : null}
          </div>
        </div>
      </form>
      {stepUp.dialog}
    </Card>
  );
}

function GroupRoles({
  rows,
  onChange,
  error,
  invalid,
}: {
  rows: GroupRole[];
  onChange: (rows: GroupRole[]) => void;
  error: string | null;
  invalid: number[];
}) {
  const { t } = useTranslation();
  const update = (index: number, patch: Partial<GroupRole>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  return (
    <div className="grid gap-2">
      <span className="text-sm font-medium">{t("directory.groupRoles")}</span>
      <p className="text-sm text-muted-foreground">{t("directory.groupRolesHint")}</p>
      {error ? <p className="text-sm text-destructive-text">{error}</p> : null}
      <ul className="grid gap-2">
        {rows.map((row, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: rows have no identity of their own and are only edited in place
          <li key={index} className="flex flex-wrap items-center gap-2" data-testid="group-role">
            <input
              aria-label={t("directory.groupDn", { number: index + 1 })}
              aria-invalid={invalid.includes(index) ? true : undefined}
              value={row.dn}
              onChange={(e) => update(index, { dn: e.target.value })}
              placeholder="CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan"
              autoCapitalize="off"
              autoComplete="off"
              spellCheck={false}
              className="h-10 min-w-0 flex-[1_1_16rem] rounded-md border border-input bg-card px-3 font-mono text-sm shadow-xs aria-invalid:border-destructive"
            />
            <Select
              aria-label={t("directory.groupRole", { number: index + 1 })}
              value={row.role}
              onChange={(e) => update(index, { role: e.target.value as DirectoryRole })}
              className="w-36 flex-none"
            >
              {DIRECTORY_ROLES.map((role) => (
                <option key={role} value={role}>
                  {t(`team.roles.${role}`)}
                </option>
              ))}
            </Select>
            <Button
              variant="ghost"
              className="h-9 px-2.5"
              disabled={rows.length <= 1}
              aria-label={t("directory.removeGroup", { number: index + 1 })}
              onClick={() => onChange(rows.filter((_, i) => i !== index))}
            >
              <Trash2 aria-hidden="true" className="size-4" />
            </Button>
          </li>
        ))}
      </ul>
      <div>
        <Button
          variant="outline"
          className="h-9"
          disabled={rows.length >= DIRECTORY_LIMITS.maxGroupRoles}
          onClick={() => onChange([...rows, { dn: "", role: "member" }])}
        >
          <Plus aria-hidden="true" className="size-4" />
          {t("directory.addGroup")}
        </Button>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Certificates                                                                */
/* -------------------------------------------------------------------------- */

function Facts({
  label,
  facts,
}: {
  label: string;
  facts: { fingerprint: string; subject: string; issuer: string; validFrom: string; validTo: string };
}) {
  const { t } = useTranslation();
  return (
    <section aria-label={label} className="grid gap-2 rounded-md border px-3 py-3">
      <h3 className="text-sm font-medium">{label}</h3>
      <code
        className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all"
        data-testid="fingerprint"
      >
        {facts.fingerprint}
      </code>
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("proxmox.certSubject")}</dt>
        <dd className="font-mono break-all">{facts.subject || "–"}</dd>
        <dt className="text-muted-foreground">{t("proxmox.certIssuer")}</dt>
        <dd className="font-mono break-all">{facts.issuer || "–"}</dd>
        <dt className="text-muted-foreground">{t("proxmox.certValid")}</dt>
        <dd>
          {formatDate(facts.validFrom)} – {formatDate(facts.validTo)}
          {new Date(facts.validTo) < new Date() ? (
            <span className="ml-2 text-destructive-text">{t("proxmox.certExpired")}</span>
          ) : null}
        </dd>
      </dl>
    </section>
  );
}

function CertificatesCard({ me, view }: { me: Me; view: DirectoryView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [reviewing, setReviewing] = useState<string | null>(null);
  const scan = useMutation({
    mutationFn: (url: string | null) =>
      api<DirectoryView>("/directory/certificates/scan", { method: "POST", body: url ? { url } : {} }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["directory"] }),
  });
  const server = view.servers.find((s) => s.url === reviewing) ?? null;

  return (
    <Card>
      <CardHeader
        title={t("directory.certificatesTitle")}
        description={t("directory.certificatesDescription")}
        actions={
          <Button variant="outline" disabled={scan.isPending} onClick={() => scan.mutate(null)}>
            <Fingerprint aria-hidden="true" className="size-4" />
            {scan.isPending ? t("common.loading") : t("directory.readCertificates")}
          </Button>
        }
      />
      {scan.isError ? (
        <div className="px-5 pb-3">
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        </div>
      ) : null}
      <ul>
        {view.servers.map((s) => (
          <li key={s.url} className="grid gap-1 border-t px-5 py-3" data-testid={`dir-server-${s.url}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm break-all">{s.url}</span>
              <Badge tone="neutral">{t(`directory.transport.${s.transport}`)}</Badge>
              <CertificateBadge server={s} />
              {s.certificate?.candidate ? (
                <Button className="ml-auto h-9" onClick={() => setReviewing(s.url)}>
                  <Fingerprint aria-hidden="true" className="size-4" />
                  {t(
                    s.certificate.status === "changed"
                      ? "directory.reviewChange"
                      : "directory.confirmCertificate",
                  )}
                </Button>
              ) : null}
            </div>
            {s.certificate?.pin ? (
              <div className="font-mono text-[13px] break-all text-muted-foreground">
                {s.certificate.pin.fingerprint}
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">
                {s.certificate?.candidate
                  ? t("directory.waitingForConfirmation")
                  : t("directory.noCertificateYet")}
              </div>
            )}
          </li>
        ))}
      </ul>
      {server ? <CertificateDialog me={me} server={server} onClose={() => setReviewing(null)} /> : null}
    </Card>
  );
}

function CertificateBadge({ server }: { server: DirectoryServerView }) {
  const { t } = useTranslation();
  const status = server.certificate?.status;
  if (!status) return null;
  return (
    <Badge tone={status === "changed" ? "critical" : status === "pending" ? "medium" : "neutral"}>
      {t(`directory.certStatus.${status}`)}
    </Badge>
  );
}

/**
 * Confirming a certificate (ADR 0020), as for Proxmox and Wazuh: the owner compares the
 * fingerprint GarnetOps read with the one the directory server shows, and the API pins exactly the
 * fingerprint that was shown. A change is a security event, so the dialog says so and shows both.
 */
function CertificateDialog({
  me,
  server,
  onClose,
}: {
  me: Me;
  server: DirectoryServerView;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [error, setError] = useState<string | null>(null);
  const candidate = server.certificate?.candidate ?? null;
  const pin = server.certificate?.pin ?? null;
  const changed = server.certificate?.status === "changed";

  const confirm = useMutation({
    mutationFn: (fingerprint: string) =>
      api<DirectoryView>("/directory/certificates/confirm", {
        method: "POST",
        body: { url: server.url, fingerprint },
      }),
    onMutate: () => setError(null),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      onClose();
    },
    onError: async (e, fingerprint) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await queryClient.invalidateQueries({ queryKey: ["directory"] });
        return setError(t("directory.certMismatch"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  return (
    <>
      <Dialog
        open
        onClose={onClose}
        title={changed ? t("directory.certChangedTitle") : t("directory.certConfirmTitle")}
        description={server.url}
      >
        <div className="grid gap-4">
          {error ? <Alert tone="error">{error}</Alert> : null}
          {changed ? <Alert tone="error">{t("directory.certChangedWarning")}</Alert> : null}
          {candidate ? (
            <Facts
              label={changed ? t("directory.certNew") : t("directory.certPresented")}
              facts={candidate}
            />
          ) : null}
          {changed && pin ? <Facts label={t("directory.certPinned")} facts={pin} /> : null}
          <p className="text-sm text-muted-foreground">{t("directory.certCompare")}</p>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            <Button
              disabled={!candidate || confirm.isPending}
              onClick={() => candidate && confirm.mutate(candidate.fingerprint)}
            >
              {confirm.isPending ? t("common.loading") : t("directory.certConfirm")}
            </Button>
          </DialogFooter>
        </div>
      </Dialog>
      {stepUp.dialog}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Test                                                                        */
/* -------------------------------------------------------------------------- */

function useProblemText() {
  const { t, i18n } = useTranslation();
  return (problem: string | undefined, detail?: string) => {
    if (!problem) return "";
    const key = `directory.problem.${problem}`;
    const text = i18n.exists(key) ? t(key as never) : t("directory.problem.internal");
    return detail ? `${text} (${detail})` : text;
  };
}

function TestCard({ view }: { view: DirectoryView }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const problemText = useProblemText();
  const [username, setUsername] = useState("");
  const [error, setError] = useState<string | null>(null);
  const run = useMutation({
    mutationFn: (name: string) =>
      api<{ result: TestView }>("/directory/test", { method: "POST", body: name ? { username: name } : {} }),
    onMutate: () => setError(null),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["directory"] }),
    onError: (e) =>
      setError(
        e instanceof ApiError && e.status === 429
          ? t("errors.tooManyAttempts")
          : e instanceof ApiError && e.status === 422
            ? t("directory.fieldError.username_invalid")
            : t("errors.actionFailed"),
      ),
  });
  const result = run.data?.result ?? null;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    run.mutate(username.trim());
  }

  return (
    <Card>
      <CardHeader title={t("directory.testTitle")} description={t("directory.testDescription")} />
      <form className="grid gap-4 px-5 pb-5" onSubmit={submit} noValidate>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          id="directory-test-user"
          label={t("directory.testUser")}
          hint={t("directory.testUserHint")}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          maxLength={DIRECTORY_LIMITS.usernameMax}
          autoCapitalize="off"
          autoComplete="off"
          spellCheck={false}
          className="max-w-96"
        />
        <div>
          <Button type="submit" variant="outline" disabled={run.isPending} data-testid="directory-test">
            {run.isPending ? t("directory.testing") : t("directory.testRun")}
          </Button>
        </div>
        {view.settings?.enabled === false ? (
          <p className="text-sm text-muted-foreground">{t("directory.testSaved")}</p>
        ) : null}
        {result ? (
          <div className="grid gap-4" data-testid="directory-test-result" aria-live="polite">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={result.ok ? "neutral" : "critical"}>
                {result.ok ? t("directory.testOk") : t("directory.testFailed")}
              </Badge>
              {!result.ok && result.problem ? (
                <span className="text-sm text-destructive-text">{problemText(result.problem)}</span>
              ) : null}
              <span className="ml-auto text-sm text-muted-foreground">
                {t("directory.testLatency", { ms: result.latencyMs })}
              </span>
            </div>
            <ul className="grid gap-1.5">
              {result.servers.map((s) => (
                <li key={s.url} className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono break-all">{s.url}</span>
                  <Badge tone="neutral">{t(`directory.transport.${s.transport}`)}</Badge>
                  <Badge tone={s.ok ? "neutral" : "critical"}>
                    {s.ok ? t("directory.serverOk") : t("directory.serverFailed")}
                  </Badge>
                  {!s.ok ? (
                    <span className="text-destructive-text">{problemText(s.problem, s.detail)}</span>
                  ) : null}
                </li>
              ))}
            </ul>
            {result.user ? (
              <section
                aria-label={t("directory.testPerson")}
                className="grid gap-2 rounded-md border px-3 py-3"
              >
                <h3 className="text-sm font-medium">{t("directory.testPerson")}</h3>
                <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">{t("directory.testDn")}</dt>
                  <dd className="font-mono break-all">{result.user.dn}</dd>
                  <dt className="text-muted-foreground">{t("directory.testName")}</dt>
                  <dd>{result.user.name ?? "–"}</dd>
                  <dt className="text-muted-foreground">{t("directory.testEmail")}</dt>
                  <dd className="break-all">{result.user.email ?? t("directory.testNoEmail")}</dd>
                  <dt className="text-muted-foreground">{t("directory.testUniqueId")}</dt>
                  <dd className="font-mono break-all">{result.user.uniqueId}</dd>
                  <dt className="text-muted-foreground">{t("directory.testGroups")}</dt>
                  <dd className="font-mono break-all">
                    {result.user.groups.length > 0
                      ? result.user.groups.join("; ")
                      : t("directory.testNoGroups")}
                  </dd>
                  <dt className="text-muted-foreground">{t("directory.testRole")}</dt>
                  <dd>
                    {result.user.role ? (
                      <Badge tone="neutral">{t(`team.roles.${result.user.role}`)}</Badge>
                    ) : (
                      <span className="text-destructive-text">{t("directory.testNoRole")}</span>
                    )}
                  </dd>
                </dl>
                {!result.user.email ? <Alert tone="error">{t("directory.testNoEmailWarning")}</Alert> : null}
              </section>
            ) : null}
            {result.groups && result.groups.length > 0 ? (
              <section aria-label={t("directory.testGroupsTitle")} className="grid gap-1.5">
                <h3 className="text-sm font-medium">{t("directory.testGroupsTitle")}</h3>
                <ul className="grid gap-1 text-sm">
                  {result.groups.map((g) => (
                    <li key={g.dn} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono break-all">{g.dn}</span>
                      <Badge tone={g.exists ? "neutral" : "medium"}>
                        {g.exists ? t("directory.groupExists") : t("directory.groupMissing")}
                      </Badge>
                      {result.user && g.exists ? (
                        <Badge tone="neutral">
                          {g.member ? t("directory.groupMember") : t("directory.groupNotMember")}
                        </Badge>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        ) : null}
      </form>
    </Card>
  );
}
