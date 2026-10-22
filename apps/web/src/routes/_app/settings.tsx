import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Settings } from "lucide-react";
import { type FormEvent, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { AiSettingsPanel } from "../../components/ai-settings-panel.tsx";
import { systemQuery } from "../../components/app-shell.tsx";
import { AttacksPanel } from "../../components/attacks-panel.tsx";
import { DirectoryPanel } from "../../components/directory-panel.tsx";
import { isAdmin } from "../../components/nav.ts";
import { NotificationsPanel } from "../../components/notifications-panel.tsx";
import { Card, CardHeader, PageHeader } from "../../components/page-header.tsx";
import { ProxmoxPanel } from "../../components/proxmox-panel.tsx";
import { QueryStatus } from "../../components/query-state.tsx";
import { SectionNav, sectionLinkClass } from "../../components/section-nav.tsx";
import { Alert } from "../../components/ui/alert.tsx";
import { Button } from "../../components/ui/button.tsx";
import { Checkbox } from "../../components/ui/checkbox.tsx";
import { Field, FormField, FormRow } from "../../components/ui/field.tsx";
import { Select } from "../../components/ui/select.tsx";
import { UpdatesPanel } from "../../components/updates-panel.tsx";
import { XdrPanel } from "../../components/xdr-panel.tsx";
import { ApiError, api } from "../../lib/api.ts";
import { formatCalendarDate, formatDateTime } from "../../lib/format.ts";
import type { MessageKey } from "../../lib/i18n.ts";
import { SETTINGS_SECTIONS, type SettingsSection, settingsSearch } from "../../lib/search.ts";
import { toast } from "../../lib/toast.ts";
import { displayVersion } from "../../lib/version.ts";

/** Public source repository; AGPL-3.0 section 13 asks us to offer the source to every user. */
const SOURCE_REPOSITORY = "https://github.com/lcsfls/garnet-ops";

export const Route = createFileRoute("/_app/settings")({
  validateSearch: settingsSearch,
  component: SettingsPage,
});

interface Organization {
  id: string;
  name: string;
  scanSchedule: { enabled: boolean; localTime: string; timeZone: string };
  lastRuns: { localDate: string; queuedScans: number; createdAt: string }[];
}

const SECTION_LABELS = {
  scanning: "settings.sectionScanning",
  signin: "settings.sectionSignin",
  notifications: "settings.sectionNotifications",
  proxmox: "settings.sectionProxmox",
  xdr: "settings.sectionXdr",
  attacks: "settings.sectionAttacks",
  ai: "ai.sectionName",
  updates: "settings.sectionUpdates",
  about: "settings.sectionAbout",
} as const satisfies Record<SettingsSection, MessageKey>;

/**
 * Settings with a section list on the left (mockup), the form in a reading
 * width, and short help beside it on wide screens or below it otherwise. The steps follow
 * the width of the content area (AGENTS.md rule 5), not the window:
 * - narrow: the sections are a row of links above the form, the help is below it;
 * - from 48 rem: sections on the left, form and help below it on the right;
 * - wide (1450 px): sections, form and help side by side.
 */
function SettingsPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const admin = isAdmin(me);
  // Updates, notifications, Proxmox, XDR, attacks and AI are an installation matter: only owners and admins see
  // them. Sign-in (the directory) is for owners alone (ADR 0020).
  const sections = SETTINGS_SECTIONS.filter(
    (s) =>
      (s === "signin" ? me.role === "owner" : true) &&
      ((s !== "updates" &&
        s !== "notifications" &&
        s !== "proxmox" &&
        s !== "xdr" &&
        s !== "attacks" &&
        s !== "ai") ||
        admin),
  );
  const section = search.section && sections.includes(search.section) ? search.section : "scanning";

  return (
    <div className="mx-auto max-w-[72rem] @wide:max-w-[96rem]">
      <PageHeader icon={Settings} title={t("settings.title")} description={t("settings.description")} />
      <div className="grid items-start gap-4 @3xl:grid-cols-[12.5rem_minmax(0,1fr)] @wide:grid-cols-[12.5rem_minmax(0,46rem)_minmax(16rem,1fr)]">
        <SectionNav label={t("settings.sections")} className="@3xl:row-span-2 @wide:row-span-1">
          {sections.map((s) => (
            <li key={s}>
              <Link
                to="/settings"
                search={s === "scanning" ? {} : { section: s }}
                aria-current={s === section ? "page" : undefined}
                className={sectionLinkClass(s === section)}
              >
                {t(SECTION_LABELS[s])}
              </Link>
            </li>
          ))}
        </SectionNav>
        {/* The column is its own container: the panels in it size their rows by its width. */}
        <div data-testid="settings-form" className="@container grid min-w-0 gap-4">
          {section === "scanning" ? <ScanningSection canEdit={admin} /> : null}
          {section === "signin" ? <DirectoryPanel me={me} /> : null}
          {section === "notifications" ? <NotificationsPanel me={me} /> : null}
          {section === "proxmox" ? <ProxmoxPanel me={me} /> : null}
          {section === "xdr" ? <XdrPanel me={me} /> : null}
          {section === "attacks" ? <AttacksPanel me={me} /> : null}
          {section === "ai" ? <AiSettingsPanel me={me} /> : null}
          {section === "updates" ? <UpdatesPanel me={me} /> : null}
          {section === "about" ? <AboutSection /> : null}
        </div>
        <Help section={section} />
      </div>
    </div>
  );
}

const HELP: Record<SettingsSection, { title: MessageKey; text: MessageKey }[]> = {
  scanning: [
    { title: "settings.helpNightlyTitle", text: "settings.helpNightlyText" },
    { title: "settings.helpSandboxTitle", text: "settings.helpSandboxText" },
  ],
  signin: [
    { title: "directory.helpPasswordTitle", text: "directory.helpPasswordText" },
    { title: "directory.helpOwnersTitle", text: "directory.helpOwnersText" },
    { title: "directory.helpRolesTitle", text: "directory.helpRolesText" },
    { title: "directory.helpLimitsTitle", text: "directory.helpLimitsText" },
  ],
  notifications: [
    { title: "settings.helpNotifyContentTitle", text: "settings.helpNotifyContentText" },
    { title: "settings.helpNotifyDiscordTitle", text: "settings.helpNotifyDiscordText" },
  ],
  proxmox: [
    { title: "settings.helpProxmoxReadOnlyTitle", text: "settings.helpProxmoxReadOnlyText" },
    { title: "settings.helpProxmoxCertificateTitle", text: "settings.helpProxmoxCertificateText" },
  ],
  xdr: [
    { title: "settings.helpXdrReadOnlyTitle", text: "settings.helpXdrReadOnlyText" },
    { title: "settings.helpXdrCertificateTitle", text: "settings.helpXdrCertificateText" },
    { title: "settings.helpXdrLicenseTitle", text: "settings.helpXdrLicenseText" },
  ],
  attacks: [
    { title: "attacks.settings.helpLocalTitle", text: "attacks.settings.helpLocalText" },
    { title: "attacks.settings.helpOptInTitle", text: "attacks.settings.helpOptInText" },
    { title: "attacks.settings.helpLicenseTitle", text: "attacks.settings.helpLicenseText" },
  ],
  ai: [
    { title: "ai.helpDataTitle", text: "ai.helpDataText" },
    { title: "ai.helpNetworkTitle", text: "ai.helpNetworkText" },
    { title: "ai.helpOffTitle", text: "ai.helpOffText" },
  ],
  updates: [
    { title: "settings.helpUpdatesSignedTitle", text: "settings.helpUpdatesSignedText" },
    { title: "settings.helpUpdatesBackupTitle", text: "settings.helpUpdatesBackupText" },
    { title: "settings.helpUpdatesManualTitle", text: "settings.helpUpdatesManualText" },
  ],
  about: [{ title: "settings.helpSourceTitle", text: "settings.helpSourceText" }],
};

function Help({ section }: { section: SettingsSection }) {
  const { t } = useTranslation();
  return (
    <Card className="@3xl:col-start-2 @wide:col-start-3 @wide:row-start-1">
      <CardHeader title={t("settings.goodToKnow")} />
      <div className="grid gap-3 px-5 py-4">
        {HELP[section].map((item) => (
          <div key={item.title}>
            <h3 className="text-sm font-medium">{t(item.title)}</h3>
            <p className="text-sm text-muted-foreground">{t(item.text)}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}

function ScanningSection({ canEdit }: { canEdit: boolean }) {
  const query = useQuery({
    queryKey: ["organization"],
    queryFn: () => api<Organization>("/organization"),
  });
  const { data } = query;
  if (!data) {
    return (
      <Card>
        <QueryStatus query={query} />
      </Card>
    );
  }
  return (
    <>
      <NightlyScan org={data} canEdit={canEdit} />
      <LastRuns runs={data.lastRuns} />
    </>
  );
}

/** Version, licence and where the source code of this version is (AGPL-3.0, section 13). */
function AboutSection() {
  const { t } = useTranslation();
  const system = useQuery(systemQuery);
  const version = system.data?.version;
  const sourceUrl = version ? `${SOURCE_REPOSITORY}/tree/v${version}` : SOURCE_REPOSITORY;
  return (
    <Card>
      <CardHeader title={t("settings.aboutTitle")} description={t("settings.aboutDescription")} />
      {system.data ? (
        <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 px-5 py-5">
          <dt className="text-muted-foreground">{t("settings.aboutVersion")}</dt>
          <dd className="font-mono">{version ? displayVersion(version, t("shell.alpha")) : null}</dd>
          <dt className="text-muted-foreground">{t("settings.aboutLicense")}</dt>
          <dd>{t("settings.aboutLicenseValue")}</dd>
          <dt className="text-muted-foreground">{t("settings.aboutSource")}</dt>
          <dd className="break-all">
            <a
              href={sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-text underline-offset-4 hover:underline"
            >
              {sourceUrl}
            </a>
          </dd>
        </dl>
      ) : (
        <QueryStatus query={system} />
      )}
    </Card>
  );
}

/** IANA zones known to the browser, with UTC first and the stored zone always present. */
function useTimeZones(current: string): string[] {
  return useMemo(() => {
    const zones = new Set<string>(["UTC", current]);
    for (const zone of Intl.supportedValuesOf("timeZone")) zones.add(zone);
    return ["UTC", ...[...zones].filter((z) => z !== "UTC").sort()];
  }, [current]);
}

function NightlyScan({ org, canEdit }: { org: Organization; canEdit: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const schedule = org.scanSchedule;
  const [enabled, setEnabled] = useState(schedule.enabled);
  const [timeZone, setTimeZone] = useState(schedule.timeZone);
  const [error, setError] = useState<MessageKey | null>(null);
  const zones = useTimeZones(schedule.timeZone);

  const save = useMutation({
    mutationFn: (body: { enabled: boolean; localTime: string; timeZone: string }) =>
      api("/organization/scan-schedule", { method: "PUT", body }),
    onSuccess: async () => {
      toast.success(t("settings.saved"));
      // The repositories page shows the schedule from the session status.
      await queryClient.invalidateQueries({ queryKey: ["organization"] });
      await queryClient.invalidateQueries({ queryKey: ["status"] });
    },
    onError: (e) =>
      setError(
        e instanceof ApiError && e.code === "unsupported-time-zone" ? "settings.errorZone" : "errors.generic",
      ),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    save.mutate({ enabled, localTime: String(form.get("localTime")), timeZone });
  }

  return (
    <Card>
      <CardHeader title={t("settings.nightlyTitle")} description={t("settings.nightlyDescription")} />
      <form className="grid gap-5 px-5 py-5" onSubmit={submit}>
        {!canEdit ? <Alert tone="info">{t("settings.readOnly")}</Alert> : null}
        {error ? <Alert tone="error">{t(error)}</Alert> : null}
        <label className="flex items-center gap-2.5">
          <Checkbox checked={enabled} disabled={!canEdit} onChange={(e) => setEnabled(e.target.checked)} />
          {t("settings.enabled")}
        </label>
        <FormRow columns={["10rem", "1fr"]} from="md">
          <Field
            id="nightly-time"
            label={t("settings.time")}
            name="localTime"
            type="time"
            required
            step={60}
            disabled={!canEdit || !enabled}
            defaultValue={schedule.localTime.slice(0, 5)}
          />
          <FormField id="nightly-zone" label={t("settings.timeZone")} hint={t("settings.timeZoneHint")}>
            {(control) => (
              <Select
                {...control}
                value={timeZone}
                disabled={!canEdit || !enabled}
                onChange={(e) => setTimeZone(e.target.value)}
              >
                {zones.map((zone) => (
                  <option key={zone} value={zone}>
                    {zone}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
        </FormRow>
        <p className="text-sm text-muted-foreground">{t("settings.timeHint")}</p>
        {canEdit ? (
          <div className="flex items-center gap-3">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? t("common.loading") : t("settings.save")}
            </Button>
          </div>
        ) : null}
      </form>
    </Card>
  );
}

function LastRuns({ runs }: { runs: Organization["lastRuns"] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("settings.lastRuns")} />
      {runs.length === 0 ? (
        <p className="px-5 py-5 text-muted-foreground">{t("settings.lastRunsEmpty")}</p>
      ) : (
        <ul>
          {runs.map((run) => (
            <li key={run.localDate} className="flex items-center gap-4 border-b px-5 py-3 last:border-0">
              <span className="font-medium">{formatCalendarDate(run.localDate)}</span>
              <span className="text-muted-foreground">
                {t("settings.queued", { count: run.queuedScans })}
              </span>
              <time dateTime={run.createdAt} className="ml-auto text-sm text-muted-foreground">
                {formatDateTime(run.createdAt)}
              </time>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
