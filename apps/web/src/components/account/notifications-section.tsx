import { defaultPreference, type UserEvent } from "@garnetops/core/user-notifications";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Mail } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../../lib/api.ts";
import type { MessageKey } from "../../lib/i18n.ts";
import {
  eventMessageKey,
  type NotificationPreferences,
  type PreferenceRow,
  preferencesQuery,
} from "../../lib/notifications.ts";
import { toast } from "../../lib/toast.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { QueryStatus } from "../query-state.tsx";
import { Alert } from "../ui/alert.tsx";
import { Button } from "../ui/button.tsx";
import { Checkbox } from "../ui/checkbox.tsx";
import { Select } from "../ui/select.tsx";

type Draft = Record<string, PreferenceRow["preference"]>;
const GROUPS = ["code", "infrastructure", "account", "system"] as const;

const toDraft = (data: NotificationPreferences): Draft =>
  Object.fromEntries(data.events.map((row) => [row.event, row.preference]));

/**
 * Account → Notifications (ADR 0019): the matrix of what this person receives, per event type,
 * in the app and by email. Not the organisation's shared channels, which admins manage under
 * Settings → Notifications; the text says so in both places.
 */
export function NotificationsSection() {
  const { t } = useTranslation();
  const query = useQuery(preferencesQuery);
  if (!query.data) {
    return (
      <Card>
        <CardHeader
          title={t("account.notifications.title")}
          description={t("account.notifications.description")}
        />
        <QueryStatus query={query} />
      </Card>
    );
  }
  return <Matrix data={query.data} />;
}

function Matrix({ data }: { data: NotificationPreferences }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft>(() => toDraft(data));
  const [saved, setSaved] = useState<Draft>(() => toDraft(data));
  // A reload from the server (after saving, or a mail channel that appeared) replaces what was shown.
  useEffect(() => {
    setDraft(toDraft(data));
    setSaved(toDraft(data));
  }, [data]);

  const dirty = data.events.some(
    (row) => JSON.stringify(draft[row.event]) !== JSON.stringify(saved[row.event]),
  );
  const save = useMutation({
    mutationFn: () =>
      api("/me/notification-preferences", {
        method: "PUT",
        body: {
          preferences: data.events.map((row) => ({
            event: row.event,
            ...(draft[row.event] ?? row.preference),
          })),
        },
      }),
    onSuccess: async () => {
      toast.success(t("account.notifications.saved"));
      await queryClient.invalidateQueries({ queryKey: preferencesQuery.queryKey });
    },
    onError: (error) => {
      toast.error(
        error instanceof ApiError && error.status === 422
          ? t("errors.invalidValue")
          : t("errors.actionFailed"),
      );
      void queryClient.invalidateQueries({ queryKey: preferencesQuery.queryKey });
    },
  });

  function set(row: PreferenceRow, change: Partial<PreferenceRow["preference"]>) {
    setDraft((d) => ({ ...d, [row.event]: { ...(d[row.event] ?? row.preference), ...change } }));
  }
  function restoreDefaults() {
    setDraft(
      Object.fromEntries(data.events.map((row) => [row.event, defaultPreference(row.event as UserEvent)])),
    );
  }

  const label = (row: PreferenceRow) =>
    t(`account.notifications.events.${eventMessageKey(row.event)}.label` as MessageKey);
  const hint = (row: PreferenceRow) =>
    t(`account.notifications.events.${eventMessageKey(row.event)}.hint` as MessageKey);

  return (
    <Card>
      <CardHeader
        title={t("account.notifications.title")}
        description={t("account.notifications.description")}
      />
      <div className="grid gap-4 px-5 pb-5">
        <p className="text-sm text-muted-foreground">{t("account.notifications.relation")}</p>
        {data.canManageChannels ? (
          <p className="text-sm">
            <Link
              to="/settings"
              search={{ section: "notifications" }}
              className="font-medium text-primary-text underline underline-offset-4"
            >
              {t("account.notifications.settingsLink")}
            </Link>
          </p>
        ) : null}
        {data.mailAvailable ? (
          <p className="flex items-start gap-2 text-sm text-muted-foreground">
            <Mail aria-hidden="true" className="mt-0.5 size-4 flex-none" />
            <span>{t("account.notifications.emailRules", { email: data.email })}</span>
          </p>
        ) : (
          <Alert tone="info">
            <b className="block font-medium">{t("account.notifications.emailUnavailable")}</b>
            {data.canManageChannels
              ? t("account.notifications.emailUnavailableAdmin")
              : t("account.notifications.emailUnavailableMember")}
          </Alert>
        )}
        <p className="text-sm text-muted-foreground">{t("account.notifications.onlyRole")}</p>

        <table data-testid="notification-matrix" className="w-full table-fixed border-collapse text-left">
          <thead>
            <tr className="border-b text-sm text-muted-foreground">
              <th scope="col" className="py-2 pr-3 font-medium">
                <span className="sr-only">{t("account.notifications.title")}</span>
              </th>
              <th scope="col" className="w-20 py-2 text-center font-medium">
                {t("account.notifications.inApp")}
              </th>
              <th scope="col" className="w-20 py-2 text-center font-medium">
                {t("account.notifications.email")}
              </th>
            </tr>
          </thead>
          {GROUPS.map((group) => {
            const rows = data.events.filter((row) => row.group === group);
            if (rows.length === 0) return null;
            return (
              <tbody key={group}>
                <tr>
                  <th
                    colSpan={3}
                    scope="colgroup"
                    className="pt-5 pb-1 text-[13px] font-medium text-muted-foreground"
                  >
                    {t(`account.notifications.groups.${group}`)}
                  </th>
                </tr>
                {rows.map((row) => {
                  const current = draft[row.event] ?? row.preference;
                  return (
                    <tr key={row.event} data-event={row.event} className="border-t align-top">
                      <th scope="row" className="py-3 pr-3 font-normal">
                        <span className="block font-medium">{label(row)}</span>
                        <span className="block text-sm text-muted-foreground">{hint(row)}</span>
                        {row.scoped ? (
                          <Select
                            className="mt-2 h-9 max-w-full text-sm"
                            aria-label={t("account.notifications.scopeLabel", { event: label(row) })}
                            value={current.scope}
                            disabled={!current.inApp && !(current.email && data.mailAvailable)}
                            onChange={(event) => set(row, { scope: event.target.value as "all" | "mine" })}
                          >
                            <option value="all">
                              {t(`account.notifications.scopes.${row.scopeKind}.all`)}
                            </option>
                            <option value="mine">
                              {t(`account.notifications.scopes.${row.scopeKind}.mine`)}
                            </option>
                          </Select>
                        ) : null}
                      </th>
                      <td className="py-3 text-center">
                        <Checkbox
                          className="mx-auto mt-1"
                          aria-label={t("account.notifications.inAppLabel", { event: label(row) })}
                          checked={current.inApp}
                          onChange={(event) => set(row, { inApp: event.target.checked })}
                        />
                      </td>
                      <td className="py-3 text-center">
                        <Checkbox
                          className="mx-auto mt-1"
                          aria-label={t("account.notifications.emailLabel", { event: label(row) })}
                          checked={current.email && data.mailAvailable}
                          disabled={!data.mailAvailable}
                          title={data.mailAvailable ? undefined : t("account.notifications.emailUnavailable")}
                          onChange={(event) => set(row, { email: event.target.checked })}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            );
          })}
        </table>

        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={save.isPending || !dirty} onClick={() => save.mutate()}>
            {save.isPending ? t("common.loading") : t("account.notifications.save")}
          </Button>
          <Button variant="outline" onClick={restoreDefaults}>
            {t("account.notifications.restore")}
          </Button>
          <span className="text-sm text-muted-foreground">{t("account.notifications.restoreHint")}</span>
        </div>
      </div>
    </Card>
  );
}
