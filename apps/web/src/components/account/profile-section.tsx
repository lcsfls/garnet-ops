import { LANGUAGE_NAMES, LANGUAGES, type Language, resolveLanguage } from "@garnetops/i18n";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "@tanstack/react-router";
import { type FormEvent, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { type AccountOverview, accountQuery } from "../../lib/account.ts";
import { ApiError, api } from "../../lib/api.ts";
import { setLanguage } from "../../lib/i18n.ts";
import { browserTimeZone, setPreferredTimeZone, timeZoneChoices } from "../../lib/time-zone.ts";
import { toast } from "../../lib/toast.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { QueryStatus } from "../query-state.tsx";
import { Alert } from "../ui/alert.tsx";
import { Button } from "../ui/button.tsx";
import { Field, FormField, FormRow } from "../ui/field.tsx";
import { Select } from "../ui/select.tsx";

/** Account → Profile: display name, the (fixed) email address, language and time zone. */
export function ProfileSection() {
  const query = useQuery(accountQuery);
  if (!query.data) {
    return (
      <Card>
        <QueryStatus query={query} />
      </Card>
    );
  }
  return (
    <>
      <NameCard profile={query.data.profile} />
      <PreferencesCard profile={query.data.profile} />
    </>
  );
}

/** The session status feeds the avatar and the menu; refresh it after a change that shows there. */
function useRefreshMe() {
  const queryClient = useQueryClient();
  const router = useRouter();
  return async () => {
    await queryClient.invalidateQueries({ queryKey: ["status"] });
    await queryClient.invalidateQueries({ queryKey: ["account"] });
    await router.invalidate();
  };
}

function NameCard({ profile }: { profile: AccountOverview["profile"] }) {
  const { t } = useTranslation();
  const refresh = useRefreshMe();
  const [name, setName] = useState(profile.name);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (value: string) => api("/account/profile", { method: "PATCH", body: { name: value } }),
    onSuccess: async () => {
      toast.success(t("account.profile.saved"));
      await refresh();
    },
    onError: (e) =>
      setError(
        e instanceof ApiError && e.status === 422 ? t("account.profile.errorName") : t("errors.generic"),
      ),
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    save.mutate(name.trim());
  }
  return (
    <Card>
      <CardHeader title={t("account.profile.title")} description={t("account.profile.description")} />
      <form className="grid gap-5 px-5 py-5" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          label={t("account.profile.name")}
          name="name"
          required
          maxLength={100}
          autoComplete="name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <Field
          label={t("account.profile.email")}
          hint={t("account.profile.emailHint")}
          name="email"
          type="email"
          readOnly
          value={profile.email}
          className="bg-muted text-muted-foreground"
        />
        <div className="flex items-center gap-3">
          <Button
            type="submit"
            disabled={save.isPending || name.trim() === "" || name.trim() === profile.name}
          >
            {save.isPending ? t("common.loading") : t("account.profile.save")}
          </Button>
        </div>
      </form>
    </Card>
  );
}

function PreferencesCard({ profile }: { profile: AccountOverview["profile"] }) {
  const { t, i18n } = useTranslation();
  const refresh = useRefreshMe();
  const [locale, setLocale] = useState<Language>(profile.locale ?? resolveLanguage(i18n.language));
  // "" is automatic: the browser's zone.
  const [zone, setZone] = useState(profile.timeZone ?? "");
  const [error, setError] = useState<string | null>(null);
  const zones = useMemo(() => timeZoneChoices(profile.timeZone), [profile.timeZone]);
  const save = useMutation({
    mutationFn: () =>
      api("/account/preferences", { method: "PUT", body: { locale, timeZone: zone === "" ? null : zone } }),
    onSuccess: async () => {
      setPreferredTimeZone(zone === "" ? null : zone);
      await setLanguage(locale);
      toast.success(t("account.profile.saved"));
      await refresh();
    },
    onError: () => setError(t("errors.generic")),
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    save.mutate();
  }
  return (
    <Card>
      <CardHeader
        title={t("account.profile.preferencesTitle")}
        description={t("account.profile.preferencesDescription")}
      />
      <form className="grid gap-5 px-5 py-5" onSubmit={submit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <FormRow columns={["12rem", "1fr"]} from="md">
          <FormField label={t("account.profile.language")}>
            {(control) => (
              <Select {...control} value={locale} onChange={(e) => setLocale(e.target.value as Language)}>
                {LANGUAGES.map((l) => (
                  <option key={l} value={l} lang={l}>
                    {LANGUAGE_NAMES[l]}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
          <FormField label={t("account.profile.timeZone")} hint={t("account.profile.timeZoneHint")}>
            {(control) => (
              <Select {...control} value={zone} onChange={(e) => setZone(e.target.value)}>
                <option value="">{t("account.profile.timeZoneAuto", { zone: browserTimeZone() })}</option>
                {zones.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
        </FormRow>
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? t("common.loading") : t("account.profile.save")}
          </Button>
        </div>
      </form>
    </Card>
  );
}
