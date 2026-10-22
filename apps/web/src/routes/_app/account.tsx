import { createFileRoute, Link } from "@tanstack/react-router";
import { UserRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import { AuthenticatorSection } from "../../components/account/authenticator-section.tsx";
import { PasskeysSection } from "../../components/account/passkeys-section.tsx";
import { PasswordSection } from "../../components/account/password-section.tsx";
import { ProfileSection } from "../../components/account/profile-section.tsx";
import { SessionsSection } from "../../components/account/sessions-section.tsx";
import { PageHeader } from "../../components/page-header.tsx";
import { SectionNav, sectionLinkClass } from "../../components/section-nav.tsx";
import type { MessageKey } from "../../lib/i18n.ts";
import { ACCOUNT_SECTIONS, type AccountSection, accountSearch } from "../../lib/search.ts";

export const Route = createFileRoute("/_app/account")({
  validateSearch: accountSearch,
  component: AccountPage,
});

const SECTION_LABELS = {
  profile: "account.nav.profile",
  password: "account.nav.password",
  authenticator: "account.nav.authenticator",
  passkeys: "account.nav.passkeys",
  sessions: "account.nav.sessions",
} as const satisfies Record<AccountSection, MessageKey>;

/**
 * The signed-in user's own account (ADR 0017), opened from the avatar menu: sections on the
 * left like Settings, a reading width for the forms, and no help column (the texts sit with
 * the controls). Below 48 rem of content width the sections are a row above the form.
 */
function AccountPage() {
  const { t } = useTranslation();
  const { me } = Route.useRouteContext();
  const search = Route.useSearch();
  const section = search.section ?? "profile";

  return (
    <div className="mx-auto max-w-[60rem]">
      <PageHeader icon={UserRound} title={t("account.title")} description={t("account.description")} />
      <div className="grid items-start gap-4 @3xl:grid-cols-[12.5rem_minmax(0,1fr)]">
        <SectionNav label={t("account.sections")}>
          {ACCOUNT_SECTIONS.map((s) => (
            <li key={s}>
              <Link
                to="/account"
                search={s === "profile" ? {} : { section: s }}
                aria-current={s === section ? "page" : undefined}
                className={sectionLinkClass(s === section)}
              >
                {t(SECTION_LABELS[s])}
              </Link>
            </li>
          ))}
        </SectionNav>
        <div data-testid="account-section" className="@container grid min-w-0 gap-4">
          {section === "profile" ? <ProfileSection /> : null}
          {section === "password" ? <PasswordSection email={me.user.email} /> : null}
          {section === "authenticator" ? <AuthenticatorSection email={me.user.email} /> : null}
          {section === "passkeys" ? <PasskeysSection email={me.user.email} /> : null}
          {section === "sessions" ? <SessionsSection /> : null}
        </div>
      </div>
    </div>
  );
}
