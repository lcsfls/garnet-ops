<script lang="ts">
  import { UserRound } from "@lucide/svelte";
  import AuthenticatorSection from "#lib/components/account/AuthenticatorSection.svelte";
  import NotificationsSection from "#lib/components/account/NotificationsSection.svelte";
  import PasskeysSection from "#lib/components/account/PasskeysSection.svelte";
  import PasswordSection from "#lib/components/account/PasswordSection.svelte";
  import ProfileSection from "#lib/components/account/ProfileSection.svelte";
  import SessionsSection from "#lib/components/account/SessionsSection.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import SectionNav from "#lib/components/SectionNav.svelte";
  import { sectionLinkClass } from "#lib/components/section-nav.ts";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { ACCOUNT_SECTIONS, type AccountSection, accountSearch } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  const SECTION_LABELS = {
    profile: "account.nav.profile",
    password: "account.nav.password",
    authenticator: "account.nav.authenticator",
    passkeys: "account.nav.passkeys",
    sessions: "account.nav.sessions",
    notifications: "account.nav.notifications",
  } as const satisfies Record<AccountSection, MessageKey>;

  /**
   * The signed-in user's own account (ADR 0017), opened from the avatar menu: sections on the
   * left like Settings, a reading width for the forms, and no help column (the texts sit with
   * the controls). Below 48 rem of content width the sections are a row above the form.
   */
  let { data }: { data: PageData } = $props();
  const search = $derived(parseSearch(accountSearch, page.url));
  const section = $derived<AccountSection>(search.section ?? "profile");
</script>

<div class="mx-auto max-w-[60rem]">
  <PageHeader icon={UserRound} title={t("account.title")} description={t("account.description")} />
  <div class="grid items-start gap-4 @3xl:grid-cols-[12.5rem_minmax(0,1fr)]">
    <SectionNav label={t("account.sections")}>
      {#each ACCOUNT_SECTIONS as s (s)}
        <li>
          <a
            href={href("/account", s === "profile" ? {} : { section: s })}
            aria-current={s === section ? "page" : undefined}
            class={sectionLinkClass(s === section)}
          >
            {t(SECTION_LABELS[s])}
          </a>
        </li>
      {/each}
    </SectionNav>
    <div data-testid="account-section" class="@container grid min-w-0 gap-4">
      {#if section === "profile"}<ProfileSection />{/if}
      {#if section === "password"}<PasswordSection email={data.me.user.email} />{/if}
      {#if section === "authenticator"}<AuthenticatorSection email={data.me.user.email} />{/if}
      {#if section === "passkeys"}<PasskeysSection email={data.me.user.email} />{/if}
      {#if section === "sessions"}<SessionsSection />{/if}
      {#if section === "notifications"}<NotificationsSection />{/if}
    </div>
  </div>
</div>
