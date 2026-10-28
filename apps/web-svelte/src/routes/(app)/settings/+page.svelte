<script lang="ts">
  import { Settings } from "@lucide/svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import SectionNav from "#lib/components/SectionNav.svelte";
  import { sectionLinkClass } from "#lib/components/section-nav.ts";
  import AboutSection from "#lib/components/settings/AboutSection.svelte";
  import AiSettingsPanel from "#lib/components/settings/AiSettingsPanel.svelte";
  import DirectoryPanel from "#lib/components/settings/directory/DirectoryPanel.svelte";
  import NotificationsPanel from "#lib/components/settings/NotificationsPanel.svelte";
  import SettingsHelp from "#lib/components/settings/SettingsHelp.svelte";
  import ScanningSection from "#lib/components/settings/scanning/ScanningSection.svelte";
  import UpdatesPanel from "#lib/components/settings/UpdatesPanel.svelte";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { SETTINGS_SECTIONS, type SettingsSection, settingsSearch } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  let { data }: { data: PageData } = $props();

  const SECTION_LABELS = {
    scanning: "settings.sectionScanning",
    signin: "settings.sectionSignin",
    notifications: "settings.sectionNotifications",
    ai: "ai.sectionName",
    updates: "settings.sectionUpdates",
    about: "settings.sectionAbout",
  } as const satisfies Record<SettingsSection, MessageKey>;

  /**
   * Settings with a section list on the left (mockup), the form in a reading width, and short help beside it on wide
   * screens or below it otherwise. The steps follow the width of the content area (AGENTS.md rule 5), not the window:
   * - narrow: the sections are a row of links above the form, the help is below it;
   * - from 48 rem: sections on the left, form and help below it on the right;
   * - wide (1450 px): sections, form and help side by side.
   */
  const me = $derived(data.me);
  const admin = $derived(isAdmin(me));
  // Updates, notifications and AI are an installation matter: only owners and admins see them. Sign-in (the
  // directory) is for owners alone (ADR 0020).
  const sections = $derived(
    SETTINGS_SECTIONS.filter(
      (s) =>
        (s === "signin" ? me.role === "owner" : true) &&
        ((s !== "updates" && s !== "notifications" && s !== "ai") || admin),
    ),
  );
  const search = $derived(parseSearch(settingsSearch, page.url));
  const section: SettingsSection = $derived(
    search.section && sections.includes(search.section) ? search.section : "scanning",
  );
</script>

<div class="mx-auto max-w-[72rem] @wide:max-w-[96rem]">
  <PageHeader icon={Settings} title={t("settings.title")} description={t("settings.description")} />
  <div
    class="grid items-start gap-4 @3xl:grid-cols-[12.5rem_minmax(0,1fr)] @wide:grid-cols-[12.5rem_minmax(0,46rem)_minmax(16rem,1fr)]"
  >
    <SectionNav label={t("settings.sections")} class="@3xl:row-span-2 @wide:row-span-1">
      {#each sections as s (s)}
        <li>
          <a
            href={href("/settings", s === "scanning" ? {} : { section: s })}
            aria-current={s === section ? "page" : undefined}
            class={sectionLinkClass(s === section)}
          >
            {t(SECTION_LABELS[s])}
          </a>
        </li>
      {/each}
    </SectionNav>
    <!-- The column is its own container: the panels in it size their rows by its width. -->
    <div data-testid="settings-form" class="@container grid min-w-0 gap-4">
      {#if section === "scanning"}<ScanningSection canEdit={admin} />{/if}
      {#if section === "signin"}<DirectoryPanel {me} />{/if}
      {#if section === "notifications"}<NotificationsPanel {me} />{/if}
      {#if section === "ai"}<AiSettingsPanel {me} />{/if}
      {#if section === "updates"}<UpdatesPanel {me} />{/if}
      {#if section === "about"}<AboutSection />{/if}
    </div>
    <SettingsHelp {section} />
  </div>
</div>
