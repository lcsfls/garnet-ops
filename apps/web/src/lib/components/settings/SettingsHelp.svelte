<script lang="ts">
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { SettingsSection } from "../../search.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";

  /** The "Good to know" column of the settings: short help for the section that is open. */
  let { section }: { section: SettingsSection } = $props();

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
</script>

<Card class="@3xl:col-start-2 @wide:col-start-3 @wide:row-start-1">
  <CardHeader title={t("settings.goodToKnow")} />
  <div class="grid gap-3 px-5 py-4">
    {#each HELP[section] as item (item.title)}
      <div>
        <h3 class="text-sm font-medium">{t(item.title)}</h3>
        <p class="text-sm text-muted-foreground">{t(item.text)}</p>
      </div>
    {/each}
  </div>
</Card>
