<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { t } from "../../i18n.svelte.ts";
  import { canOpenSection } from "../../system-status.ts";
  import { href } from "../../url.ts";
  import { displayVersion } from "../../version.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Fact from "./Fact.svelte";
  import Facts from "./Facts.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  let { app, role }: { app: SystemStatus["app"]; role: string } = $props();

  const updater = $derived(app.updater);
  const word = $derived(
    !updater.configured
      ? t("systemStatus.integrations.state.notConfigured")
      : !updater.reachable
        ? t("systemStatus.app.updaterDown")
        : t(`systemStatus.app.phase.${updater.phase ?? "idle"}`),
  );
</script>

<Card>
  <CardHeader title={t("systemStatus.app.title")} description={t("systemStatus.app.description")} />
  <Facts>
    <Fact label={t("systemStatus.app.version")}>
      <span class="font-mono" data-testid="app-version">
        {displayVersion(app.version, t("shell.alpha"))}
      </span>
    </Fact>
    <Fact label={t("systemStatus.app.updates")}>
      <span class="inline-flex flex-wrap items-center gap-2">
        <StatusBadge level={updater.level}>
          {!updater.configured
            ? t("systemStatus.integrations.state.notConfigured")
            : !updater.reachable
              ? t("systemStatus.level.attention")
              : updater.level === "failed"
                ? t("systemStatus.level.failed")
                : t("systemStatus.level.ok")}
        </StatusBadge>
        <span data-testid="updater-text">
          {updater.configured ? word : t("systemStatus.app.updaterOff")}
        </span>
      </span>
      {#if updater.configured && updater.reachable}
        <span class="mt-1 block text-muted-foreground">
          {updater.latestAvailable
            ? t("systemStatus.app.latest", { version: updater.latestAvailable })
            : t("systemStatus.app.noLatest")}
        </span>
      {/if}
    </Fact>
  </Facts>
  {#if canOpenSection("updates", role)}
    <p class="px-5 pb-4 text-sm">
      <a
        href={href("/settings", { section: "updates" })}
        class="text-primary-text underline-offset-4 hover:underline"
        data-testid="settings-link-updates"
      >
        {t("systemStatus.settingsLink")}
      </a>
    </p>
  {/if}
</Card>
