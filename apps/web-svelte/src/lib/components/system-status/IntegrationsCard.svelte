<script lang="ts">
  import type {
    InstanceStatus,
    IntegrationPartStatus,
    IntegrationStatus,
  } from "@garnetops/core/system-status-view";
  import { formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { camelState, canOpenSection, INTEGRATION_SECTION } from "../../system-status.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Row from "./Row.svelte";
  import { reasonText } from "./reason.ts";
  import StatusBadge from "./StatusBadge.svelte";

  let { integrations, role }: { integrations: IntegrationStatus[]; role: string } = $props();

  /** One connection behind a part: its name, state, why and when it last worked. */
  function instanceText(instance: InstanceStatus): string {
    const reason = reasonText(instance.reason);
    let text = `: ${t(`systemStatus.integrations.state.${camelState(instance.state)}`)}`;
    if (instance.blocked) text += ` – ${t(`systemStatus.integrations.blocked.${instance.blocked}`)}`;
    if (reason) text += ` – ${reason}`;
    if (instance.lastSuccessAt)
      text += ` (${t("systemStatus.integrations.instanceLast", { when: formatRelative(instance.lastSuccessAt) })})`;
    return text;
  }

  /** Counts that explain a part's state: the endpoint scope, accounts checked, channels. */
  function extraOf(integration: IntegrationStatus, part: IntegrationPartStatus): string[] {
    const detail = part.detail;
    const extra: string[] = [];
    if (integration.key === "ai" && typeof detail.scope === "string") {
      extra.push(
        t("systemStatus.integrations.scope", {
          scope: t(`systemStatus.integrations.scopeValue.${detail.scope as "private"}`),
        }),
      );
    }
    if (integration.key === "directory" && typeof detail.accountsChecked === "number") {
      extra.push(t("systemStatus.integrations.accounts", { count: detail.accountsChecked }));
    }
    if (integration.key === "notifications") {
      extra.push(
        t("systemStatus.integrations.channels", {
          enabled: Number(detail.enabled ?? 0),
          connections: Number(detail.connections ?? 0),
        }),
      );
    }
    return extra;
  }
</script>

{#snippet partLine(integration: IntegrationStatus, part: IntegrationPartStatus)}
  {@const off = part.state === "not_configured"}
  {@const reason = reasonText(part.reason)}
  {@const extra = extraOf(integration, part)}
  {@const showFacts = !off}
  <li class="grid gap-0.5" data-testid="part-{integration.key}-{part.key}">
    <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
      <span class="font-medium text-foreground">
        {t(`systemStatus.integrations.part.${part.key}` as MessageKey)}
      </span>
      <StatusBadge level={part.level}>
        {off
          ? t("systemStatus.integrations.partOff")
          : t(`systemStatus.integrations.state.${camelState(part.state)}`)}
      </StatusBadge>
    </div>
    {#if showFacts}
      <span
        >{part.lastSuccessAt
          ? t("systemStatus.integrations.lastSuccess", { when: formatRelative(part.lastSuccessAt) })
          : t("systemStatus.integrations.noSuccess")}{" · "}{part.lastAttemptAt && part.lastAttemptOk !== null
          ? t(
              part.lastAttemptOk ? "systemStatus.integrations.attemptOk" : "systemStatus.integrations.attemptFailed",
              { when: formatRelative(part.lastAttemptAt) },
            )
          : t("systemStatus.integrations.noAttempt")}</span
      >
    {/if}
    {#if extra.length > 0 && !off}<span>{extra.join(" · ")}</span>{/if}
    {#if part.blocked}<span>{t(`systemStatus.integrations.blocked.${part.blocked}`)}</span>{/if}
    {#if reason && part.state !== "blocked"}<span>{reason}</span>{/if}
    {#if part.instances.length > 0}
      <ul class="ml-4 list-disc">
        {#each part.instances as i (i.name)}
          <li class="[overflow-wrap:anywhere]">
            <span class="font-medium text-foreground">{i.name}</span>{instanceText(i)}
          </li>
        {/each}
      </ul>
    {/if}
  </li>
{/snippet}

<Card>
  <CardHeader title={t("systemStatus.integrations.title")} description={t("systemStatus.integrations.description")} />
  <ul>
    {#each integrations as integration (integration.key)}
      {@const section = INTEGRATION_SECTION[integration.key]}
      {@const word = t(`systemStatus.integrations.state.${camelState(integration.state)}`)}
      <Row testId="integration-{integration.key}">
        {#snippet title()}
          {t(`systemStatus.integrations.name.${integration.key}`)}{#if integration.configured}<span
              class="ml-2 text-sm font-normal text-muted-foreground"
              >{t(`systemStatus.integrations.count.${integration.key}`, { count: integration.count })}</span
            >{/if}
        {/snippet}
        {#snippet badge()}<StatusBadge level={integration.level}>{word}</StatusBadge>{/snippet}
        {#if integration.parts.length > 0}
          <ul class="grid gap-2">
            {#each integration.parts as p (p.key)}
              {@render partLine(integration, p)}
            {/each}
          </ul>
        {/if}
        {#if canOpenSection(section, role)}
          <span>
            <a
              href={href("/settings", { section })}
              data-testid="settings-link-{integration.key}"
              class="text-primary-text underline-offset-4 hover:underline"
            >
              {t("systemStatus.settingsLink")}
            </a>
          </span>
        {:else}
          <span>{t("systemStatus.integrations.directoryOwnerOnly")}</span>
        {/if}
      </Row>
    {/each}
  </ul>
</Card>
