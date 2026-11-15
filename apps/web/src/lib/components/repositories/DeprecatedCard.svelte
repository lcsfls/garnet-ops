<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Badge from "../ui/Badge.svelte";
  import ButtonLink from "../ui/ButtonLink.svelte";

  /**
   * A repository's deprecated and yanked packages (ADR 0051), with the maintainers' message as text. Shown only while the module
   * is on; nothing here is a finding or changes the grade.
   */
  let { repo }: { repo: RepositoryDetail } = $props();
  interface Item {
    name: string;
    version: string;
    type: string;
    state: "deprecated" | "yanked";
    message: string | null;
  }
  const list = createQuery(() => ({
    queryKey: ["deprecated", repo.id],
    queryFn: () => api<{ items: Item[] }>(`/deprecated/repositories/${repo.id}`),
  }));
  const SHOWN = 8;
</script>

<Card>
  <div data-testid="repository-deprecated">
    <CardHeader title={t("deprecated.cardTitle")} description={t("deprecated.cardDescription")} />
    <QueryStatus query={list} />
    {#if list.data}
      {@const items = list.data.items}
      <div class="grid gap-3 px-5 pb-5 text-sm">
        {#if items.length === 0}
          <p>{t("deprecated.cardNone")}</p>
        {:else}
          <p class="font-medium">{t("deprecated.cardCount", { count: items.length })}</p>
          <ul class="grid gap-2">
            {#each items.slice(0, SHOWN) as item (`${item.type}:${item.name}@${item.version}`)}
              <li class="grid gap-0.5">
                <span class="flex flex-wrap items-baseline gap-1.5">
                  <span class="font-mono break-all">{item.name}@{item.version}</span>
                  <Badge tone="neutral">{t(`deprecated.${item.state}`)}</Badge>
                </span>
                {#if item.message}<span class="text-muted-foreground">{item.message}</span>{/if}
              </li>
            {/each}
          </ul>
          <div>
            <ButtonLink class="h-9 text-sm" href={href("/packages", { repositoryId: repo.id, deprecated: "1" })}>
              {t("deprecated.cardShowAll")}
            </ButtonLink>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</Card>
