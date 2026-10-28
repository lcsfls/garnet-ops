<script lang="ts">
  import { ArrowRight } from "@lucide/svelte";
  import { goto } from "$app/navigation";
  import { t } from "../../i18n.svelte.ts";
  import { rowClick } from "../../row-link.ts";
  import type { Overview } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import SeverityDot from "../ui/SeverityDot.svelte";

  let { items }: { items: Overview["fixFirst"] } = $props();
</script>

<Card class="h-full">
  <CardHeader title={t("overview.fixFirst")} description={t("overview.fixFirstDescription")}>
    {#snippet actions()}
      <a href="/findings" class="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline">
        {t("overview.allFindings")}
        <ArrowRight aria-hidden="true" class="size-4" />
      </a>
    {/snippet}
  </CardHeader>
  {#if items.length === 0}
    <p class="px-5 pb-6 text-muted-foreground">{t("overview.nothingToFix")}</p>
  {:else}
    <table class="w-full text-left">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("findings.columnFinding")}</th>
          <th class="px-3 py-2.5 font-medium">{t("findings.columnRepository")}</th>
          <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">
            {t("overview.columnSource")}
          </th>
          <th class="px-3 py-2.5 font-medium">{t("findings.severityFilter")}</th>
          <th class="hidden px-5 py-2.5 font-medium @xl:table-cell">{t("findings.columnFixedIn")}</th>
        </tr>
      </thead>
      <tbody>
        {#each items as f (f.id)}
          {@const link = href("/findings", { id: f.id, state: "all" })}
          <tr class="row-link border-b last:border-0" onclick={rowClick(() => void goto(link))}>
            <td class="px-5 py-2.5">
              <div class="flex items-start gap-2.5">
                <SeverityDot severity={f.severity} class="mt-2" />
                <div class="min-w-0">
                  <a href={link} class="font-medium hover:underline">
                    {f.vulnerabilityId}
                  </a>
                  <div class="font-mono text-sm text-muted-foreground">
                    {f.packageName} {f.packageVersion}
                  </div>
                </div>
              </div>
            </td>
            <td class="px-3 py-2.5">
              <RepositoryLink id={f.repositoryId} name={f.repositoryName} />
            </td>
            <td class="hidden px-3 py-2.5 text-sm text-muted-foreground @wide:table-cell">
              {t("overview.sourceDependency", { type: f.packageType })}
            </td>
            <td class="px-3 py-2.5">
              <div class="flex flex-wrap gap-1">
                <SeverityBadge severity={f.severity} />
                {#if f.knownExploited}
                  <span class="text-sm text-destructive-text">{t("findings.kev")}</span>
                {/if}
              </div>
            </td>
            <td class="hidden px-5 py-2.5 font-mono text-sm @xl:table-cell">
              {#if f.fixedIn?.length}
                {f.fixedIn.join(", ")}
              {:else}
                <span class="font-sans text-muted-foreground">{t("findings.noFix")}</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</Card>
