<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { Overview } from "../../types.ts";
  import { href } from "../../url.ts";
  import Banner from "../ui/Banner.svelte";
  import ButtonLink from "../ui/ButtonLink.svelte";
  import { remedyHref } from "./links.ts";

  /**
   * The one place for the overview's top statement, written from the facts the API computed (overview.ts, headlineFacts):
   * how many critical (or else high) findings are open and where, what they come from, what fixes them and whether any is
   * known to be exploited. Its tone is that severity's; with neither open it says so plainly, in neutral, without cheer.
   */
  let { data }: { data: Overview } = $props();
  const h = $derived(data.headline);
  const open = $derived(Object.values(data.open).reduce((sum, n) => sum + (n ?? 0), 0));

  const sentences = $derived.by(() => {
    if (h.level === "none") return [];
    const out: string[] = [];
    if (h.package) {
      out.push(
        t("overview.headline.onePackage", {
          count: h.count,
          package: `${h.package.name} ${h.package.version}`,
        }),
      );
    } else if (h.packages > 1) {
      out.push(t("overview.headline.severalPackages", { packages: h.packages }));
    }
    if (h.oneUpgrade)
      out.push(t("overview.headline.oneUpgrade", { count: h.count, version: h.oneUpgrade.toVersion }));
    else if (h.fixable === h.count) out.push(t("overview.headline.allFixable", { upgrades: h.upgrades }));
    else if (h.fixable > 0)
      out.push(t("overview.headline.someFixable", { upgrades: h.upgrades, fixable: h.fixable }));
    else out.push(t("overview.headline.noneFixable", { count: h.count }));
    out.push(
      h.count === 1
        ? t("overview.headline.exploitedOne", { exploited: h.knownExploited })
        : t("overview.headline.exploitedMany", { exploited: h.knownExploited }),
    );
    return out;
  });

  /** The one action: the fix when there is one, else the fixes, else the findings themselves. */
  const next = $derived.by(() => {
    if (h.level === "none") return null;
    if (h.oneUpgrade)
      return {
        label: t("overview.headline.reviewFix"),
        to: remedyHref(h.oneUpgrade.packageName, h.oneUpgrade.proposals),
      };
    if (h.fixable > 0)
      return { label: t("overview.headline.reviewFixes"), to: href("/fixes", { severity: h.level }) };
    return { label: t("overview.viewFindings"), to: href("/findings", { severity: h.level }) };
  });
</script>

<div data-testid="overview-headline">
  {#if h.level === "none"}
    {#if h.scanned}
      <Banner class="mb-0" tone="neutral" title={t("overview.headline.noneTitle")}>
        {t("overview.headline.noneText", { open })}
      </Banner>
    {:else}
      <Banner class="mb-0" tone="neutral" title={t("overview.headline.notScannedTitle")}>
        {t("overview.headline.notScannedText")}
      </Banner>
    {/if}
  {:else}
    <Banner
      class="mb-0"
      tone={h.level}
      title={t(`overview.headline.${h.level}`, { count: h.count, repositories: h.repositories })}
    >
      {sentences.join(" ")}
      {#snippet action()}
        {#if next}
          <ButtonLink href={next.to} data-testid="overview-headline-action">{next.label}</ButtonLink>
        {/if}
      {/snippet}
    </Banner>
  {/if}
</div>
