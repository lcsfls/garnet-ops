<script lang="ts">
  import { cn } from "../../cn.ts";
  import { t } from "../../i18n.svelte.ts";

  /**
   * The two views of website monitoring: the websites, one row per name, and the certificates, one row per certificate. Links,
   * not tabs: each view has its own address, so a notification can lead straight to a certificate.
   */
  let { current }: { current: "websites" | "certificates" } = $props();
  const views = [
    { value: "websites", to: "/websites", label: "websites.viewWebsites" },
    { value: "certificates", to: "/websites/certificates", label: "websites.viewCertificates" },
  ] as const;
</script>

<nav aria-label={t("websites.viewsLabel")} class="mb-4" data-testid="websites-views">
  <ul class="inline-flex max-w-full flex-wrap gap-0.5 rounded-lg bg-muted p-[3px]">
    {#each views as view (view.value)}
      <li>
        <a
          href={view.to}
          aria-current={view.value === current ? "page" : undefined}
          class={cn(
            "flex h-8 items-center rounded-md px-3 text-sm whitespace-nowrap",
            view.value === current
              ? "bg-card font-medium text-foreground shadow-xs"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {t(view.label)}
        </a>
      </li>
    {/each}
  </ul>
</nav>
