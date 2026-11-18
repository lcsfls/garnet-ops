<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { FindingDetail } from "../../types.ts";

  /**
   * Whether the finding's package is in a running image built from its repository (ADR 0054), with the containers the answer
   * rests on. A fact in neutral words: "not in the image" is never shown as good news, and nothing here changes the finding.
   */
  let { image, version }: { image: FindingDetail["image"]; version: string } = $props();
  const text = $derived(
    image.state === "in-image"
      ? t("findings.image.in")
      : image.state === "not-in-image"
        ? t("findings.image.notIn")
        : t(`findings.image.unknown.${image.reason ?? "no-image"}`),
  );
</script>

<div data-testid="finding-image" data-state={image.state ?? image.reason}>
  <h3 class="mb-1 text-sm font-medium">{t("findings.image.title")}</h3>
  <p class="text-sm">{text}</p>
  {#if image.state === "not-in-image" && image.caveat}
    <p class="mt-1 text-sm text-muted-foreground">{t(`findings.image.caveat.${image.caveat}`)}</p>
  {/if}
  {#if image.containers.length > 0}
    <table class="mt-2 w-full text-left text-sm">
      <thead class="text-muted-foreground">
        <tr class="border-b">
          <th class="py-1.5 pr-3 font-medium">{t("findings.image.columnContainer")}</th>
          <th class="py-1.5 font-medium">{t("findings.image.columnVersion")}</th>
        </tr>
      </thead>
      <tbody>
        <!-- Unkeyed: two hosts may run a container of the same name. -->
        {#each image.containers as container}
          <tr class="border-b align-top last:border-0">
            <td class="py-1.5 pr-3">
              <a class="link" href={`/hosts/${container.hostId}`}>{container.name}</a>
              <span class="text-muted-foreground">{t("findings.image.onHost", { host: container.hostName })}</span>
              <span class="block font-mono break-all text-muted-foreground">{container.imageRef}</span>
            </td>
            <td class="py-1.5">
              {#if container.version !== null}
                <span class="font-mono break-all">{container.version}</span>
                {#if container.version === version}
                  <span class="block text-muted-foreground">{t("findings.image.sameVersion")}</span>
                {/if}
              {:else}
                <span class="text-muted-foreground"
                  >{container.read ? t("findings.image.notFound") : t("findings.image.notRead")}</span
                >
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
  {#if image.state}
    <p class="mt-2 text-sm text-muted-foreground">{t("findings.image.nothingChanges")}</p>
  {/if}
</div>
