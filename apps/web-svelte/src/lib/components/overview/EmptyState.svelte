<script lang="ts">
  import { Plus } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
</script>

<Card class="max-w-2xl px-6 py-6">
  <h2 class="text-lg font-semibold">{t("overview.emptyTitle")}</h2>
  <p class="mt-1 text-muted-foreground">{t("overview.emptyDescription")}</p>
  <a
    href={href("/repositories", { add: "1" })}
    class="mt-5 inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
  >
    <Plus aria-hidden="true" class="size-4" />
    {t("repositories.add")}
  </a>
</Card>
