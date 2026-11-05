<script lang="ts">
  import { Plus } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import ButtonLink from "../ui/ButtonLink.svelte";
</script>

<Card class="max-w-2xl px-6 py-6">
  <h2 class="text-lg font-semibold">{t("overview.emptyTitle")}</h2>
  <p class="mt-1 text-muted-foreground">{t("overview.emptyDescription")}</p>
  <ButtonLink variant="primary" href={href("/repositories", { add: "1" })} class="mt-5">
    <Plus aria-hidden="true" class="size-4" />
    {t("repositories.add")}
  </ButtonLink>
</Card>
