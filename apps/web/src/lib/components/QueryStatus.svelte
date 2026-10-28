<script lang="ts">
  import { RefreshCw } from "@lucide/svelte";
  import { cn } from "../cn.ts";
  import { t } from "../i18n.svelte.ts";
  import Alert from "./ui/Alert.svelte";
  import Button from "./ui/Button.svelte";

  /**
   * Loading and error states of a query, so no page waits silently forever or shows an empty table when the server
   * could not be reached. The loading block reserves room for a few rows, so the first data does not push the page
   * around much.
   */
  let {
    query,
    class: className,
  }: {
    query: { data: unknown; isError: boolean; isFetching: boolean; refetch: () => unknown };
    class?: string;
  } = $props();
</script>

{#if query.isError}
  <div class={cn("px-5 py-5", className)}>
    <Alert tone="error">
      <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
        <span>{query.data === undefined ? t("errors.loadFailed") : t("errors.refreshFailed")}</span>
        <Button
          variant="outline"
          class="h-8 px-3 text-sm"
          disabled={query.isFetching}
          onclick={() => void query.refetch()}
        >
          <RefreshCw aria-hidden="true" class="size-3.5" />
          {t("common.retry")}
        </Button>
      </div>
    </Alert>
  </div>
{:else if query.data === undefined}
  <p role="status" class={cn("min-h-40 px-5 py-6 text-muted-foreground", className)}>{t("common.loading")}</p>
{/if}
