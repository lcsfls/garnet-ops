<script lang="ts">
  import { UPDATE_TONE, type UpdateInfo } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Badge from "../ui/Badge.svelte";

  /** Whether a newer image exists for a container's tag, as a word. */
  let { update }: { update: UpdateInfo } = $props();
</script>

<Badge tone={UPDATE_TONE[update.state]}>
  {update.state === "newer-version"
    ? t("hosts.update.newer-version", { tag: update.tag ?? "", kind: update.kind ? t(`hosts.updateKind.${update.kind}`) : "" })
    : t(`hosts.update.${update.state}`)}
</Badge>
