<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { FindingNote } from "../../types.ts";

  /** Notes on the finding. Today they are AI suggestions that a person took over (ADR 0013). */
  let { findingId }: { findingId: string } = $props();
  const notes = createQuery(() => ({
    queryKey: ["finding-notes", findingId],
    queryFn: () => api<FindingNote[]>(`/findings/${findingId}/notes`),
  }));
</script>

{#if notes.data?.length}
  <div>
    <h3 class="mb-1 text-sm font-medium">{t("ai.notesTitle")}</h3>
    <ul class="grid gap-2">
      {#each notes.data as note (note.id)}
        <li class="rounded-md border px-3 py-2 text-sm">
          <p class="break-words whitespace-pre-line">{note.body}</p>
          <p class="mt-1 text-[13px] text-muted-foreground">
            {note.source === "ai" ? t("ai.noteFromAi", { name: note.author ?? "?" }) : (note.author ?? "")}{" · "}<time
              datetime={note.createdAt}>{formatRelative(note.createdAt)}</time
            >
          </p>
        </li>
      {/each}
    </ul>
  </div>
{/if}
