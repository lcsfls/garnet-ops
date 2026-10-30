import { useQueryClient } from "@tanstack/svelte-query";

/**
 * Reloads every query once a scan the page follows has finished. A page polls only its own data while a scan
 * runs; the findings, counts, trends and histories a finished scan changed (new, reopened or resolved findings)
 * would otherwise stay as they were until the next reload or window focus.
 */
export function refreshWhenScansFinish(busy: () => boolean) {
  const queryClient = useQueryClient();
  let wasBusy = false;
  $effect(() => {
    const now = busy();
    if (wasBusy && !now) void queryClient.invalidateQueries();
    wasBusy = now;
  });
}
