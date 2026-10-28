import type { QueryClient } from "@tanstack/svelte-query";
import { invalidateAll } from "$app/navigation";

/**
 * The session status feeds the avatar and the menu; refresh it after a change that shows there. Re-running the load
 * functions gives the signed-in layout the new status (React: `router.invalidate()`).
 */
export async function refreshMe(queryClient: QueryClient): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: ["status"] });
  await queryClient.invalidateQueries({ queryKey: ["account"] });
  await invalidateAll();
}
