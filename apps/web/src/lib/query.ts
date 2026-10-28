import { QueryClient } from "@tanstack/svelte-query";

/** One cache for the whole app, shared by route guards (load functions) and components. */
export const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: true } },
});
