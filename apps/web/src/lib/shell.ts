import { api } from "./api.ts";

export interface FindingCounts {
  states: { open: number; accepted: number; resolved: number };
  open: Partial<Record<string, number>>;
}

/** Shared with the findings page, which shows the same counts on its tabs. */
export const findingCountsQuery = (filters = "") => ({
  queryKey: ["finding-counts", filters],
  queryFn: () => api<FindingCounts>(`/findings/counts${filters}`),
});

export const systemQuery = {
  queryKey: ["system"],
  queryFn: () => api<{ version: string }>("/system"),
  staleTime: 5 * 60_000,
};
