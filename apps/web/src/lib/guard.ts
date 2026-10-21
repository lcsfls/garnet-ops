import type { QueryClient } from "@tanstack/react-query";
import { redirect } from "@tanstack/react-router";
import { homeFor, type Status, statusQuery } from "./session.ts";

/**
 * Route guard: lets the visitor stay only if their status is one of `allowed`,
 * otherwise sends them to the page for their status. Returns the status so the
 * route can use it.
 */
export async function guard(queryClient: QueryClient, allowed: Status["kind"][]): Promise<Status> {
  const status = await queryClient.fetchQuery(statusQuery);
  if (!allowed.includes(status.kind)) throw redirect({ to: homeFor(status), replace: true });
  return status;
}
