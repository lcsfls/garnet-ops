import { redirect } from "@sveltejs/kit";
import { queryClient } from "./query.ts";
import { homeFor, type Status, statusQuery } from "./session.ts";

/**
 * Route guard for load functions: lets the visitor stay only if their status is one of `allowed`, otherwise sends them
 * to the page for their status. Returns the status so the route can use it.
 */
export async function guard(allowed: Status["kind"][]): Promise<Status> {
  const status = await queryClient.fetchQuery(statusQuery);
  if (!allowed.includes(status.kind)) redirect(307, homeFor(status));
  return status;
}
