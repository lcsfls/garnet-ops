import { redirect } from "@sveltejs/kit";
import type { PageLoad } from "./$types";

// Owners and admins only; the API enforces the same rule.
export const load: PageLoad = async ({ parent }) => {
  const { me } = await parent();
  if (me.role !== "owner" && me.role !== "admin") redirect(307, "/");
  return {};
};
