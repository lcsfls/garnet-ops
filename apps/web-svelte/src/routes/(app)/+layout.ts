import { guard } from "#lib/guard.ts";
import { applyPreferences } from "#lib/preferences.ts";

/** Layout for every signed-in page: only users with a second factor and an organisation get here. */
export async function load() {
  const status = await guard(["ready"]);
  if (status.kind !== "ready") throw new Error("guard let a non-ready status through");
  await applyPreferences(status.me.user);
  return { me: status.me };
}
