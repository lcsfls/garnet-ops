import { guard } from "#lib/guard.ts";

export const load = () => guard(["no-organization"]).then(() => ({}));
