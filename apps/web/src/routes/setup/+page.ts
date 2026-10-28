import { guard } from "#lib/guard.ts";

export const load = () => guard(["setup"]).then(() => ({}));
