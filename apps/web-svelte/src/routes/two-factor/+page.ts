import { guard } from "#lib/guard.ts";

export const load = () => guard(["signed-out"]).then(() => ({}));
