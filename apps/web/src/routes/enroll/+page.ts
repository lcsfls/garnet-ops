import { guard } from "#lib/guard.ts";

/**
 * Mandatory TOTP enrolment (AGENTS.md rule 1): a signed-in user without a second factor lands here and cannot reach
 * anything else except signing out.
 */
export const load = () => guard(["enroll"]).then(() => ({}));
