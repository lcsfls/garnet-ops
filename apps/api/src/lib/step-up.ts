import type { Actor } from "./context.ts";
import { ProblemError } from "./problem.ts";

/** How recent a full sign-in (password and second factor) must be for sensitive actions. */
export const STEP_UP_MAX_AGE_SECONDS = 10 * 60;

/** Throws `step-up-required` unless the actor signed in within the last ten minutes. */
export function requireRecentSignIn(actor: Actor): void {
  if (Date.now() - actor.strongAuthAt.getTime() > STEP_UP_MAX_AGE_SECONDS * 1000) {
    throw new ProblemError(403, "step-up-required", "Sign in again to confirm it is you", undefined, {
      maxAgeSeconds: STEP_UP_MAX_AGE_SECONDS,
    });
  }
}
