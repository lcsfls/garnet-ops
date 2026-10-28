import { ApiError } from "./api.ts";

/**
 * For actions the API guards with a recent sign-in (`step-up-required`): `handled` opens the confirmation and remembers
 * the action, which runs again once the sign-in is fresh. Render `<StepUpPrompt {stepUp} email={...} />` next to it.
 *
 *   const stepUp = new StepUp();
 *   onError: (e) => { if (!stepUp.handled(e, () => save.mutate(input))) toast.error(...) }
 */
export class StepUp {
  #retry = $state<(() => void) | null>(null);

  get open(): boolean {
    return this.#retry !== null;
  }

  handled = (error: unknown, again: () => void): boolean => {
    if (!(error instanceof ApiError && error.code === "step-up-required")) return false;
    this.#retry = again;
    return true;
  };

  close = (): void => {
    this.#retry = null;
  };

  confirmed = (): void => {
    const again = this.#retry;
    this.#retry = null;
    again?.();
  };
}
