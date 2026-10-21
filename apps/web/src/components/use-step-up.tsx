import { useState } from "react";
import { ApiError } from "../lib/api.ts";
import { StepUpDialog } from "./step-up-dialog.tsx";

/**
 * For actions the API guards with a recent sign-in (`step-up-required`): `handled` opens
 * the confirmation and remembers the action, which runs again once the sign-in is fresh.
 */
export function useStepUp(email: string) {
  const [retry, setRetry] = useState<(() => void) | null>(null);
  const handled = (error: unknown, again: () => void): boolean => {
    if (!(error instanceof ApiError && error.code === "step-up-required")) return false;
    setRetry(() => again);
    return true;
  };
  const dialog = (
    <StepUpDialog
      open={retry !== null}
      email={email}
      onClose={() => setRetry(null)}
      onConfirmed={() => {
        const again = retry;
        setRetry(null);
        again?.();
      }}
    />
  );
  return { handled, dialog };
}
