import { initialToasts, type ToastInput, type ToastState, toastReducer } from "./toast-queue.ts";

/**
 * The toast store (ADR 0019): module-level state so any code, component or not, can show a message
 * (`toast.success(t("...saved"))`). The region that draws them is `ToastRegion`. Messages are already translated by
 * the caller and are always rendered as text.
 */
let state = $state<ToastState>(initialToasts);

function dispatch(action: Parameters<typeof toastReducer>[1]): void {
  const next = toastReducer(state, action);
  if (next !== state) state = next;
}

type Options = Pick<ToastInput, "action" | "durationMs">;

export const toast = {
  success: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "success", message, ...options } }),
  error: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "error", message, ...options } }),
  info: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "info", message, ...options } }),
  dismiss: (id: number) => dispatch({ type: "dismiss", id }),
  clear: () => dispatch({ type: "clear" }),
};

/** The current toasts; reading this in a component follows every change. */
export function toasts(): ToastState {
  return state;
}
